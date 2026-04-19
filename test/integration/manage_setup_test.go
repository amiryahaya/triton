//go:build integration

// Manage Server — end-to-end setup → licence → auth → /me flow.
//
// Exercises the full PR B1 shell with a stub License Server:
//
//  1. Fresh DB → /setup/status reports setup_required=true.
//  2. POST /setup/admin creates the first admin (201).
//  3. /setup/status now reflects admin_created=true, license_activated=false.
//  4. POST /setup/license activates against a stub LS that returns a
//     validly-signed Ed25519 token with Features.Manage=true (200).
//  5. /setup/status now reports setup_required=false.
//  6. POST /auth/login with admin creds returns a JWT.
//  7. GET /api/v1/me with Bearer JWT returns the user payload.
//
// Schema isolation: each test allocates a fresh PG schema via
// managestore.NewPostgresStoreInSchema and drops it in cleanup, matching
// the pattern in pkg/manageserver/*_test.go so this file can run
// concurrently alongside the package-level tests without colliding.

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// manageSchemaSeq monotonically allocates unique PG schemas so parallel
// packages never collide on the shared triton_test database.
var manageSchemaSeq atomic.Int64

// manageJWTKey is a fixed 32-byte HS256 secret for deterministic tests.
var manageJWTKey = []byte("manage-int-test-jwt-key-32bytes!")

// getManageDBURL mirrors testDBURL() from helpers_test.go, kept separate so
// the B1 test file remains self-contained and easy to read.
func getManageDBURL() string {
	if u := os.Getenv("TRITON_TEST_DB_URL"); u != "" {
		return u
	}
	return "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
}

// stubLicenseServerConfig drives the stub License Server's response payload.
type stubLicenseServerConfig struct {
	signedToken string
	activationID string
	tier        string
	features    licensestore.Features
}

// newManageStubLicenseServer spins an httptest server that answers the two
// endpoints the Manage Server touches during setup + lifecycle:
//
//   - POST /api/v1/license/activate → 201 with the v2 ActivateResponse
//   - POST /api/v1/license/usage     → 200 {"ok": true} (stopping the
//     pusher from emitting connection errors in the test log; it's
//     invoked by startLicence immediately after successful activation)
func newManageStubLicenseServer(t *testing.T, cfg stubLicenseServerConfig) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/license/activate":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":        cfg.signedToken,
				"activationID": cfg.activationID,
				"tier":         cfg.tier,
				"seats":        10,
				"seatsUsed":    1,
				"expiresAt":    time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"features":     cfg.features,
				"limits":       []any{},
				"product_scope": "manage",
			})
		case "/api/v1/license/usage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

// openManageServer bootstraps a Manage Server on an isolated schema with
// the supplied Ed25519 public key (so it can verify tokens signed by the
// stub License Server). Returns the server + concrete store + cleanup func.
func openManageServer(t *testing.T, pub []byte) (*manageserver.Server, *managestore.PostgresStore, func()) {
	t.Helper()
	schema := fmt.Sprintf("test_manage_int_%d", manageSchemaSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getManageDBURL(), schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: manageJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store)
	require.NoError(t, err)

	cleanup := func() {
		_ = store.DropSchema(context.Background())
		_ = store.Close()
	}
	return srv, store, cleanup
}

// TestManageServerSetupFlow — end-to-end happy path.
func TestManageServerSetupFlow(t *testing.T) {
	// 1. Mint an Ed25519 keypair + sign a licence token the stub LS returns.
	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "int-test-lic",
		Tier:      license.TierPro,
		Org:       "IntegrationTest",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true, Report: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	// 2. Stub License Server.
	ls := newManageStubLicenseServer(t, stubLicenseServerConfig{
		signedToken:  signed,
		activationID: "int-test-activation",
		tier:         "pro",
		features:     licensestore.Features{Manage: true, Report: true},
	})
	defer ls.Close()

	// 3. Manage Server backed by the stub LS's matching pubkey.
	srv, _, cleanup := openManageServer(t, pub)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// ---- Step 1: fresh DB → setup_required ----
	status := manageGetJSON(t, ts.URL+"/api/v1/setup/status")
	assert.Equal(t, false, status["admin_created"], "fresh DB: admin_created=false")
	assert.Equal(t, false, status["license_activated"], "fresh DB: license_activated=false")
	assert.Equal(t, true, status["setup_required"], "fresh DB: setup_required=true")

	// ---- Step 2: create admin ----
	const adminEmail = "admin@example.com"
	const adminPassword = "supersecret-password-1" // ≥12 chars + digit
	createAdmin := postJSON(t, ts.URL+"/api/v1/setup/admin", map[string]any{
		"email":    adminEmail,
		"name":     "Integration Admin",
		"password": adminPassword,
	})
	createAdminBody := manageReadBody(createAdmin)
	require.Equal(t, http.StatusCreated, createAdmin.StatusCode,
		"POST /setup/admin must succeed on fresh DB, got body: %s", createAdminBody)

	// ---- Step 3: status reflects admin exists but licence still un-activated ----
	status = manageGetJSON(t, ts.URL+"/api/v1/setup/status")
	assert.Equal(t, true, status["admin_created"])
	assert.Equal(t, false, status["license_activated"])
	assert.Equal(t, true, status["setup_required"],
		"setup_required stays true until licence activates")

	// ---- Step 4: activate licence via stub LS ----
	licResp := postJSON(t, ts.URL+"/api/v1/setup/license", map[string]any{
		"license_server_url": ls.URL,
		"license_key":        "int-test-lic",
	})
	licBody := manageReadBody(licResp)
	require.Equal(t, http.StatusOK, licResp.StatusCode,
		"POST /setup/license must succeed against stub LS, got body: %s", licBody)

	// ---- Step 5: setup complete ----
	status = manageGetJSON(t, ts.URL+"/api/v1/setup/status")
	assert.Equal(t, true, status["admin_created"])
	assert.Equal(t, true, status["license_activated"])
	assert.Equal(t, false, status["setup_required"], "setup flow is now complete")

	// ---- Step 6: login ----
	loginResp := postJSON(t, ts.URL+"/api/v1/auth/login", map[string]any{
		"email":    adminEmail,
		"password": adminPassword,
	})
	// Buffer the body before any status assertion — require.Equal's format
	// args are evaluated eagerly, so using a read-and-close helper inline
	// (even on the happy path where the format string never renders) can
	// race with json.NewDecoder below. Read once, then inspect both the
	// status and the parsed payload from the buffered bytes.
	loginBodyBytes, err := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, loginResp.StatusCode,
		"login must succeed with the admin credentials, got body: %s", string(loginBodyBytes))
	var loginBody map[string]any
	require.NoError(t, json.Unmarshal(loginBodyBytes, &loginBody))

	token, ok := loginBody["token"].(string)
	require.True(t, ok, "login must return a token string, got %+v", loginBody)
	require.NotEmpty(t, token)

	user, ok := loginBody["user"].(map[string]any)
	require.True(t, ok, "login must return a user object")
	assert.Equal(t, adminEmail, user["email"])
	assert.Equal(t, "admin", user["role"])

	// ---- Step 7: /me with Bearer JWT ----
	meReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/me", nil)
	require.NoError(t, err)
	meReq.Header.Set("Authorization", "Bearer "+token)
	meResp, err := http.DefaultClient.Do(meReq)
	require.NoError(t, err)
	meBodyBytes, err := io.ReadAll(meResp.Body)
	meResp.Body.Close()
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, meResp.StatusCode,
		"GET /me must succeed with a valid token, got body: %s", string(meBodyBytes))
	var meBody map[string]any
	require.NoError(t, json.Unmarshal(meBodyBytes, &meBody))
	assert.Equal(t, adminEmail, meBody["email"])
	assert.Equal(t, "admin", meBody["role"])
	assert.Equal(t, "Integration Admin", meBody["name"])
}

// --- small HTTP helpers kept local to this file. Names are prefixed
// `manage*` so they don't collide with other integration-test helpers
// (e.g. postJSON in license_server_test.go which is also package-level).

func manageGetJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET %s must return 200", url)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// manageReadBody drains a response body as a string with Close. Use for
// failure-path diagnostics only; don't follow up with a NewDecoder on
// the same body afterwards.
func manageReadBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

