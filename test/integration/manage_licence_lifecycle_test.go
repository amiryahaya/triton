//go:build integration

// Manage Server — licence lifecycle end-to-end integration tests.
//
// Covers the five lifecycle operations added in feat/manage-licence-lifecycle:
//
//  1. TestManageLicence_Refresh          — POST /admin/licence/refresh → 200 {ok:true}
//  2. TestManageLicence_ReplaceKey       — POST /admin/licence/replace → 200
//  3. TestManageLicence_Deactivate_Immediate  — immediate deactivation when no active scans
//  4. TestManageLicence_Deactivate_Queued_ThenAutoFires — queued deactivation fires after scan completes
//  5. TestManageLicence_CancelDeactivation — DELETE /admin/licence/deactivation clears pending flag
//
// Each test allocates an isolated PostgreSQL schema via
// managestore.NewPostgresStoreInSchema so they can run in parallel with
// the rest of the manage integration tests without schema collisions.

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/licensestore"
	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// lcSchemaSeq allocates unique PG schemas across lifecycle tests running
// in parallel.
var lcSchemaSeq atomic.Int64

// lcJWTKey is a fixed 32-byte HS256 secret for the lifecycle tests.
var lcJWTKey = []byte("manage-lc-test-jwt-key-32bytess!")

// lcStubLicenseServer extends the shared newManageStubLicenseServer with
// a POST /api/v1/license/deactivate endpoint so deactivateNow does not
// error trying to contact the License Server.
func lcStubLicenseServer(t *testing.T, signedToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/license/activate":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":         signedToken,
				"activationID":  "lc-test-activation",
				"tier":          "pro",
				"seats":         10,
				"seatsUsed":     1,
				"expiresAt":     time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"features":      licensestore.Features{Manage: true, Report: true},
				"limits":        []any{},
				"product_scope": "manage",
			})
		case "/api/v1/license/deactivate":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case "/api/v1/license/usage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

// lcFixture holds the pieces of a lifecycle test rig.
type lcFixture struct {
	Server    *manageserver.Server
	Store     *managestore.PostgresStore
	AdminSrv  *httptest.Server
	AdminURL  string
	AdminJWT  string // populated by lcSetup
	LSStub    *httptest.Server
	SignedToken string
}

// newLCFixture allocates an isolated schema, builds a Manage Server, and
// returns the test rig. t.Cleanup handles teardown.
func newLCFixture(t *testing.T) *lcFixture {
	t.Helper()
	// Allow insecure (http) license server in tests.
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")

	pub, priv, err := license.GenerateKeypair()
	require.NoError(t, err)

	lic := &license.License{
		ID:        "lc-test-lic",
		Tier:      license.TierPro,
		Org:       "LCTest",
		Seats:     10,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour).Unix(),
		Features:  licensestore.Features{Manage: true, Report: true},
	}
	signed, err := license.Encode(lic, priv)
	require.NoError(t, err)

	ls := lcStubLicenseServer(t, signed)

	schema := fmt.Sprintf("test_manage_lc_%d", lcSchemaSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getManageDBURL(), schema)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: lcJWTKey,
		PublicKey:     pub,
		SessionTTL:    time.Hour,
		// Bind the gateway to an OS-assigned port so tests don't fight
		// each other over :8443. The gateway listener is not exercised
		// here, so just give it a random free address.
		GatewayListen:   "127.0.0.1:0",
		GatewayHostname: "127.0.0.1",
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	adminSrv := httptest.NewServer(srv.Router())

	fix := &lcFixture{
		Server:      srv,
		Store:       store,
		AdminSrv:    adminSrv,
		AdminURL:    adminSrv.URL,
		LSStub:      ls,
		SignedToken: signed,
	}

	t.Cleanup(func() {
		adminSrv.Close()
		ls.Close()
		_ = store.DropSchema(context.Background())
		_ = store.Close()
	})
	return fix
}

// lcSetup drives /setup/admin + /setup/license + /auth/login so the fixture
// is post-setup and AdminJWT is populated.
func (f *lcFixture) lcSetup(t *testing.T) {
	t.Helper()
	const adminEmail = "admin@lctest.local"
	const adminPassword = "lc-test-password-1" // ≥12 chars + digit

	// Create admin.
	resp := postJSON(t, f.AdminURL+"/api/v1/setup/admin", map[string]any{
		"email":    adminEmail,
		"name":     "LC Admin",
		"password": adminPassword,
	})
	body := manageReadBody(resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "setup/admin: %s", body)

	// Activate licence.
	resp = postJSON(t, f.AdminURL+"/api/v1/setup/license", map[string]any{
		"license_server_url": f.LSStub.URL,
		"license_key":        "lc-test-lic",
		"server_name":        "Test Manage Server",
	})
	body = manageReadBody(resp)
	require.Equal(t, http.StatusOK, resp.StatusCode, "setup/license: %s", body)

	// Login.
	loginResp := postJSON(t, f.AdminURL+"/api/v1/auth/login", map[string]any{
		"email":    adminEmail,
		"password": adminPassword,
	})
	loginBytes, err := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, loginResp.StatusCode, "login: %s", string(loginBytes))

	var loginOut map[string]any
	require.NoError(t, json.Unmarshal(loginBytes, &loginOut))
	tok, ok := loginOut["token"].(string)
	require.True(t, ok, "login must return a token string, got %+v", loginOut)
	f.AdminJWT = tok
}

// adminReq sends an authenticated admin-plane request.
func (f *lcFixture) adminReq(t *testing.T, method, path string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, f.AdminURL+path, body)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+f.AdminJWT)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// -------------------------------------------------------------------------
// Test 1: Refresh re-activates the stored key and returns {ok:true}.
// -------------------------------------------------------------------------

func TestManageLicence_Refresh(t *testing.T) {
	f := newLCFixture(t)
	f.lcSetup(t)

	// POST /api/v1/admin/licence/refresh
	resp := f.adminReq(t, http.MethodPost, "/api/v1/admin/licence/refresh", nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "refresh: %s", string(body))

	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	assert.Equal(t, true, out["ok"], "refresh must return ok:true")

	// Guard is still live — GET /admin/licence must return 200.
	licResp := f.adminReq(t, http.MethodGet, "/api/v1/admin/licence", nil)
	defer licResp.Body.Close()
	licBody, _ := io.ReadAll(licResp.Body)
	assert.Equal(t, http.StatusOK, licResp.StatusCode,
		"GET /admin/licence must return 200 after refresh: %s", string(licBody))
}

// -------------------------------------------------------------------------
// Test 2: Replace activates a new key and returns 200.
// -------------------------------------------------------------------------

func TestManageLicence_ReplaceKey(t *testing.T) {
	f := newLCFixture(t)
	f.lcSetup(t)

	// POST /api/v1/admin/licence/replace with a (still-valid) key.
	payload := `{"license_key":"lc-test-lic"}`
	resp := f.adminReq(t, http.MethodPost, "/api/v1/admin/licence/replace",
		strings.NewReader(payload))
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "replace: %s", string(body))
}

// -------------------------------------------------------------------------
// Test 3: Immediate deactivation when no active scan jobs.
// -------------------------------------------------------------------------

func TestManageLicence_Deactivate_Immediate(t *testing.T) {
	f := newLCFixture(t)
	f.lcSetup(t)

	// No scan jobs exist → deactivation should fire immediately.
	resp := f.adminReq(t, http.MethodPost, "/api/v1/admin/licence/deactivate", nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"immediate deactivate must return 200: %s", string(body))

	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	assert.Equal(t, false, out["pending"], "immediate deactivation: pending must be false")
	assert.Equal(t, true, out["ok"], "immediate deactivation: ok must be true")

	// Licence is now cleared — guard is nil → GET /admin/licence returns 503.
	licResp := f.adminReq(t, http.MethodGet, "/api/v1/admin/licence", nil)
	defer licResp.Body.Close()
	licBody, _ := io.ReadAll(licResp.Body)
	assert.Equal(t, http.StatusServiceUnavailable, licResp.StatusCode,
		"GET /admin/licence after deactivation must return 503: %s", string(licBody))
}

// -------------------------------------------------------------------------
// Test 4: Queued deactivation fires automatically after the running scan
// job completes. The watcher polls every 10 s; we wait up to 15 s.
// -------------------------------------------------------------------------

func TestManageLicence_Deactivate_Queued_ThenAutoFires(t *testing.T) {
	f := newLCFixture(t)
	f.lcSetup(t)

	// Resolve instance_id so we can seed the scan job under the right tenant.
	ctx := context.Background()
	state, err := f.Store.GetSetup(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, state.InstanceID, "instance_id must be set after /setup/license")

	tenantID, err := uuid.Parse(state.InstanceID)
	require.NoError(t, err)

	// Seed a running scan job directly (zone_id + host_id may be NULL
	// after migration v6, so no FK rows are required).
	var jobID uuid.UUID
	require.NoError(t, f.Store.Pool().QueryRow(ctx,
		`INSERT INTO manage_scan_jobs (tenant_id, profile, status, running_heartbeat_at)
		 VALUES ($1, 'quick', 'running', NOW())
		 RETURNING id`,
		tenantID,
	).Scan(&jobID))

	// POST /admin/licence/deactivate — must return 202 (queued) because
	// active scan count is 1.
	resp := f.adminReq(t, http.MethodPost, "/api/v1/admin/licence/deactivate", nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"deactivate with active scan must return 202: %s", string(body))

	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	assert.Equal(t, true, out["pending"], "deactivate with active scan: pending must be true")

	// Licence is still active at this point.
	licResp := f.adminReq(t, http.MethodGet, "/api/v1/admin/licence", nil)
	licBody, _ := io.ReadAll(licResp.Body)
	licResp.Body.Close()
	assert.Equal(t, http.StatusOK, licResp.StatusCode,
		"licence must still be active while deactivation is pending: %s", string(licBody))

	// Complete the running scan job so CountActive drops to 0.
	_, err = f.Store.Pool().Exec(ctx,
		`UPDATE manage_scan_jobs SET status = 'completed', finished_at = NOW() WHERE id = $1`,
		jobID,
	)
	require.NoError(t, err)

	// Wait up to 15 s for the watcher (10 s tick) to fire deactivateNow.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		licResp2 := f.adminReq(t, http.MethodGet, "/api/v1/admin/licence", nil)
		io.Copy(io.Discard, licResp2.Body) //nolint:errcheck
		licResp2.Body.Close()
		if licResp2.StatusCode == http.StatusServiceUnavailable {
			return // watcher fired — test passes
		}
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatal("deactivation watcher did not fire within 15 s after scan job completed")
}

// -------------------------------------------------------------------------
// Test 5: DELETE /admin/licence/deactivation clears a pending flag.
// -------------------------------------------------------------------------

func TestManageLicence_CancelDeactivation(t *testing.T) {
	f := newLCFixture(t)
	f.lcSetup(t)

	// Set pending_deactivation=true directly via store (simulating a
	// prior POST /admin/licence/deactivate that returned 202).
	ctx := context.Background()
	require.NoError(t, f.Store.SetPendingDeactivation(ctx, true))

	// Verify state is pending.
	st, err := f.Store.GetSetup(ctx)
	require.NoError(t, err)
	require.True(t, st.PendingDeactivation, "pending flag must be set before cancel")

	// DELETE /api/v1/admin/licence/deactivation
	resp := f.adminReq(t, http.MethodDelete, "/api/v1/admin/licence/deactivation", nil)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "cancel deactivation: %s", string(body))

	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	assert.Equal(t, true, out["ok"], "cancel deactivation: ok must be true")

	// Verify flag is cleared in the store.
	st2, err := f.Store.GetSetup(ctx)
	require.NoError(t, err)
	assert.False(t, st2.PendingDeactivation, "pending_deactivation must be false after cancel")
}

