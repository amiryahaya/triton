//go:build integration

package manageserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// --- /setup/admin -----------------------------------------------------------

func TestSetupAdmin_CreatesFirstAdminAndTransitions(t *testing.T) {
	srv, store, cleanup := openSetupServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := strings.NewReader(`{
		"email":"admin@example.com",
		"name":"Root Admin",
		"password":"Sup3rStr0ngPw!"
	}`)
	resp, err := http.Post(ts.URL+"/api/v1/setup/admin", "application/json", body)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, true, out["ok"])
	assert.NotEmpty(t, out["user_id"])

	// Setup state flipped AdminCreated=true.
	state, err := store.GetSetup(context.Background())
	require.NoError(t, err)
	assert.True(t, state.AdminCreated)

	// A second call must 409.
	body2 := strings.NewReader(`{
		"email":"other@example.com",
		"name":"Other",
		"password":"AnotherStr0ng!"
	}`)
	resp2, err := http.Post(ts.URL+"/api/v1/setup/admin", "application/json", body2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)
}

func TestSetupAdmin_RejectsShortPassword(t *testing.T) {
	srv, _, cleanup := openSetupServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/setup/admin", "application/json",
		strings.NewReader(`{"email":"a@b.com","name":"A","password":"short1"}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, fmt.Sprintf("%v", out["error"]), "12 characters")
}

func TestSetupAdmin_RejectsPasswordWithoutDigit(t *testing.T) {
	srv, _, cleanup := openSetupServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/setup/admin", "application/json",
		strings.NewReader(`{"email":"a@b.com","name":"A","password":"longenoughbutnodigits"}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, fmt.Sprintf("%v", out["error"]), "digit")
}

// --- /setup/license --------------------------------------------------------

// fakeActivateResponse is the minimal v2 body the stub License Server returns.
type fakeActivateResponse struct {
	Token         string                    `json:"token"`
	ActivationID  string                    `json:"activationID"`
	Tier          string                    `json:"tier"`
	Seats         int                       `json:"seats"`
	SeatsUsed     int                       `json:"seatsUsed"`
	ExpiresAt     string                    `json:"expiresAt"`
	Features      map[string]any            `json:"features"`
	Limits        []map[string]any          `json:"limits"`
	SoftBufferPct int                       `json:"soft_buffer_pct"`
	ProductScope  string                    `json:"product_scope"`
	Usage         map[string]map[string]int `json:"usage"`
	GraceSeconds  int                       `json:"grace_seconds"`
}

func newStubLicenseServer(t *testing.T, resp fakeActivateResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/license/activate" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestSetupLicense_PersistsAndExitsSetupMode(t *testing.T) {
	srv, store, cleanup := openSetupServer(t)
	defer cleanup()

	// Pre-req: admin exists.
	require.NoError(t, store.MarkAdminCreated(context.Background()))
	srv.RefreshSetupMode(context.Background())

	ls := newStubLicenseServer(t, fakeActivateResponse{
		Token:        "signed-token-abcdef",
		ActivationID: "act-1",
		Tier:         "pro",
		Seats:        5,
		SeatsUsed:    1,
		ExpiresAt:    "2030-01-01T00:00:00Z",
		Features: map[string]any{
			"report": true,
			"manage": true,
		},
		Limits: []map[string]any{
			{"metric": "hosts", "window": "total", "cap": 100},
		},
		SoftBufferPct: 10,
		ProductScope:  "manage",
		GraceSeconds:  7 * 24 * 3600,
	})
	defer ls.Close()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{
		"license_server_url": %q,
		"license_key":        "lic-uuid"
	}`, ls.URL)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, true, out["ok"])
	features, ok := out["features"].(map[string]any)
	require.True(t, ok, "features should be an object in response")
	assert.Equal(t, true, features["manage"])

	// DB state reflects activation.
	state, err := store.GetSetup(context.Background())
	require.NoError(t, err)
	assert.True(t, state.LicenseActivated)
	assert.Equal(t, ls.URL, state.LicenseServerURL)
	assert.Equal(t, "lic-uuid", state.LicenseKey)
	assert.Equal(t, "signed-token-abcdef", state.SignedToken)
	assert.NotEmpty(t, state.InstanceID, "instance_id must be generated + persisted")

	// Router is now operational — setup/admin should 409.
	adminResp, err := http.Post(ts.URL+"/api/v1/setup/admin", "application/json",
		strings.NewReader(`{"email":"a@b.com","name":"A","password":"longenoughpw1"}`))
	require.NoError(t, err)
	defer adminResp.Body.Close()
	assert.Equal(t, http.StatusConflict, adminResp.StatusCode,
		"setup/admin must 409 once operational")
}

func TestSetupLicense_RejectsWhenFeatureManageFalse(t *testing.T) {
	srv, store, cleanup := openSetupServer(t)
	defer cleanup()

	require.NoError(t, store.MarkAdminCreated(context.Background()))
	srv.RefreshSetupMode(context.Background())

	ls := newStubLicenseServer(t, fakeActivateResponse{
		Token: "signed-token",
		Tier:  "pro",
		Features: map[string]any{
			"report": true,
			"manage": false, // the important bit
		},
		ProductScope: "report",
	})
	defer ls.Close()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{
		"license_server_url": %q,
		"license_key":        "lic-report-only"
	}`, ls.URL)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	// DB state unchanged — no accidental write.
	state, err := store.GetSetup(context.Background())
	require.NoError(t, err)
	assert.False(t, state.LicenseActivated)
	assert.Empty(t, state.SignedToken)
}

func TestSetupLicense_RejectsBeforeAdmin(t *testing.T) {
	srv, _, cleanup := openSetupServer(t)
	defer cleanup()

	// NO admin created — SetupState.AdminCreated == false.
	ls := newStubLicenseServer(t, fakeActivateResponse{
		Token:    "ignored",
		Features: map[string]any{"manage": true},
	})
	defer ls.Close()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{
		"license_server_url": %q,
		"license_key":        "any"
	}`, ls.URL)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// openSetupServer returns a fresh-DB Server+Store in setup mode (no admin,
// no licence activated). Mirrors openOperationalServer but skips the
// MarkAdminCreated + SaveLicenseActivation calls.
func openSetupServer(t *testing.T) (*manageserver.Server, *managestore.PostgresStore, func()) {
	t.Helper()
	schema := fmt.Sprintf("test_msrv_setup_%d", serverTestSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getTestDBURL(), schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store)
	require.NoError(t, err)

	cleanup := func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	}
	return srv, store, cleanup
}
