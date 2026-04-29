//go:build integration

package manageserver_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")
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
		"license_key":        "lic-uuid",
		"server_name":        "Test Manage Server"
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
	assert.Equal(t, "Test Manage Server", out["server_name"])
	assert.NotEmpty(t, out["instance_id"], "instance_id must be present in response")

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
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")
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
		"license_key":        "lic-report-only",
		"server_name":        "Test Manage Server"
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

func TestSetupLicense_ReturnsBadRequestWhenLicenseServerUnreachable(t *testing.T) {
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")
	srv, store, cleanup := openSetupServer(t)
	defer cleanup()

	// Pre-req: admin exists so we get past the AdminCreated gate and actually
	// exercise the Activate() path.
	require.NoError(t, store.MarkAdminCreated(context.Background()))
	srv.RefreshSetupMode(context.Background())

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// Port 1 is IANA-reserved and no service listens there; TCP connect fails
	// immediately, keeping the test hermetic (no DNS, no external traffic).
	body := `{
		"license_server_url": "http://127.0.0.1:1/",
		"license_key":        "lic-unreachable",
		"server_name":        "Test Manage Server"
	}`
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, fmt.Sprintf("%v", out["error"]), "activation failed")

	// DB state must remain un-activated — no partial write on LS failure.
	state, err := store.GetSetup(context.Background())
	require.NoError(t, err)
	assert.False(t, state.LicenseActivated, "LicenseActivated must remain false when LS unreachable")
	assert.Empty(t, state.SignedToken)
	assert.Empty(t, state.InstanceID)
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
		"license_key":        "any",
		"server_name":        "Test Manage Server"
	}`, ls.URL)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// --- Batch A: HTTPS gate on /setup/license --------------------------------

func TestSetupLicense_RejectsHTTP(t *testing.T) {
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "")
	srv, _, cleanup := openSetupServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// Create admin first so we can reach /setup/license.
	_, _ = http.Post(ts.URL+"/api/v1/setup/admin", "application/json", strings.NewReader(`{
		"email":"admin@example.com","name":"A","password":"Sup3rStr0ngPw!"
	}`))

	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json", strings.NewReader(`{
		"license_server_url":"http://insecure.example.com","license_key":"abc"
	}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Contains(t, fmt.Sprintf("%v", body["error"]), "https://")
}

func TestSetupLicense_AllowsHTTPWhenEnvSet(t *testing.T) {
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")
	srv, _, cleanup := openSetupServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// Stub LS accepting activation.
	ls := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token":"stub","features":{"manage":true}}`))
	}))
	defer ls.Close()

	_, _ = http.Post(ts.URL+"/api/v1/setup/admin", "application/json", strings.NewReader(`{
		"email":"admin@example.com","name":"A","password":"Sup3rStr0ngPw!"
	}`))

	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json", strings.NewReader(fmt.Sprintf(`{
		"license_server_url":%q,"license_key":"abc","server_name":"Test Manage Server"
	}`, ls.URL)))
	require.NoError(t, err)
	defer resp.Body.Close()

	// With the env set we should NOT hit the https:// rejection.
	// Downstream activation may still 4xx with a different error
	// (stub may not sign a valid token); either way the body must
	// NOT contain "must use https://".
	body, _ := io.ReadAll(resp.Body)
	assert.NotContains(t, string(body), "must use https://")
}

func TestSetupLicense_RejectsMissingScheme(t *testing.T) {
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "")
	srv, _, cleanup := openSetupServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	_, _ = http.Post(ts.URL+"/api/v1/setup/admin", "application/json", strings.NewReader(`{
		"email":"admin@example.com","name":"A","password":"Sup3rStr0ngPw!"
	}`))

	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json", strings.NewReader(`{
		"license_server_url":"example.com","license_key":"abc"
	}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestSetupLicense_RequiresServerName — omitting server_name from the request body
// must return 400. The field is mandatory so the Manage Server has a human-readable
// identity in both the Report enrol payload and the response.
func TestSetupLicense_RequiresServerName(t *testing.T) {
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")
	srv, store, cleanup := openSetupServer(t)
	defer cleanup()

	require.NoError(t, store.MarkAdminCreated(context.Background()))
	srv.RefreshSetupMode(context.Background())

	ls := newStubLicenseServer(t, fakeActivateResponse{
		Token:    "tok",
		Features: map[string]any{"manage": true},
	})
	defer ls.Close()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// No server_name field.
	body := fmt.Sprintf(`{"license_server_url":%q,"license_key":"k1"}`, ls.URL)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"missing server_name must return 400")

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, fmt.Sprintf("%v", out["error"]), "server_name")
}

// TestSetupLicense_RejectsBlankServerName — a whitespace-only server_name is
// equivalent to omitting it.
func TestSetupLicense_RejectsBlankServerName(t *testing.T) {
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")
	srv, store, cleanup := openSetupServer(t)
	defer cleanup()

	require.NoError(t, store.MarkAdminCreated(context.Background()))
	srv.RefreshSetupMode(context.Background())

	ls := newStubLicenseServer(t, fakeActivateResponse{
		Token:    "tok",
		Features: map[string]any{"manage": true},
	})
	defer ls.Close()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{"license_server_url":%q,"license_key":"k1","server_name":"   "}`, ls.URL)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"blank server_name must return 400")
}

// TestSetupLicense_RejectsTooLongServerName — server_name exceeding 100 chars
// must return 400.
func TestSetupLicense_RejectsTooLongServerName(t *testing.T) {
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")
	srv, store, cleanup := openSetupServer(t)
	defer cleanup()

	require.NoError(t, store.MarkAdminCreated(context.Background()))
	srv.RefreshSetupMode(context.Background())

	ls := newStubLicenseServer(t, fakeActivateResponse{
		Token:    "tok",
		Features: map[string]any{"manage": true},
	})
	defer ls.Close()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	tooLong := strings.Repeat("a", 101)
	body := fmt.Sprintf(`{"license_server_url":%q,"license_key":"k1","server_name":%q}`, ls.URL, tooLong)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"server_name > 100 chars must return 400")
}

// TestSetupLicense_ReturnsInstanceIDAndServerName — a successful activation
// must echo back instance_id and server_name in the response body.
func TestSetupLicense_ReturnsInstanceIDAndServerName(t *testing.T) {
	t.Setenv("TRITON_MANAGE_ALLOW_INSECURE_LICENSE_SERVER", "true")
	srv, store, cleanup := openSetupServer(t)
	defer cleanup()

	require.NoError(t, store.MarkAdminCreated(context.Background()))
	srv.RefreshSetupMode(context.Background())

	ls := newStubLicenseServer(t, fakeActivateResponse{
		Token:    "signed-token",
		Features: map[string]any{"manage": true},
	})
	defer ls.Close()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{"license_server_url":%q,"license_key":"k1","server_name":"My Manage Server"}`, ls.URL)
	resp, err := http.Post(ts.URL+"/api/v1/setup/license", "application/json",
		strings.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, true, out["ok"])
	assert.NotEmpty(t, out["instance_id"], "instance_id must be present in response")
	assert.Equal(t, "My Manage Server", out["server_name"],
		"server_name must be echoed back in response")
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
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	cleanup := func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	}
	return srv, store, cleanup
}
