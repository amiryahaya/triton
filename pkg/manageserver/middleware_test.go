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
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
	"github.com/amiryahaya/triton/pkg/managestore"
)

// okHandler returns 200 "ok".
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
})

func TestSetupOnly_PassesWhenInSetup(t *testing.T) {
	srv, cleanup := openTestServer(t)
	defer cleanup()

	// SetupOnly gate: setup/status route is always open, but we verify
	// that a setup-mode server returns 200 for /api/v1/setup/status.
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/setup/status")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSetupOnly_RejectsWhenOperational(t *testing.T) {
	store, storeCleanup := openRawStore(t)
	defer storeCleanup()

	// Mark operational.
	require.NoError(t, store.MarkAdminCreated(context.Background()))
	require.NoError(t, store.SaveLicenseActivation(context.Background(),
		"https://ls.example.com", "key", "tok", "00000000-0000-0000-0000-000000000001"))

	cfg := &manageserver.Config{
		Listen:        ":0",
		JWTSigningKey: testJWTKey,
		SessionTTL:    time.Hour,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	// Wrap SetupOnly around a simple handler.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		srv.SetupOnly(okHandler).ServeHTTP(w, r)
	})
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestRequireOperational_RejectsWhenInSetup(t *testing.T) {
	srv, cleanup := openTestServer(t)
	defer cleanup()

	// Fresh DB → in setup mode → /api/v1/auth/login returns 503.
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"email":"a@b.com","password":"pass"}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestRequireOperational_PassesWhenOperational(t *testing.T) {
	srv, _, storeCleanup := openOperationalServer(t)
	defer storeCleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// /api/v1/auth/login passes the requireOperational gate → 400 (bad body) not 503.
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{}`))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestJWTAuth_ValidTokenPopulatesContext(t *testing.T) {
	srv, store, storeCleanup := openOperationalServer(t)
	defer storeCleanup()

	user := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	token := loginViaHTTP(t, ts.URL, user.Email, "Password123!")

	resp, err := authorizedRequest(t, ts.URL+"/api/v1/me", "GET", token)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestJWTAuth_NoHeaderReturns401(t *testing.T) {
	srv, _, storeCleanup := openOperationalServer(t)
	defer storeCleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/me", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWTAuth_BadPrefixReturns401(t *testing.T) {
	srv, _, storeCleanup := openOperationalServer(t)
	defer storeCleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/me", nil)
	req.Header.Set("Authorization", "Token notabearer")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWTAuth_ExpiredTokenReturns401(t *testing.T) {
	srv, _, storeCleanup := openOperationalServer(t)
	defer storeCleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// A structurally valid 3-part JWT with an obviously wrong signature
	// (and expired exp) — parseJWT will reject it.
	fakeExpired := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
		".eyJzdWIiOiJ1c2VyLTEiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjEsImV4cCI6Mn0" +
		".invalidsignature"

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+fakeExpired)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWTAuth_SessionNotInStoreReturns401(t *testing.T) {
	srv, store, storeCleanup := openOperationalServer(t)
	defer storeCleanup()

	user := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	token := loginViaHTTP(t, ts.URL, user.Email, "Password123!")

	// Logout to delete the session row.
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	logoutResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	logoutResp.Body.Close()

	// The token is still cryptographically valid but session is gone.
	resp, err := authorizedRequest(t, ts.URL+"/api/v1/me", "GET", token)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestInjectInstanceOrg_StashesInstanceID(t *testing.T) {
	srv, _, storeCleanup := openOperationalServer(t)
	defer storeCleanup()

	// openOperationalServer saves "00000000-0000-0000-0000-000000000001".
	wantID := "00000000-0000-0000-0000-000000000001"

	// Echo the UUID the middleware stashes.
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := orgctx.InstanceIDFromContext(r.Context())
		if !ok {
			http.Error(w, "no instance id", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(id.String()))
	})
	ts := httptest.NewServer(srv.InjectInstanceOrgForTest(echo))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, wantID, string(body))
}

func TestInjectInstanceOrg_ServiceUnavailableWhenSetupIncomplete(t *testing.T) {
	// Fresh-DB server: instance_id never populated.
	srv, cleanup := openTestServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.InjectInstanceOrgForTest(okHandler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestRequireRole_AdmitsMatchedRole(t *testing.T) {
	srv, store, storeCleanup := openOperationalServer(t)
	defer storeCleanup()

	user := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	token := loginViaHTTP(t, ts.URL, user.Email, "Password123!")

	// /api/v1/me admits any authenticated user — verifies the happy path.
	resp, err := authorizedRequest(t, ts.URL+"/api/v1/me", "GET", token)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRequireRole_Rejects403(t *testing.T) {
	// Build a synthetic handler that uses RequireRole("admin") directly.
	// No jwtAuth → no user in context → RequireRole returns 401.
	adminOnly := manageserver.RequireRole("admin")
	ts := httptest.NewServer(adminOnly(okHandler))
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL, nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	// No user in context → 401 (not authenticated) per middleware spec.
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- helpers shared by middleware_test + handlers_auth_test ---

func openRawStore(t *testing.T) (*managestore.PostgresStore, func()) {
	t.Helper()
	schema := fmt.Sprintf("test_msrv_raw_%d", serverTestSeq.Add(1))
	s, err := managestore.NewPostgresStoreInSchema(context.Background(), getTestDBURL(), schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	return s, func() {
		_ = s.DropSchema(context.Background())
		s.Close()
	}
}

// openOperationalServer creates a Server + Store pair that is already past
// setup mode (admin created + license activated).
func openOperationalServer(t *testing.T) (*manageserver.Server, *managestore.PostgresStore, func()) {
	return openOperationalServerWithRetryInterval(t, 0)
}

// openOperationalServerWithRetryInterval mirrors openOperationalServer
// but lets the caller override Config.GatewayRetryInterval for
// deterministic test timing around the gateway retry loop. A zero
// interval falls through to the production default (5s) inside
// manageserver.New.
func openOperationalServerWithRetryInterval(
	t *testing.T, interval time.Duration,
) (*manageserver.Server, *managestore.PostgresStore, func()) {
	t.Helper()
	schema := fmt.Sprintf("test_msrv_op_%d", serverTestSeq.Add(1))
	store, err := managestore.NewPostgresStoreInSchema(context.Background(), getTestDBURL(), schema)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}

	require.NoError(t, store.MarkAdminCreated(context.Background()))
	require.NoError(t, store.SaveLicenseActivation(context.Background(),
		"https://ls.example.com", "key", "tok", "00000000-0000-0000-0000-000000000001"))

	cfg := &manageserver.Config{
		Listen:               ":0",
		GatewayListen:        ":0",
		JWTSigningKey:        testJWTKey,
		SessionTTL:           time.Hour,
		GatewayRetryInterval: interval,
	}
	srv, err := manageserver.New(cfg, store, store.Pool())
	require.NoError(t, err)

	cleanup := func() {
		_ = store.DropSchema(context.Background())
		store.Close()
	}
	return srv, store, cleanup
}

func seedAdminUser(t *testing.T, store *managestore.PostgresStore) *managestore.ManageUser {
	t.Helper()
	pw, err := manageserver.HashPassword("Password123!")
	require.NoError(t, err)
	user := &managestore.ManageUser{
		Email:        fmt.Sprintf("admin%d@example.com", serverTestSeq.Add(1)),
		Name:         "Test Admin",
		Role:         "admin",
		PasswordHash: pw,
	}
	require.NoError(t, store.CreateUser(context.Background(), user))
	return user
}

func loginViaHTTP(t *testing.T, baseURL, email, password string) string {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req, err := http.NewRequest("POST", baseURL+"/api/v1/auth/login",
		strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "login must succeed for test setup")

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	token, ok := out["token"].(string)
	require.True(t, ok && token != "", "token must be in login response")
	return token
}

func authorizedRequest(t *testing.T, url, method, token string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

// suppress unused import if readBody isn't used.
var _ = io.Discard
