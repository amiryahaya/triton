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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

func TestLogin_HappyPath(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	user := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{"email":%q,"password":"Password123!"}`, user.Email)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/login",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.NotEmpty(t, out["token"], "token should be returned")

	userOut, ok := out["user"].(map[string]any)
	require.True(t, ok, "user object should be present")
	assert.Equal(t, user.Email, userOut["email"])
	assert.Equal(t, user.Role, userOut["role"])
}

func TestLogin_WrongPasswordReturns401(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	user := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{"email":%q,"password":"wrongpassword"}`, user.Email)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/login",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogin_UnknownEmailReturns401(t *testing.T) {
	srv, _, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := `{"email":"nobody@example.com","password":"Password123!"}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/login",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestLogin_RateLimitKicksIn(t *testing.T) {
	// Use a fresh server per test to avoid bleed between parallel tests.
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	user := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := fmt.Sprintf(`{"email":%q,"password":"wrongpassword"}`, user.Email)

	// Send 5 bad attempts — all should return 401.
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/login",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "attempt %d", i+1)
	}

	// 6th attempt should be rate-limited → 429.
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/login",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}

func TestLogout_DeletesSession(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	user := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	token := loginViaHTTP(t, ts.URL, user.Email, "Password123!")

	// /me should work before logout.
	resp, err := authorizedRequest(t, ts.URL+"/api/v1/me", "GET", token)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Logout.
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	logoutResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	logoutResp.Body.Close()
	assert.Equal(t, http.StatusNoContent, logoutResp.StatusCode)

	// /me should now return 401 (session deleted).
	resp2, err := authorizedRequest(t, ts.URL+"/api/v1/me", "GET", token)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestLogout_NoAuthHeaderReturns204(t *testing.T) {
	srv, _, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/logout", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

func TestRefresh_IssuesNewTokenAndRevokesOld(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	user := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	oldToken := loginViaHTTP(t, ts.URL, user.Email, "Password123!")

	// Refresh.
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	newToken, ok := out["token"].(string)
	require.True(t, ok && newToken != "" && newToken != oldToken,
		"refresh must issue a different token")

	// Old token should no longer work.
	resp2, err := authorizedRequest(t, ts.URL+"/api/v1/me", "GET", oldToken)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

	// New token should work.
	resp3, err := authorizedRequest(t, ts.URL+"/api/v1/me", "GET", newToken)
	require.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusOK, resp3.StatusCode)
}

func TestMe_ReturnsUserForValidToken(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()

	user := seedAdminUser(t, store)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	token := loginViaHTTP(t, ts.URL, user.Email, "Password123!")

	resp, err := authorizedRequest(t, ts.URL+"/api/v1/me", "GET", token)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, user.Email, out["email"])
	assert.Equal(t, user.Role, out["role"])
}

func TestMe_NoAuthReturns401(t *testing.T) {
	srv, _, cleanup := openOperationalServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/me", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuthRoutes_BlockedInSetupMode(t *testing.T) {
	// Fresh DB — no admin created → setup mode → /auth/* returns 503.
	srv, cleanup := openTestServer(t)
	defer cleanup()

	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := `{"email":"admin@example.com","password":"Password123!"}`
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/login",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, true, out["setup_required"])
}

// seedNetworkEngineer creates a network_engineer user in the store.
func seedNetworkEngineer(t *testing.T, store *managestore.PostgresStore) *managestore.ManageUser {
	t.Helper()
	pw, err := manageserver.HashPassword("Password123!")
	require.NoError(t, err)
	user := &managestore.ManageUser{
		Email:        fmt.Sprintf("ne%d@example.com", serverTestSeq.Add(1)),
		Name:         "Network Engineer",
		Role:         "network_engineer",
		PasswordHash: pw,
	}
	require.NoError(t, store.CreateUser(context.Background(), user))
	return user
}
