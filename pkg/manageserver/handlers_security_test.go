//go:build integration

package manageserver_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedLockout drives count bad-password login attempts for the given email
// against the test server to populate the in-memory rate limiter.
func seedLockout(t *testing.T, serverURL, email string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		body, _ := json.Marshal(map[string]string{
			"email":    email,
			"password": "definitely-wrong-password",
		})
		resp, err := http.Post(serverURL+"/api/v1/auth/login",
			"application/json", bytes.NewReader(body))
		require.NoError(t, err)
		resp.Body.Close()
	}
}

// TestSecurityEvents_ListReturnsActiveLockouts: seed 6 bad logins, GET
// /admin/security-events, assert the locked (email, IP) appears in the list.
func TestSecurityEvents_ListReturnsActiveLockouts(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	// Trigger lockout: 6 bad-password attempts (threshold is 5).
	seedLockout(t, ts.URL, admin.Email, 6)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/security-events", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out struct {
		ActiveLockouts []map[string]any `json:"active_lockouts"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	require.NotEmpty(t, out.ActiveLockouts)
	assert.Equal(t, admin.Email, out.ActiveLockouts[0]["email"])
}

// TestSecurityEvents_ListEmptyWhenNoLockouts: fresh server, GET returns
// {"active_lockouts": []} — never null.
func TestSecurityEvents_ListEmptyWhenNoLockouts(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/security-events", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out struct {
		ActiveLockouts []map[string]any `json:"active_lockouts"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.NotNil(t, out.ActiveLockouts, "active_lockouts must not be null")
	assert.Empty(t, out.ActiveLockouts)
}

// TestSecurityEvents_NonAdminRejected: network_engineer caller gets 403.
func TestSecurityEvents_NonAdminRejected(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	_ = seedAdminUser(t, store)
	engEmail := fmt.Sprintf("eng-sec-%d@example.com", serverTestSeq.Add(1))
	seedExtraUser(t, store, engEmail, "network_engineer")
	token := loginViaHTTP(t, ts.URL, engEmail, "Password123!")

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/security-events", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestSecurityEvents_ClearRemovesLockout: after triggering a lockout,
// DELETE /admin/security-events clears it, subsequent login succeeds.
func TestSecurityEvents_ClearRemovesLockout(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	// Trigger lockout.
	seedLockout(t, ts.URL, admin.Email, 6)

	// Confirm the user is now locked out.
	lockedBody, _ := json.Marshal(map[string]string{
		"email": admin.Email, "password": "Password123!",
	})
	lockResp, err := http.Post(ts.URL+"/api/v1/auth/login",
		"application/json", bytes.NewReader(lockedBody))
	require.NoError(t, err)
	lockResp.Body.Close()
	require.Equal(t, http.StatusTooManyRequests, lockResp.StatusCode, "user should be locked")

	// Clear lockout. httptest.Server uses loopback so the IP is 127.0.0.1.
	deleteURL := ts.URL + "/api/v1/admin/security-events?email=" +
		url.QueryEscape(admin.Email) + "&ip=127.0.0.1"
	delReq, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	require.NoError(t, err)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delResp, err := http.DefaultClient.Do(delReq)
	require.NoError(t, err)
	delResp.Body.Close()
	require.Equal(t, http.StatusNoContent, delResp.StatusCode)

	// User can now log in again.
	loginResp, err := http.Post(ts.URL+"/api/v1/auth/login",
		"application/json", bytes.NewReader(lockedBody))
	require.NoError(t, err)
	loginResp.Body.Close()
	assert.Equal(t, http.StatusOK, loginResp.StatusCode, "user should be unlocked")
}

// TestSecurityEvents_ClearMissing404: DELETE with an unknown (email, IP)
// pair returns 404.
func TestSecurityEvents_ClearMissing404(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	req, err := http.NewRequest(http.MethodDelete,
		ts.URL+"/api/v1/admin/security-events?email=nobody%40example.com&ip=9.9.9.9", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestSecurityEvents_ClearMissingQueryParams400: DELETE without email or
// ip returns 400.
func TestSecurityEvents_ClearMissingQueryParams400(t *testing.T) {
	srv, store, cleanup := openOperationalServer(t)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	admin := seedAdminUser(t, store)
	token := loginViaHTTP(t, ts.URL, admin.Email, "Password123!")

	// Missing ip param.
	req1, err := http.NewRequest(http.MethodDelete,
		ts.URL+"/api/v1/admin/security-events?email=test%40example.com", nil)
	require.NoError(t, err)
	req1.Header.Set("Authorization", "Bearer "+token)
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	resp1.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp1.StatusCode)

	// Missing email param.
	req2, err := http.NewRequest(http.MethodDelete,
		ts.URL+"/api/v1/admin/security-events?ip=1.2.3.4", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+token)
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	resp2.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
}
