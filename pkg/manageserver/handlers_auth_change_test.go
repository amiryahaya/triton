//go:build integration

package manageserver_test

import (
	"context"
	"encoding/base64"
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

// TestChangePassword_HappyPath: forced-change user logs in, changes password,
// receives a new JWT with Mcp=false, can no longer log in with old password.
func TestChangePassword_HappyPath(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithUser(t, "user@example.com", "TempPass1234!", true /* mustChangePW */)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	// Login → get JWT (Mcp should be true, but we don't assert it here).
	loginResp := loginUser(t, ts.URL, "user@example.com", "TempPass1234!")
	token := loginResp["token"].(string)

	// Change password.
	body := strings.NewReader(`{"current":"TempPass1234!","next":"NewSecret9876!"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body2 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body2))
	assert.NotEmpty(t, body2["token"])
	assert.Equal(t, false, body2["must_change_password"])
	assert.NotEmpty(t, body2["expires_at"])

	// Old password no longer works.
	failed := loginUserExpectingError(t, ts.URL, "user@example.com", "TempPass1234!")
	assert.Equal(t, http.StatusUnauthorized, failed)

	// New password works.
	_ = loginUser(t, ts.URL, "user@example.com", "NewSecret9876!")
}

func TestChangePassword_WrongCurrent(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithUser(t, "u1@example.com", "RealPass1234!", false)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	token := loginUser(t, ts.URL, "u1@example.com", "RealPass1234!")["token"].(string)

	body := strings.NewReader(`{"current":"WrongPass1234!","next":"AnotherSecret9876!"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestChangePassword_PolicyFail_TooShort(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithUser(t, "u2@example.com", "RealPass1234!", false)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	token := loginUser(t, ts.URL, "u2@example.com", "RealPass1234!")["token"].(string)

	body := strings.NewReader(`{"current":"RealPass1234!","next":"short1"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, fmt.Sprintf("%v", out["error"]), "12 characters")
}

func TestChangePassword_PolicyFail_NoDigit(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithUser(t, "u3@example.com", "RealPass1234!", false)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	token := loginUser(t, ts.URL, "u3@example.com", "RealPass1234!")["token"].(string)

	body := strings.NewReader(`{"current":"RealPass1234!","next":"NoDigitsAtAll!!"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, fmt.Sprintf("%v", out["error"]), "digit")
}

func TestChangePassword_SameAsCurrent(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithUser(t, "u4@example.com", "SamePass1234!", false)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	token := loginUser(t, ts.URL, "u4@example.com", "SamePass1234!")["token"].(string)

	body := strings.NewReader(`{"current":"SamePass1234!","next":"SamePass1234!"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Contains(t, fmt.Sprintf("%v", out["error"]), "differ from current")
}

func TestChangePassword_MissingFields(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithUser(t, "u5@example.com", "RealPass1234!", false)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	token := loginUser(t, ts.URL, "u5@example.com", "RealPass1234!")["token"].(string)

	for _, body := range []string{
		`{"current":"","next":"NewSecret9876!"}`,
		`{"current":"RealPass1234!","next":""}`,
		`{}`,
	} {
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", body)
	}
}

func TestChangePassword_NoAuthHeader(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithUser(t, "u6@example.com", "RealPass1234!", false)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	body := strings.NewReader(`{"current":"RealPass1234!","next":"NewSecret9876!"}`)
	resp, err := http.Post(ts.URL+"/api/v1/auth/change-password", "application/json", body)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestChangePassword_OldTokenInvalidatedAfterSuccess(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithUser(t, "u7@example.com", "OldPass1234!", false)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	oldToken := loginUser(t, ts.URL, "u7@example.com", "OldPass1234!")["token"].(string)

	// Successfully change password.
	body := strings.NewReader(`{"current":"OldPass1234!","next":"NewSecret9876!"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Old token should now fail on /me.
	req2, _ := http.NewRequest("GET", ts.URL+"/api/v1/me", nil)
	req2.Header.Set("Authorization", "Bearer "+oldToken)
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
}

func TestChangePassword_McpClearedInNewToken(t *testing.T) {
	srv, _, cleanup := openOperationalServerWithUser(t, "u8@example.com", "TempPass1234!", true)
	defer cleanup()
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()
	token := loginUser(t, ts.URL, "u8@example.com", "TempPass1234!")["token"].(string)

	body := strings.NewReader(`{"current":"TempPass1234!","next":"NewSecret9876!"}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/auth/change-password", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body2 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body2))
	newToken := body2["token"].(string)

	// Decode the new JWT payload (base64url middle segment) and confirm Mcp is
	// absent or false. omitempty means the claim is dropped entirely when false,
	// so either outcome satisfies "mcp is not true" for the frontend guard.
	parts := strings.Split(newToken, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var c map[string]any
	require.NoError(t, json.Unmarshal(raw, &c))
	if v, ok := c["mcp"]; ok {
		assert.Equal(t, false, v)
	}
}

// --- helpers ---------------------------------------------------------------

// openOperationalServerWithUser wraps openOperationalServer and seeds an
// additional ManageUser with an arbitrary MustChangePW flag so tests can
// exercise both forced-change and voluntary-rotation flows.
func openOperationalServerWithUser(t *testing.T, email, password string, mustChangePW bool) (*manageserver.Server, *managestore.PostgresStore, func()) {
	t.Helper()
	srv, store, cleanup := openOperationalServer(t)

	hash, err := manageserver.HashPassword(password)
	require.NoError(t, err)
	user := &managestore.ManageUser{
		Email:        email,
		Name:         "Test User",
		Role:         "network_engineer",
		PasswordHash: hash,
		MustChangePW: mustChangePW,
	}
	require.NoError(t, store.CreateUser(context.Background(), user))
	return srv, store, cleanup
}

func loginUser(t *testing.T, baseURL, email, password string) map[string]any {
	t.Helper()
	body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))
	resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", body)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

func loginUserExpectingError(t *testing.T, baseURL, email, password string) int {
	t.Helper()
	body := strings.NewReader(fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))
	resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", body)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}
