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
