//go:build integration

package licenseserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/pkg/licensestore"
)

// authedDo is the generic-path counterpart to adminDo — sends a Bearer
// JWT against any URL path (admin or otherwise).
func authedDo(t *testing.T, tsURL, jwt, method, path string, body any) adminResponse {
	t.Helper()
	var b []byte
	if body != nil {
		var err error
		b, err = json.Marshal(body)
		require.NoError(t, err)
	}
	req, err := http.NewRequest(method, tsURL+path, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return adminResponse{Code: resp.StatusCode, Body: result}
}

// seedUserWithPassword inserts a platform_admin with the given email +
// plaintext password. The MustChangePassword flag controls the response
// surface test in TestLogin_MustChangePasswordFlag*.
func seedUserWithPassword(t *testing.T, store *licensestore.PostgresStore,
	email, password string, mustChange bool) {
	t.Helper()
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	u := &licensestore.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		Email:              email,
		Name:               "Test",
		Role:               "platform_admin",
		Password:           string(hashed),
		MustChangePassword: mustChange,
	}
	require.NoError(t, store.CreateUser(context.Background(), u))
}

func TestLogin_MustChangePasswordFlagSurfacesInResponse(t *testing.T) {
	ts, store := setupTestServer(t)
	seedUserWithPassword(t, store, "alice@example.com", "TempPwd123!", true)

	resp := postLogin(t, ts.URL, "alice@example.com", "TempPwd123!")
	require.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, true, resp.Body["mustChangePassword"])
}

func TestLogin_MustChangePasswordFalseAfterChange(t *testing.T) {
	ts, store := setupTestServer(t)
	seedUserWithPassword(t, store, "alice@example.com", "TempPwd123!", true)
	first := postLogin(t, ts.URL, "alice@example.com", "TempPwd123!")
	token := first.Body["token"].(string)

	change := authedDo(t, ts.URL, token, http.MethodPost,
		"/api/v1/auth/change-password",
		map[string]string{"current": "TempPwd123!", "next": "NewPassword123!"})
	require.Equal(t, http.StatusOK, change.Code)

	relogin := postLogin(t, ts.URL, "alice@example.com", "NewPassword123!")
	require.Equal(t, http.StatusOK, relogin.Code)
	assert.Equal(t, false, relogin.Body["mustChangePassword"])
}

func TestChangePassword_Success_RotatesJWT(t *testing.T) {
	ts, store := setupTestServer(t)
	seedUserWithPassword(t, store, "alice@example.com", "TempPwd123!", true)
	first := postLogin(t, ts.URL, "alice@example.com", "TempPwd123!")
	oldToken := first.Body["token"].(string)

	change := authedDo(t, ts.URL, oldToken, http.MethodPost,
		"/api/v1/auth/change-password",
		map[string]string{"current": "TempPwd123!", "next": "NewPassword123!"})
	require.Equal(t, http.StatusOK, change.Code)
	newToken := change.Body["token"].(string)
	assert.NotEqual(t, oldToken, newToken)

	// Old token must no longer be accepted.
	probe := authedDo(t, ts.URL, oldToken, http.MethodGet, "/api/v1/admin/stats", nil)
	assert.Equal(t, http.StatusUnauthorized, probe.Code)

	// New token must work.
	probeNew := authedDo(t, ts.URL, newToken, http.MethodGet, "/api/v1/admin/stats", nil)
	assert.Equal(t, http.StatusOK, probeNew.Code)
}

func TestChangePassword_WrongCurrent_Returns401(t *testing.T) {
	ts, store := setupTestServer(t)
	seedUserWithPassword(t, store, "alice@example.com", "TempPwd123!", true)
	login := postLogin(t, ts.URL, "alice@example.com", "TempPwd123!")

	resp := authedDo(t, ts.URL, login.Body["token"].(string), http.MethodPost,
		"/api/v1/auth/change-password",
		map[string]string{"current": "wrong", "next": "NewPassword123!"})
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
}

func TestChangePassword_ShortNext_Returns400(t *testing.T) {
	ts, store := setupTestServer(t)
	seedUserWithPassword(t, store, "alice@example.com", "TempPwd123!", true)
	login := postLogin(t, ts.URL, "alice@example.com", "TempPwd123!")

	resp := authedDo(t, ts.URL, login.Body["token"].(string), http.MethodPost,
		"/api/v1/auth/change-password",
		map[string]string{"current": "TempPwd123!", "next": "short"})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
}
