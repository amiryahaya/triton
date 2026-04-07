//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// authReq sends a JSON POST to the given path with optional Bearer token.
func authReq(t *testing.T, srv *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(b)
	}
	var req *http.Request
	if bodyReader != nil {
		req = httptest.NewRequest(method, path, bodyReader)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	return w
}

// loginAndExtractToken issues a login and returns the resulting JWT.
func loginAndExtractToken(t *testing.T, srv *Server, email, password string) string {
	t.Helper()
	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    email,
		"password": password,
	})
	require.Equal(t, http.StatusOK, w.Code, "login failed: %s", w.Body.String())
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	return resp["token"].(string)
}

// --- Login ---

func TestLogin_Success(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "correct-horse-battery", false)

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    user.Email,
		"password": "correct-horse-battery",
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.NotEmpty(t, resp["token"])
	assert.NotEmpty(t, resp["expiresAt"])
	assert.Equal(t, false, resp["mustChangePassword"])
}

func TestLogin_NormalizesEmail(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_user", "correct-horse-battery", false)

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    "  " + strings.ToUpper(user.Email[:1]) + user.Email[1:],
		"password": "correct-horse-battery",
	})
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogin_WrongPassword(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_user", "correct", false)

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    user.Email,
		"password": "wrong",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_UnknownEmail(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    "nobody@example.com",
		"password": "anything",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogin_MustChangePasswordFlag(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "temp-password-from-invite", true)

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    user.Email,
		"password": "temp-password-from-invite",
	})
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, true, resp["mustChangePassword"], "invited user must see mcp=true on login")
}

func TestLogin_MissingFields(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Logout ---

func TestLogout_Success(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_user", "pw1234567890", false)
	token := loginAndExtractToken(t, srv, user.Email, "pw1234567890")

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/logout", token, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogout_MissingToken(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/logout", "", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestLogout_RejectsInvalidJWT verifies M3: logout must cryptographically
// verify the JWT before doing the session-hash lookup. Without this, the
// endpoint's implicit contract becomes "logout by token-hash knowledge"
// rather than "logout by JWT possession" — an attacker who knows a
// session's hash (or can craft a string hashing to one) could force-logout
// a victim.
func TestLogout_RejectsInvalidJWT(t *testing.T) {
	srv, _ := testServerWithJWT(t)
	// A syntactically valid 3-part JWT but signed with the wrong key.
	// Without M3, the handler would still SHA-256 hash this and try the
	// session lookup; with M3, it rejects with 401 before touching the DB.
	bogusToken := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZXIifQ.fake-signature-bytes"

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/logout", bogusToken, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Refresh ---

func TestRefresh_Success(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "pw1234567890", false)
	oldToken := loginAndExtractToken(t, srv, user.Email, "pw1234567890")

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/refresh", oldToken, nil)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	newToken := resp["token"].(string)
	assert.NotEmpty(t, newToken)
	assert.NotEqual(t, oldToken, newToken, "refresh must produce a new token")
}

func TestRefresh_RejectsDeletedUser(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_user", "pw1234567890", false)
	token := loginAndExtractToken(t, srv, user.Email, "pw1234567890")

	require.NoError(t, db.DeleteUser(context.Background(), user.ID))

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/refresh", token, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "deleted user must not be able to refresh")
}

// --- Change password ---

func TestChangePassword_Success(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "old-temp-password", true)
	token := loginAndExtractToken(t, srv, user.Email, "old-temp-password")

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/change-password", token, map[string]string{
		"current_password": "old-temp-password",
		"new_password":     "brand-new-strong-password",
	})
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, false, resp["mustChangePassword"], "flag must be cleared in response")
	assert.NotEmpty(t, resp["token"], "fresh token must be issued")

	// Verify the DB row is updated.
	updated, err := db.GetUser(context.Background(), user.ID)
	require.NoError(t, err)
	assert.False(t, updated.MustChangePassword, "DB flag must be cleared")

	// Old password no longer works.
	wOld := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    user.Email,
		"password": "old-temp-password",
	})
	assert.Equal(t, http.StatusUnauthorized, wOld.Code)

	// New password works.
	wNew := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    user.Email,
		"password": "brand-new-strong-password",
	})
	assert.Equal(t, http.StatusOK, wNew.Code)
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "real-password", true)
	token := loginAndExtractToken(t, srv, user.Email, "real-password")

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/change-password", token, map[string]string{
		"current_password": "wrong-password",
		"new_password":     "brand-new-strong-password",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestChangePassword_WeakNewPassword(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "real-password", true)
	token := loginAndExtractToken(t, srv, user.Email, "real-password")

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/change-password", token, map[string]string{
		"current_password": "real-password",
		"new_password":     "short",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, strings.ToLower(w.Body.String()), "password")
}

func TestChangePassword_SameAsCurrent(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_admin", "samepw1234567", true)
	token := loginAndExtractToken(t, srv, user.Email, "samepw1234567")

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/change-password", token, map[string]string{
		"current_password": "samepw1234567",
		"new_password":     "samepw1234567",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Route disabled when JWT not configured ---

func TestAuthRoutes_DisabledWithoutJWTKey(t *testing.T) {
	// A server without JWTSigningKey shouldn't expose any /auth routes.
	srv, _ := testServer(t)

	for _, path := range []string{"/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/refresh", "/api/v1/auth/change-password"} {
		w := authReq(t, srv, http.MethodPost, path, "", map[string]string{"email": "x", "password": "x"})
		assert.Equal(t, http.StatusNotFound, w.Code, "path=%s", path)
	}
}
