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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/store"
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

// newTestLoginLimiter returns a rate-limiter with a tight budget and
// near-instant lockout duration so rate-limit tests finish in
// milliseconds rather than the 15-minute production defaults. The
// 5-attempt budget matches prod so the test wording remains accurate.
func newTestLoginLimiter() *auth.LoginRateLimiter {
	return auth.NewLoginRateLimiter(auth.LoginRateLimiterConfig{
		MaxAttempts:     5,
		Window:          1 * time.Hour,
		LockoutDuration: 1 * time.Hour,
	})
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

// TestLogin_RateLimited_AfterRepeatedFailures verifies Phase 5.1: after
// the configured number of failed login attempts on the same email, the
// next attempt returns 429 with a Retry-After header and does NOT hit
// the bcrypt comparison (measurable by returning even when the password
// is actually correct — we don't test timing but we do verify the 429
// is returned even for a RIGHT password).
func TestLogin_RateLimited_AfterRepeatedFailures(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_user", "correct-password-123", false)

	// Swap in a fast-cycle limiter so the test runs in milliseconds
	// rather than the 15-minute production defaults.
	srv.loginLimiter = newTestLoginLimiter()

	// Burn through the budget with wrong passwords.
	for i := 0; i < 5; i++ {
		w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
			"email":    user.Email,
			"password": "wrong-password",
		})
		require.Equal(t, http.StatusUnauthorized, w.Code,
			"attempt %d should be 401 not 429 (still within budget)", i+1)
	}

	// 6th attempt — even with the CORRECT password — must be 429.
	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    user.Email,
		"password": "correct-password-123",
	})
	require.Equal(t, http.StatusTooManyRequests, w.Code,
		"after 5 failures the limiter must block even a correct password")
	assert.NotEmpty(t, w.Header().Get("Retry-After"),
		"429 response must include a Retry-After header")
}

// TestLogin_RateLimit_ResetsOnSuccess verifies that a successful login
// clears the counter so a user who mistypes a few times then gets it
// right doesn't carry the failure budget into a later session.
func TestLogin_RateLimit_ResetsOnSuccess(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_user", "correct-password-123", false)
	srv.loginLimiter = newTestLoginLimiter()

	// 4 failures (one under the 5-attempt threshold).
	for i := 0; i < 4; i++ {
		authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
			"email":    user.Email,
			"password": "wrong",
		})
	}

	// Success — should reset the counter.
	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    user.Email,
		"password": "correct-password-123",
	})
	require.Equal(t, http.StatusOK, w.Code)

	// Now 5 more failures should be permitted before the 6th locks.
	for i := 0; i < 5; i++ {
		w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
			"email":    user.Email,
			"password": "wrong",
		})
		require.Equal(t, http.StatusUnauthorized, w.Code,
			"post-reset attempt %d should still be 401", i+1)
	}
}

// TestLogin_InviteExpired_Rejects verifies Phase 5.2: a user with
// mcp=true whose invited_at is older than the invite expiry window
// gets 403, even with the correct temp password.
func TestLogin_InviteExpired_Rejects(t *testing.T) {
	srv, db := testServerWithJWT(t)

	// Create an org + user directly so we can backdate invited_at.
	ctx := context.Background()
	org := &store.Organization{
		ID:   "00000000-0000-0000-0000-00000000f001",
		Name: "Expired Invite Org",
	}
	require.NoError(t, db.CreateOrg(ctx, org))
	hashed, err := bcrypt.GenerateFromPassword([]byte("temp-password-1234"), bcrypt.DefaultCost)
	require.NoError(t, err)
	user := &store.User{
		ID:                 "00000000-0000-0000-0000-00000000e001",
		OrgID:              org.ID,
		Email:              "expired-invite@auth.test",
		Name:               "Expired Invitee",
		Role:               "org_user",
		Password:           string(hashed),
		MustChangePassword: true,
		InvitedAt:          time.Now().Add(-30 * 24 * time.Hour), // 30 days ago
	}
	require.NoError(t, db.CreateUser(ctx, user))

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    user.Email,
		"password": "temp-password-1234",
	})
	// Per D4 from the Phase 5.1/5.2 review: the response collapses to
	// 401 "invalid credentials" rather than 403 "invite expired" so
	// an attacker holding a stolen temp password cannot use the
	// status-code difference to confirm the credential was historically
	// valid. Recovery path for legitimate users is the resend-invite
	// endpoint, not a distinct error code on login.
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"expired invite must return 401 (not 403) to avoid a credential oracle")
}

// TestLogin_InviteExpired_IgnoredForCompletedUsers verifies that a
// user who has already rotated their password (mcp=false) is NOT
// affected by an old invited_at — the gate only applies while the
// must-change-password flag is still set.
func TestLogin_InviteExpired_IgnoredForCompletedUsers(t *testing.T) {
	srv, db := testServerWithJWT(t)
	ctx := context.Background()
	org := &store.Organization{
		ID:   "00000000-0000-0000-0000-00000000f002",
		Name: "Completed User Org",
	}
	require.NoError(t, db.CreateOrg(ctx, org))
	hashed, err := bcrypt.GenerateFromPassword([]byte("rotated-password-1234"), bcrypt.DefaultCost)
	require.NoError(t, err)
	user := &store.User{
		ID:                 "00000000-0000-0000-0000-00000000e002",
		OrgID:              org.ID,
		Email:              "completed@auth.test",
		Name:               "Completed User",
		Role:               "org_user",
		Password:           string(hashed),
		MustChangePassword: false, // already rotated
		InvitedAt:          time.Now().Add(-365 * 24 * time.Hour),
	}
	require.NoError(t, db.CreateUser(ctx, user))

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    user.Email,
		"password": "rotated-password-1234",
	})
	assert.Equal(t, http.StatusOK, w.Code,
		"user who already rotated their password must not be gated by invited_at")
}

// TestLogin_InviteFresh_Succeeds verifies the happy path: an invite
// younger than the expiry window still allows first-login.
func TestLogin_InviteFresh_Succeeds(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, user := createOrgUser(t, db, "org_user", "fresh-invite-1234", true)
	// createOrgUser inserts with InvitedAt=zero; CreateUser defaults it
	// to now, so this user's invite is fresh by construction.

	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    user.Email,
		"password": "fresh-invite-1234",
	})
	require.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, true, resp["mustChangePassword"])
}

// TestLogin_RateLimit_PerEmail verifies that a lockout on alice does
// NOT affect bob.
func TestLogin_RateLimit_PerEmail(t *testing.T) {
	srv, db := testServerWithJWT(t)
	_, alice := createOrgUser(t, db, "org_user", "alice-pw-1234567", false)
	_, bob := createOrgUser(t, db, "org_user", "bob-pw-1234567", false)
	srv.loginLimiter = newTestLoginLimiter()

	// Lock alice.
	for i := 0; i < 5; i++ {
		authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
			"email":    alice.Email,
			"password": "wrong",
		})
	}

	// Bob should still be able to log in normally.
	w := authReq(t, srv, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"email":    bob.Email,
		"password": "bob-pw-1234567",
	})
	assert.Equal(t, http.StatusOK, w.Code, "bob must not be affected by alice's lockout")
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
