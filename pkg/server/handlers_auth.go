package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/store"
)

const (
	userJWTTTL = 24 * time.Hour
	// minUserPasswordLen aliases auth.MinPasswordLength so the existing
	// call sites in pkg/server stay readable. The canonical value lives
	// in internal/auth/password.go — raise it there.
	minUserPasswordLen = auth.MinPasswordLength
	// inviteExpiryWindow caps how long an unused invite (a user with
	// must_change_password=true who has never completed the first-login
	// flow) remains valid. Beyond this window handleLogin returns 403
	// and the user must have an admin issue a fresh invite via the
	// resend-invite flow. Phase 5.2.
	inviteExpiryWindow = 7 * 24 * time.Hour
)

// signUserToken issues a JWT for the given user and creates a session row
// referencing it. Returns (token, expiresAt, error).
func (s *Server) signUserToken(r *http.Request, user *store.User) (string, time.Time, error) {
	claims := &auth.UserClaims{
		Sub:                user.ID,
		Org:                user.OrgID,
		Role:               user.Role,
		Name:               user.Name,
		MustChangePassword: user.MustChangePassword,
	}
	token, err := auth.SignJWT(claims, s.config.JWTSigningKey, userJWTTTL)
	if err != nil {
		return "", time.Time{}, err
	}

	h := sha256.Sum256([]byte(token))
	expiresAt := time.Now().Add(userJWTTTL)
	sess := &store.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: hex.EncodeToString(h[:]),
		ExpiresAt: expiresAt,
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// extractBearerToken extracts the token from "Authorization: Bearer <token>".
func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(authHeader, "Bearer ")
}

// extractAndVerifyBearer extracts the Bearer token from the request and
// cryptographically verifies it against the report server's JWT public
// key. Returns the raw token string + parsed claims on success, or
// (empty, nil, errStatus) on failure.
//
// This is the shared prologue for handlers that don't run behind the
// JWTAuth middleware (logout, refresh, change-password) — those routes
// can't use middleware because some of them run in contexts where the
// user state isn't yet known to be valid (e.g., refresh re-derives it
// from the DB rather than trusting the token).
//
// Callers should map the returned errStatus to a generic "invalid or
// expired token" message — never leak which specific check failed.
func (s *Server) extractAndVerifyBearer(r *http.Request) (token string, claims *auth.UserClaims, errStatus int) {
	token = extractBearerToken(r)
	if token == "" {
		return "", nil, http.StatusUnauthorized
	}
	claims, err := auth.VerifyJWT(token, s.config.JWTPublicKey)
	if err != nil {
		return "", nil, http.StatusUnauthorized
	}
	return token, claims, 0
}

// POST /api/v1/auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Phase 5.1 — rate-limit the per-email failure counter BEFORE the
	// bcrypt comparison so a locked account returns 429 without burning
	// CPU on hash verification. The limiter is checked against the
	// normalized email so casing attacks can't bypass it. The 429 path
	// is reached for both unknown emails (they still share the bucket)
	// and known emails — deliberately: we want to make it expensive to
	// enumerate existence by hammering a single address.
	if allowed, retryAfter := s.loginLimiter.Check(email); !allowed {
		seconds := int(retryAfter.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
		return
	}

	user, status := s.loadOrgUserByEmail(r.Context(), email)
	if status != 0 {
		// Generic 401 to prevent user enumeration. Don't surface the
		// helper's 404 directly. Still record the failure so attackers
		// who guess non-existent emails also burn through the budget.
		s.loginLimiter.RecordFailure(email)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		s.loginLimiter.RecordFailure(email)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Phase 5.2 — invite expiry. A user who is still holding an invite
	// (mcp=true) whose temp-password credential was issued more than
	// inviteExpiryWindow ago cannot complete the first-login flow. This
	// check runs AFTER password verification so an attacker cannot
	// distinguish "expired invite" from "wrong password" by response
	// code alone — both require knowing the temp password to observe
	// anything other than 401. Users who have already rotated their
	// password (mcp=false) ignore invited_at entirely.
	if user.MustChangePassword && !user.InvitedAt.IsZero() &&
		time.Since(user.InvitedAt) > inviteExpiryWindow {
		// Record as a failure so an attacker scanning for expired
		// invites still burns through the rate-limit budget.
		s.loginLimiter.RecordFailure(email)
		writeError(w, http.StatusForbidden,
			"invite has expired; contact your organization administrator for a new invite")
		return
	}

	token, expiresAt, err := s.signUserToken(r, user)
	if err != nil {
		log.Printf("login: sign token error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Successful login — clear the failure counter so earlier mistypes
	// don't accumulate against this user for the next session.
	s.loginLimiter.RecordSuccess(email)

	// Surface must_change_password in the response so the UI can route
	// the user to the change-password screen on first login.
	writeJSON(w, http.StatusOK, map[string]any{
		"token":              token,
		"expiresAt":          expiresAt.Format(time.RFC3339),
		"mustChangePassword": user.MustChangePassword,
	})
}

// POST /api/v1/auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Verify the JWT cryptographically before doing anything else.
	// Without this, an attacker who knows a session's token-hash (or
	// can craft a string that hashes to one) could force-logout a
	// victim. The JWT verification ensures only the legitimate token
	// holder can reach the session lookup.
	token, _, status := s.extractAndVerifyBearer(r)
	if status != 0 {
		writeError(w, status, "invalid or expired token")
		return
	}

	h := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(h[:])

	sess, err := s.store.GetSessionByHash(r.Context(), tokenHash)
	if err != nil {
		// Session not found — already logged out, or token is valid
		// JWT-wise but its session was already invalidated. Either way,
		// idempotent success.
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	// Surface DB errors rather than silently leaking sessions (M6 lesson).
	if err := s.store.DeleteSession(r.Context(), sess.ID); err != nil {
		log.Printf("logout: delete session %s failed: %v", sess.ID, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/v1/auth/refresh
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	token, claims, status := s.extractAndVerifyBearer(r)
	if status != 0 {
		writeError(w, status, "invalid or expired token")
		return
	}

	// Re-fetch the user from the DB so role/name/org changes propagate
	// and deleted users cannot refresh (H2 lesson from license server).
	user, status := s.loadOrgUserByID(r.Context(), claims.Sub)
	if status != 0 {
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	// Delete old session. Surface failure rather than swallow (M7 lesson).
	h := sha256.Sum256([]byte(token))
	oldHash := hex.EncodeToString(h[:])
	if sess, err := s.store.GetSessionByHash(r.Context(), oldHash); err == nil {
		if err := s.store.DeleteSession(r.Context(), sess.ID); err != nil {
			log.Printf("refresh: delete old session %s failed: %v", sess.ID, err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	newToken, expiresAt, err := s.signUserToken(r, user)
	if err != nil {
		log.Printf("refresh: sign token error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":              newToken,
		"expiresAt":          expiresAt.Format(time.RFC3339),
		"mustChangePassword": user.MustChangePassword,
	})
}

// POST /api/v1/auth/change-password
//
// Accepts the user's current password (must match) plus a new password,
// re-hashes, persists, and clears the must_change_password flag. Issues
// a fresh JWT reflecting the cleared flag so the client can immediately
// access protected routes.
//
// This endpoint is the ONLY route that an authenticated user with
// must_change_password=true is permitted to call. The Phase 1.5e
// BlockUntilPasswordChanged middleware enforces this elsewhere; this
// route is deliberately NOT behind that middleware.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	token, claims, status := s.extractAndVerifyBearer(r)
	if status != 0 {
		writeError(w, status, "invalid or expired token")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}
	if len(req.NewPassword) < minUserPasswordLen {
		writeError(w, http.StatusBadRequest, "new_password must be at least 12 characters")
		return
	}
	if req.NewPassword == req.CurrentPassword {
		writeError(w, http.StatusBadRequest, "new_password must differ from current_password")
		return
	}

	user, status := s.loadOrgUserByID(r.Context(), claims.Sub)
	if status != 0 {
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.CurrentPassword)); err != nil {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("change-password: bcrypt error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Persist new password and clear must_change_password atomically
	// via the partial-update DTO.
	clearFlag := false
	if err := s.store.UpdateUser(r.Context(), store.UserUpdate{
		ID:                 user.ID,
		Name:               user.Name,
		Password:           string(hashed),
		MustChangePassword: &clearFlag,
	}); err != nil {
		log.Printf("change-password: update user error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Re-fetch so the new JWT reflects mustChangePassword=false.
	updated, status := s.loadOrgUserByID(r.Context(), user.ID)
	if status != 0 {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Invalidate the old session before issuing a new token.
	h := sha256.Sum256([]byte(token))
	oldHash := hex.EncodeToString(h[:])
	if sess, err := s.store.GetSessionByHash(r.Context(), oldHash); err == nil {
		if err := s.store.DeleteSession(r.Context(), sess.ID); err != nil {
			log.Printf("change-password: delete old session %s failed: %v", sess.ID, err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	newToken, expiresAt, err := s.signUserToken(r, updated)
	if err != nil {
		log.Printf("change-password: sign token error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":              newToken,
		"expiresAt":          expiresAt.Format(time.RFC3339),
		"mustChangePassword": false,
	})
}
