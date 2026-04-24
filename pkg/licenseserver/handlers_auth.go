package licenseserver

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
	"github.com/amiryahaya/triton/pkg/licensestore"
)

const jwtTTL = 24 * time.Hour

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	// Normalize email to match the storage format used by handleCreateSuperadmin.
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Phase 5.1 — per-email rate limit BEFORE the bcrypt comparison.
	// See pkg/server/handlers_auth.go::handleLogin for the rationale;
	// the license server uses the exact same policy so the superadmin
	// login endpoint has the same brute-force posture as the org user
	// endpoint.
	if allowed, retryAfter := s.loginLimiter.Check(email); !allowed {
		seconds := int(retryAfter.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		auth.LogFailedLogin("license", "rate_limited", email, r.RemoteAddr, "retry-after="+strconv.Itoa(seconds))
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
		return
	}

	// loadPlatformAdminByEmail enforces the role check at the lookup
	// boundary. Both "no such user" and "user is not a platform_admin"
	// surface as a 404 from the helper, which we collapse into a 401
	// here so the login endpoint never leaks user existence or role.
	user, status, _ := s.loadPlatformAdminByEmail(r.Context(), email)
	if status != 0 {
		s.loginLimiter.RecordFailure(email)
		auth.LogFailedLogin("license", "unknown_email_or_non_admin", email, r.RemoteAddr, "no matching platform_admin")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		s.loginLimiter.RecordFailure(email)
		auth.LogFailedLogin("license", "bad_password", email, r.RemoteAddr, "bcrypt mismatch")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Successful login — clear the failure counter.
	s.loginLimiter.RecordSuccess(email)
	auth.LogSuccessfulLogin("license", email, r.RemoteAddr)

	claims := &auth.UserClaims{
		Sub:                user.ID,
		Org:                user.OrgID,
		Role:               user.Role,
		Name:               user.Name,
		MustChangePassword: user.MustChangePassword,
	}
	token, err := auth.SignJWT(claims, s.config.SigningKey, jwtTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign token")
		return
	}

	// Create session (store hash of token for server-side validation).
	h := sha256.Sum256([]byte(token))
	sess := &licensestore.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: hex.EncodeToString(h[:]),
		ExpiresAt: time.Now().Add(jwtTTL),
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":              token,
		"expiresAt":          sess.ExpiresAt.Format(time.RFC3339),
		"mustChangePassword": user.MustChangePassword,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization header")
		return
	}

	h := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(h[:])

	sess, err := s.store.GetSessionByHash(r.Context(), tokenHash)
	if err != nil {
		// Session not found — already logged out or invalid token.
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}

	// Surface DB errors rather than silently leaking sessions. A "successful"
	// logout that doesn't actually delete the session would be worse than
	// reporting the failure.
	if err := s.store.DeleteSession(r.Context(), sess.ID); err != nil {
		log.Printf("logout: delete session %s failed: %v", sess.ID, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization header")
		return
	}

	// Verify current JWT (allow within grace period).
	claims, err := auth.VerifyJWT(token, s.config.PublicKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	// Re-fetch the user via loadPlatformAdminByID so role enforcement
	// runs at the lookup boundary. This ensures that:
	//   - Deleted users cannot refresh (lookup fails)
	//   - Role demotions take effect on the next refresh
	//   - Name changes in the DB propagate into the new token
	//   - Only platform_admin users can refresh (defense in depth against C1)
	// We collapse the helper's 404 into the generic "invalid or expired
	// token" message — the refresh endpoint must not leak whether a user
	// existed or had a different role.
	user, status, _ := s.loadPlatformAdminByID(r.Context(), claims.Sub)
	if status != 0 {
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	// Delete old session. Any failure here is surfaced rather than swallowed —
	// leaving the old session alive while issuing a new token would double
	// the attack surface of a stolen token.
	h := sha256.Sum256([]byte(token))
	oldHash := hex.EncodeToString(h[:])
	if sess, err := s.store.GetSessionByHash(r.Context(), oldHash); err == nil {
		if err := s.store.DeleteSession(r.Context(), sess.ID); err != nil {
			log.Printf("refresh: delete old session %s failed: %v", sess.ID, err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	// Issue new token with freshly-fetched user state.
	newClaims := &auth.UserClaims{
		Sub:                user.ID,
		Org:                user.OrgID,
		Role:               user.Role,
		Name:               user.Name,
		MustChangePassword: user.MustChangePassword,
	}
	newToken, err := auth.SignJWT(newClaims, s.config.SigningKey, jwtTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign token")
		return
	}

	nh := sha256.Sum256([]byte(newToken))
	sess := &licensestore.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: hex.EncodeToString(nh[:]),
		ExpiresAt: time.Now().Add(jwtTTL),
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":     newToken,
		"expiresAt": sess.ExpiresAt.Format(time.RFC3339),
	})
}

// POST /api/v1/auth/change-password (JWT-gated)
// Verifies the current password via bcrypt, sets the new one, clears
// the must_change_password flag, and rotates the JWT — old sessions
// are revoked and a fresh token is returned.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	authed, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Next) < auth.MinPasswordLength {
		writeError(w, http.StatusBadRequest, "new password must be at least 12 characters")
		return
	}

	user, err := s.store.GetUser(r.Context(), authed.ID)
	if err != nil {
		log.Printf("change password: get user: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Current)); err != nil {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Next), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if err := s.store.UpdateUser(r.Context(), licensestore.UserUpdate{
		ID:                 user.ID,
		Name:               user.Name,
		Password:           string(hashed),
		MustChangePassword: false,
	}); err != nil {
		log.Printf("change password: update user: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Revoke all old sessions. For a still-active user (unlike delete-user) there
	// is no JWTAuth safety net — old tokens remain live until they expire. Treat
	// failure as fatal so the caller knows their old sessions are still valid.
	if err := s.store.DeleteSessionsForUser(r.Context(), user.ID); err != nil {
		log.Printf("change password: revoke sessions: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	claims := &auth.UserClaims{
		Sub:  user.ID,
		Org:  user.OrgID,
		Role: user.Role,
		Name: user.Name,
	}
	newToken, err := auth.SignJWT(claims, s.config.SigningKey, jwtTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign token")
		return
	}

	h := sha256.Sum256([]byte(newToken))
	sess := &licensestore.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    user.ID,
		TokenHash: hex.EncodeToString(h[:]),
		ExpiresAt: time.Now().Add(jwtTTL),
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	s.audit(r, "password_changed", "", "", "", map[string]any{
		"user_id": user.ID,
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"token":     newToken,
		"expiresAt": sess.ExpiresAt.Format(time.RFC3339),
	})
}

// extractBearerToken extracts the token from "Authorization: Bearer <token>".
func extractBearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(header, "Bearer ")
}
