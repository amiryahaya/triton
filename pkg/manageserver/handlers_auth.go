package manageserver

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/managestore"
)

// handleLogin authenticates a user by email + password, creates a session,
// and returns a signed JWT.
// POST /api/v1/auth/login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password required")
		return
	}

	clientIP := remoteIP(r.RemoteAddr)
	if s.loginLimiter != nil && s.loginLimiter.Locked(req.Email, clientIP) {
		writeError(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}

	user, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		if s.loginLimiter != nil {
			s.loginLimiter.Record(req.Email, clientIP)
		}
		// Constant-time feel: still attempt hash comparison on dummy value.
		_ = VerifyPassword("$2a$12$dummydummydummydummydummydummydummydummydummydummy", req.Password)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := VerifyPassword(user.PasswordHash, req.Password); err != nil {
		if s.loginLimiter != nil {
			s.loginLimiter.Record(req.Email, clientIP)
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	now := time.Now()
	claims := JWTClaims{
		Sub:  user.ID,
		Role: user.Role,
		Iat:  now.Unix(),
		Exp:  now.Add(s.cfg.SessionTTL).Unix(),
		Jti:  now.UnixNano(),
		Mcp:  user.MustChangePW,
	}
	token, err := signJWT(claims, s.cfg.JWTSigningKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue token failed")
		return
	}
	hash := hashToken(token)
	sess := &managestore.ManageSession{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: now.Add(s.cfg.SessionTTL),
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		writeError(w, http.StatusInternalServerError, "store session failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token": token,
		"user": map[string]any{
			"id":             user.ID,
			"email":          user.Email,
			"name":           user.Name,
			"role":           user.Role,
			"must_change_pw": user.MustChangePW,
		},
	})
}

// handleLogout deletes the session backing the presented token.
// Idempotent: unknown tokens return 204.
// POST /api/v1/auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sess, err := s.store.GetSessionByTokenHash(r.Context(), hashToken(token))
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_ = s.store.DeleteSession(r.Context(), sess.ID)
	w.WriteHeader(http.StatusNoContent)
}

// handleRefresh issues a new token and replaces the session row.
// POST /api/v1/auth/refresh
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	oldToken := bearerToken(r)
	if oldToken == "" {
		writeError(w, http.StatusUnauthorized, "missing token")
		return
	}
	claims, err := parseJWT(oldToken, s.cfg.JWTSigningKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	oldHash := hashToken(oldToken)
	oldSess, err := s.store.GetSessionByTokenHash(r.Context(), oldHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "session not found")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user missing")
		return
	}

	now := time.Now()
	newClaims := JWTClaims{
		Sub:  user.ID,
		Role: user.Role,
		Iat:  now.Unix(),
		Exp:  now.Add(s.cfg.SessionTTL).Unix(),
		Jti:  now.UnixNano(),
		Mcp:  user.MustChangePW,
	}
	newToken, err := signJWT(newClaims, s.cfg.JWTSigningKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue token failed")
		return
	}
	// Delete the old session first to avoid a token_hash uniqueness conflict
	// in the rare case where two tokens hash identically (same-second issue).
	_ = s.store.DeleteSession(r.Context(), oldSess.ID)

	newSess := &managestore.ManageSession{
		UserID:    user.ID,
		TokenHash: hashToken(newToken),
		ExpiresAt: now.Add(s.cfg.SessionTTL),
	}
	if err := s.store.CreateSession(r.Context(), newSess); err != nil {
		writeError(w, http.StatusInternalServerError, "store session failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"token": newToken})
}

// handleChangePassword rotates the authenticated user's password and issues
// a fresh session. Tolerates must_change_pw=true sessions — this is the one
// endpoint forced-change users can hit.
//
// POST /api/v1/auth/change-password
// Body: {"current":"<plain>","next":"<plain>"}
// 200:  {"token":"<jwt>","expires_at":"...","must_change_password":false}
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	// 1. Auth — parse token, locate session + user.
	token := bearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization header")
		return
	}
	claims, err := parseJWT(token, s.cfg.JWTSigningKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	oldHash := hashToken(token)
	oldSess, err := s.store.GetSessionByTokenHash(r.Context(), oldHash)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "session not found")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), claims.Sub)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user not found")
		return
	}

	// 2. Decode + validate body.
	var req struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Current == "" || req.Next == "" {
		writeError(w, http.StatusBadRequest, "current and next password required")
		return
	}
	if req.Next == req.Current {
		writeError(w, http.StatusBadRequest, "new password must differ from current")
		return
	}
	if err := validatePassword(req.Next); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// 3. Verify current password.
	if err := VerifyPassword(user.PasswordHash, req.Current); err != nil {
		writeError(w, http.StatusUnauthorized, "current password incorrect")
		return
	}

	// 4. Hash + persist (atomically clears must_change_pw inside
	// UpdateUserPassword).
	nextHash, err := HashPassword(req.Next)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), user.ID, nextHash); err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// 5. Rotate session — delete old row BEFORE minting the new token so a
	// token_hash collision on same-second issue can never fire.
	_ = s.store.DeleteSession(r.Context(), oldSess.ID)

	now := time.Now()
	newClaims := JWTClaims{
		Sub:  user.ID,
		Role: user.Role,
		Iat:  now.Unix(),
		Exp:  now.Add(s.cfg.SessionTTL).Unix(),
		Jti:  now.UnixNano(),
		Mcp:  false,
	}
	newToken, err := signJWT(newClaims, s.cfg.JWTSigningKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	expiresAt := now.Add(s.cfg.SessionTTL)
	newSess := &managestore.ManageSession{
		UserID:    user.ID,
		TokenHash: hashToken(newToken),
		ExpiresAt: expiresAt,
	}
	if err := s.store.CreateSession(r.Context(), newSess); err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":                newToken,
		"expires_at":           expiresAt.UTC().Format(time.RFC3339),
		"must_change_password": false,
	})
}

// handleMe returns the authenticated user (requires jwtAuth middleware).
// GET /api/v1/me
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             user.ID,
		"email":          user.Email,
		"name":           user.Name,
		"role":           user.Role,
		"must_change_pw": user.MustChangePW,
	})
}

// bearerToken extracts the token from Authorization: Bearer <...>.
// Returns "" if header missing or malformed.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimPrefix(h, prefix)
}

// remoteIP extracts just the host from a host:port RemoteAddr string.
// Falls back to the raw value when parsing fails.
func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
