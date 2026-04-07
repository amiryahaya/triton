package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/store"
)

const (
	userJWTTTL         = 24 * time.Hour
	minUserPasswordLen = 12
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
	user, status := s.loadOrgUserByEmail(r.Context(), email)
	if status != 0 {
		// Generic 401 to prevent user enumeration. Don't surface the
		// helper's 404 directly.
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, expiresAt, err := s.signUserToken(r, user)
	if err != nil {
		log.Printf("login: sign token error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

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
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization header")
		return
	}

	claims, err := auth.VerifyJWT(token, s.config.JWTPublicKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
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
// must_change_password=true is permitted to call (Phase 1.5e will add
// the middleware that enforces this gate).
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization header")
		return
	}

	claims, err := auth.VerifyJWT(token, s.config.JWTPublicKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
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
