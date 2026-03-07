package licenseserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/license"
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

	user, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		// Generic error to prevent user enumeration.
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	claims := &license.UserClaims{
		Sub:  user.ID,
		Org:  user.OrgID,
		Role: user.Role,
		Name: user.Name,
	}
	token, err := license.SignJWT(claims, s.config.SigningKey, jwtTTL)
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
		"token":     token,
		"expiresAt": sess.ExpiresAt.Format(time.RFC3339),
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

	_ = s.store.DeleteSession(r.Context(), sess.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "missing authorization header")
		return
	}

	// Verify current JWT (allow within grace period).
	claims, err := license.VerifyJWT(token, s.config.PublicKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}

	// Delete old session.
	h := sha256.Sum256([]byte(token))
	oldHash := hex.EncodeToString(h[:])
	if sess, err := s.store.GetSessionByHash(r.Context(), oldHash); err == nil {
		_ = s.store.DeleteSession(r.Context(), sess.ID)
	}

	// Issue new token.
	newClaims := &license.UserClaims{
		Sub:  claims.Sub,
		Org:  claims.Org,
		Role: claims.Role,
		Name: claims.Name,
	}
	newToken, err := license.SignJWT(newClaims, s.config.SigningKey, jwtTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign token")
		return
	}

	nh := sha256.Sum256([]byte(newToken))
	sess := &licensestore.Session{
		ID:        uuid.Must(uuid.NewV7()).String(),
		UserID:    claims.Sub,
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

// extractBearerToken extracts the token from "Authorization: Bearer <token>".
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(auth, "Bearer ")
}
