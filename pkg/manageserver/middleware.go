package manageserver

import (
	"net/http"

	"github.com/amiryahaya/triton/pkg/managestore"
)

type contextKey string

const userCtxKey contextKey = "manage.user"

// userFromContext returns the authenticated user, or nil if not authenticated.
func userFromContext(r *http.Request) *managestore.ManageUser {
	if v, ok := r.Context().Value(userCtxKey).(*managestore.ManageUser); ok {
		return v
	}
	return nil
}

// SetupOnly allows requests only when the server is in setup mode.
// If setup is already complete, returns 409.
// Wired by Task 4.x for /api/v1/setup/admin and /api/v1/setup/license.
func (s *Server) SetupOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isSetupMode() {
			writeError(w, http.StatusConflict, "setup already complete")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireOperational blocks requests when the server is in setup mode.
// Returns 503 with setup_required=true.
func (s *Server) requireOperational(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isSetupMode() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"setup_required": true,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// jwtAuth parses Authorization: Bearer <token>, validates the HS256 signature,
// looks up the session by token hash, and stashes the user in request context.
// Returns 401 on any failure.
func (s *Server) jwtAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		hash := hashToken(token)
		sess, err := s.store.GetSessionByTokenHash(r.Context(), hash)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "session revoked or expired")
			return
		}
		user, err := s.store.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "user not found")
			return
		}
		// Stale claims check: ensure token subject matches session user.
		if claims.Sub != user.ID {
			writeError(w, http.StatusUnauthorized, "token mismatch")
			return
		}
		ctx := r.Context()
		ctx = contextWithUser(ctx, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole returns middleware that admits only users whose role is in the
// provided list. Must be chained AFTER jwtAuth.
// Wired by Task 4.x for admin-only endpoints.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := userFromContext(r)
			if user == nil {
				writeError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if _, ok := allowed[user.Role]; !ok {
				writeError(w, http.StatusForbidden, "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
