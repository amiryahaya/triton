package licenseserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

type ctxKey string

const userCtxKey ctxKey = "license_user"

// AuthedUser is the shape stored in the request context by JWTAuth.
// Handlers retrieve it via UserFromContext(r.Context()).
type AuthedUser struct {
	ID                 string
	Email              string
	Name               string
	MustChangePassword bool
}

// UserFromContext returns the authenticated user or false if the
// context does not carry one (e.g., unauthed routes).
func UserFromContext(ctx context.Context) (AuthedUser, bool) {
	u, ok := ctx.Value(userCtxKey).(AuthedUser)
	return u, ok
}

// JWTAuth requires a valid platform_admin JWT on every request. Fails
// closed on any issue — missing/malformed header, bad signature,
// expired, revoked session, deleted user, wrong role.
func (s *Server) JWTAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr := r.Header.Get("Authorization")
			if !strings.HasPrefix(hdr, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}
			token := strings.TrimPrefix(hdr, "Bearer ")

			claims, err := auth.VerifyJWT(token, s.config.PublicKey)
			if err != nil {
				log.Printf("auth: verify jwt: %v", err)
				writeError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			// Require session to still exist (covers logout).
			h := sha256.Sum256([]byte(token))
			sess, err := s.store.GetSessionByHash(r.Context(), hex.EncodeToString(h[:]))
			if err != nil {
				writeError(w, http.StatusUnauthorized, "session revoked")
				return
			}
			if time.Now().After(sess.ExpiresAt) {
				writeError(w, http.StatusUnauthorized, "session expired")
				return
			}

			// Require user still exists and is platform_admin.
			user, err := s.store.GetUser(r.Context(), claims.Sub)
			if err != nil {
				var nf *licensestore.ErrNotFound
				if errors.As(err, &nf) {
					writeError(w, http.StatusUnauthorized, "user not found")
					return
				}
				log.Printf("auth: get user: %v", err)
				writeError(w, http.StatusInternalServerError, "internal server error")
				return
			}
			if user.Role != "platform_admin" {
				writeError(w, http.StatusUnauthorized, "insufficient role")
				return
			}

			ctx := context.WithValue(r.Context(), userCtxKey, AuthedUser{
				ID: user.ID, Email: user.Email, Name: user.Name,
				MustChangePassword: user.MustChangePassword,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// BlockUntilPasswordChanged rejects admin API calls when the authenticated
// user has must_change_password=true. The change-password endpoint is on
// /api/v1/auth/change-password (outside the admin route group), so it
// remains accessible — only admin operations are gated.
//
// Must be applied AFTER JWTAuth so the context already has an AuthedUser.
func (s *Server) BlockUntilPasswordChanged() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u, ok := UserFromContext(r.Context()); ok && u.MustChangePassword {
				writeError(w, http.StatusForbidden, "password change required before accessing admin API")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
