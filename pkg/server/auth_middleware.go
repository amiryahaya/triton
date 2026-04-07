package server

import (
	"context"
	"crypto/ed25519"
	"net/http"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/pkg/store"
)

const (
	userContextKey   contextKey = "auth_user"
	claimsContextKey contextKey = "auth_claims"
)

// UserFromContext returns the authenticated user stored by JWTAuth
// middleware, or nil if the request was not authenticated.
func UserFromContext(ctx context.Context) *store.User {
	v, _ := ctx.Value(userContextKey).(*store.User)
	return v
}

// ClaimsFromContext returns the JWT claims stored by JWTAuth middleware,
// or nil if the request was not authenticated.
func ClaimsFromContext(ctx context.Context) *auth.UserClaims {
	v, _ := ctx.Value(claimsContextKey).(*auth.UserClaims)
	return v
}

// JWTAuth verifies the Bearer JWT, loads the user from the store, and
// attaches both to the request context. Subsequent middleware/handlers
// can call UserFromContext / ClaimsFromContext to access them.
//
// Re-fetching the user on every request (rather than trusting the JWT
// claims) is the H2 lesson from the license server review: deletions
// and role changes must take immediate effect even on in-flight tokens.
// Phase 2.1 will introduce a TTL-bounded cache to soften the per-request
// DB cost; for now we eat the lookup.
//
// Rejects with 401 for missing/invalid/expired tokens or unknown users.
// The handler chain only sees authenticated requests with a non-nil
// user in context.
func JWTAuth(pubKey ed25519.PublicKey, userStore store.UserStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				writeError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}
			claims, err := auth.VerifyJWT(token, pubKey)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}
			user, err := userStore.GetUser(r.Context(), claims.Sub)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}
			// Defense in depth: a JWT only validates if the user still
			// has an org-level role. Anything else (e.g., a stale token
			// from a deleted-then-recreated user with a different role)
			// is rejected.
			if user.Role != "org_admin" && user.Role != "org_user" {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}
			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			ctx = context.WithValue(ctx, userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireOrgAdmin enforces that the authenticated user has role=org_admin.
// Must be chained AFTER JWTAuth — if no user is in the context, the
// middleware returns 401 (treats the absence as unauthenticated rather
// than 500, since the missing-JWTAuth case is a misconfiguration).
//
// Returns 403 for authenticated users who lack org_admin role (e.g.,
// org_user trying to access user-management endpoints).
func RequireOrgAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if user.Role != "org_admin" {
			writeError(w, http.StatusForbidden, "org_admin role required")
			return
		}
		next.ServeHTTP(w, r.WithContext(r.Context()))
	})
}

// BlockUntilPasswordChanged is middleware that refuses every request
// from a user whose must_change_password flag is set, returning 403
// with a clear instruction to call /api/v1/auth/change-password.
//
// This is the Phase 1.5e gate: invited users (created via the org
// provisioning endpoint with must_change_password=true) can log in
// and obtain a JWT, but they cannot exercise any protected route
// until they've cleared the flag by calling change-password.
//
// Must be chained AFTER JWTAuth. The /auth/change-password endpoint
// must NOT have this middleware applied — that's the exit ramp.
//
// Returns 403 (forbidden — you are who you say you are, but you may
// not act yet) rather than 401 (unauthenticated). Clients can detect
// this state via the {"error": "..."} body or by inspecting the
// mustChangePassword field returned from /auth/login.
func BlockUntilPasswordChanged(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if user.MustChangePassword {
			writeError(w, http.StatusForbidden, "must change password before accessing this endpoint")
			return
		}
		next.ServeHTTP(w, r)
	})
}
