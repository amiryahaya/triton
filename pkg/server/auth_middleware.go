package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"

	"time"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/auth/sessioncache"
	"github.com/amiryahaya/triton/pkg/store"
)

// jwtAuthStore is the narrow interface JWTAuth needs: user lookup by
// ID plus session lookup by token hash. Accepting an interface (not
// the full store.Store) keeps the middleware testable with a minimal
// fake and documents the actual dependency surface.
type jwtAuthStore interface {
	GetUser(ctx context.Context, id string) (*store.User, error)
	GetSessionByHash(ctx context.Context, tokenHash string) (*store.Session, error)
}

// RequestRateLimitByUser is the JWTAuth-layer counterpart to
// RequestRateLimit: routes protected by JWTAuth (users, audit) don't
// set the tenant context key that UnifiedAuth writes, so we key
// the limiter by the authenticated user's OrgID directly. Same
// limiter instance as RequestRateLimit so one org's budget is
// shared across both middleware surfaces.
//
// The "ip:"-prefixed fallback key (used when no user context is
// present) assumes no legitimate org_id ever starts with "ip:".
// Since org IDs are UUIDv7 they always begin with a hex digit, so
// the collision space is empty in practice. Don't change org_id
// to allow arbitrary strings without revisiting this — Sprint 3 D6.
func RequestRateLimitByUser(limiter *auth.RequestRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := ""
			if u := UserFromContext(r.Context()); u != nil {
				key = u.OrgID
			}
			if key == "" {
				key = "ip:" + r.RemoteAddr
			}
			allowed, retryAfter := limiter.Allow(key)
			if !allowed {
				seconds := int(retryAfter.Seconds())
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(seconds))
				writeError(w, http.StatusTooManyRequests, "request rate limit exceeded; try again later")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequestRateLimit returns middleware that enforces a per-tenant
// request rate limit on non-login data endpoints. Keys requests by
// the tenant context (set by UnifiedAuth), falling back to a
// fingerprint of RemoteAddr when there's no tenant yet. Requests
// exceeding the budget return 429 with a Retry-After header.
//
// Phase 5 Sprint 3 B3 — prevents an authenticated-but-malicious
// org user from hammering /scans and exhausting the DB connection
// pool. The default 600/min budget is generous enough for a busy
// agent fleet while still catching accidental infinite loops.
func RequestRateLimit(limiter *auth.RequestRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := TenantFromContext(r.Context())
			if key == "" {
				// Fall back to the client IP for unauthenticated
				// requests. This is the minority path — POST /scans
				// in single-tenant mode — but we still want DoS
				// protection there.
				key = "ip:" + r.RemoteAddr
			}
			allowed, retryAfter := limiter.Allow(key)
			if !allowed {
				seconds := int(retryAfter.Seconds())
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(seconds))
				writeError(w, http.StatusTooManyRequests, "request rate limit exceeded; try again later")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

const (
	userContextKey   contextKey = "auth_user"
	claimsContextKey contextKey = "auth_claims"
)

// Role identifiers stored in the users.role column and JWT claims.
// Mapping to onboarding design spec §5:
//
//	RoleOwner    (org_admin)   — full CRUD on inventory, credentials, scans, users
//	RoleEngineer (org_user)    — CRUD on inventory, credentials, scans (no user mgmt)
//	RoleOfficer  (org_officer) — view-only + trigger scans on existing groups
//
// Introduced by migration Version 15. Existing call sites in this
// package still compare against the string literals directly; new
// code should prefer these constants.
const (
	RoleOwner    = "org_admin"
	RoleEngineer = "org_user"
	RoleOfficer  = "org_officer"
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

// contextWithClaims is the internal counterpart to ClaimsFromContext,
// used by tests to inject claims without running the full JWTAuth
// middleware. The context key is unexported so this helper keeps it
// that way; test files in package server call it directly.
func contextWithClaims(ctx context.Context, c *auth.UserClaims) context.Context {
	return context.WithValue(ctx, claimsContextKey, c)
}

// JWTAuth verifies the Bearer JWT, looks up the associated session
// row, loads the user from the store, and attaches both to the
// request context. Subsequent middleware/handlers can call
// UserFromContext / ClaimsFromContext to access them.
//
// Session verification (Phase 5 Sprint 3 B1): the middleware
// computes SHA-256 of the raw token and looks it up in the
// sessions table. If the row is absent (logged out, revoked,
// deleted by admin) or expired, the request is rejected as 401
// regardless of the JWT's signature validity. This closes the
// "logout is a lie" gap where a logged-out JWT remained usable
// until natural expiry.
//
// Re-fetching the user on every request is the H2 lesson from the
// license server review: deletions and role changes must take
// immediate effect even on in-flight tokens. The session check
// above is cheaper than a user lookup, so we do it first.
//
// Rejects with 401 for missing/invalid/expired tokens, revoked
// sessions, or unknown users. The handler chain only sees
// authenticated requests with a non-nil user in context.
//
// Arch #4: a non-nil cache short-circuits both PG calls on the
// hot path. Cache is keyed by sha256(raw token); a hit rebuilds a
// *store.User from the cached fields and skips GetSessionByHash +
// GetUser entirely. Revocation via logout/refresh/change-password
// explicitly deletes the cache entry; revocation via other paths
// (admin DeleteSession, direct SQL) is eventually-consistent
// within the cache TTL. Pass nil to disable caching (preserves
// pre-Arch#4 behavior exactly).
func JWTAuth(pubKey ed25519.PublicKey, jwtStore jwtAuthStore, cache *sessioncache.SessionCache) func(http.Handler) http.Handler {
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
			h := sha256.Sum256([]byte(token))
			tokenHash := hex.EncodeToString(h[:])

			// Cache fast path. On hit we have everything the
			// handler chain needs; on miss we fall through to
			// the DB lookups below and Put the result.
			if entry, ok := cache.Get(tokenHash); ok {
				user := &store.User{
					ID:                 entry.UserID,
					OrgID:              entry.OrgID,
					Role:               entry.Role,
					MustChangePassword: entry.MustChangePassword,
				}
				ctx := context.WithValue(r.Context(), claimsContextKey, claims)
				ctx = context.WithValue(ctx, userContextKey, user)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// B1 session revocation check — compute the same SHA-256
			// hash that handleLogin / handleRefresh wrote into the
			// sessions table and refuse the request if the row is
			// missing or expired. GetSessionByHash already filters
			// expires_at > now at the SQL level.
			//
			// N7 fix: a transient DB error (connection timeout,
			// pool exhausted) must NOT be reported as 401. A 401
			// tells the client "your token is invalid — log in
			// again", which causes spurious logouts during DB
			// hiccups. Return 503 for non-NotFound errors so the
			// client knows to retry with the same token after a
			// backoff.
			if _, err := jwtStore.GetSessionByHash(r.Context(), tokenHash); err != nil {
				var nf *store.ErrNotFound
				if errors.As(err, &nf) {
					writeError(w, http.StatusUnauthorized, "session revoked or expired")
					return
				}
				writeError(w, http.StatusServiceUnavailable, "authentication backend unavailable; retry")
				return
			}
			user, err := jwtStore.GetUser(r.Context(), claims.Sub)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}
			// Defense in depth: a JWT only validates if the user still
			// has a known org-level role. Anything else (e.g., a stale
			// token from a deleted-then-recreated user with an unknown
			// role) is rejected. Uses roleRank so adding a new role in
			// rbac.go automatically admits it here too — previously
			// hardcoding "org_admin" || "org_user" blocked org_officer
			// with a 401 before RequireRole ever ran.
			if roleRank[user.Role] == 0 {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}
			// Populate cache after full validation succeeded. We
			// stamp the entry's JWTExpiry from the claims so the
			// cache never outlives the token itself.
			cache.Put(tokenHash, sessioncache.Entry{
				UserID:             user.ID,
				OrgID:              user.OrgID,
				Role:               user.Role,
				MustChangePassword: user.MustChangePassword,
				JWTExpiry:          time.Unix(claims.Exp, 0),
			})
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
		next.ServeHTTP(w, r)
	})
}

// RequireAnyOrgRole enforces that the authenticated user has either
// role=org_admin OR role=org_user. Both can read scan data, run policy
// evaluations, and view their org's dashboard — they only diverge on
// administrative actions like user CRUD.
//
// Phase 2 will use this for routes like GET /api/v1/scans where any
// authenticated org user should have access. Today no production routes
// use it, but it's exercised by tests as the missing piece called out
// in the architecture review (Arch #5 partial).
//
// Must be chained AFTER JWTAuth.
func RequireAnyOrgRole(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if roleRank[user.Role] == 0 {
			writeError(w, http.StatusForbidden, "org role required")
			return
		}
		next.ServeHTTP(w, r)
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
