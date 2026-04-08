package server

import (
	"context"
	"crypto/ed25519"
	"log"
	"net/http"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/store"
)

// AuthSource indicates how the tenant was identified for a request.
type AuthSource string

const (
	AuthSourceJWT          AuthSource = "jwt"           // human user logged in via password
	AuthSourceLicenseToken AuthSource = "license_token" // agent identified by its license
	AuthSourceGuard        AuthSource = "guard"         // single-tenant deployment fallback
)

// TenantContext is the canonical authenticated-request identity for the
// report server. It collapses the previously-separate JWT user context
// and license-token tenant context into a single struct that downstream
// handlers can read regardless of how the request was authenticated.
//
// Introduced in Phase 2.3 per the Phase 1.5 architecture review finding
// (Arch #10): "there are two separate context keys for org_id...
// Phase 2 routes that accept BOTH JWT users and license-token agents on
// the same URL need a unified resolver and single canonical context key."
type TenantContext struct {
	OrgID  string      // always set when TenantContext is present
	User   *store.User // nil for license-token requests (agents have no user row)
	Source AuthSource  // how this tenant was identified
}

const tenantContextKey contextKey = "tenant_context"

// TenantContextFromContext returns the TenantContext stashed by
// UnifiedAuth, or nil if the request was not authenticated (or if the
// middleware hasn't run — e.g., on health-check routes).
func TenantContextFromContext(ctx context.Context) *TenantContext {
	v, _ := ctx.Value(tenantContextKey).(*TenantContext)
	return v
}

// UnifiedAuth is the replacement for the old TenantScope + JWTAuth
// pair. It resolves tenant identity from any of:
//
//  1. Authorization: Bearer JWT (human users) — JWT signing key must be
//     configured for this path to be active.
//  2. X-Triton-License-Token (agents) — Ed25519 public key must be
//     configured for this path to be active.
//  3. Guard.OrgID (single-tenant fallback) — if a Guard is configured
//     with a fixed org ID, that's used when no other credentials are
//     present.
//
// When multiple credentials are present, JWT wins (precedence: JWT >
// license token > guard).
//
// Invalid credentials return 401 — this middleware does NOT fall through
// to other sources when a presented credential is malformed, because
// silently ignoring a bad token would hide misconfiguration.
//
// No credentials AND no guard fallback → pass through without setting
// a TenantContext. Handlers that require a tenant must chain
// RequireTenant after this middleware.
func UnifiedAuth(
	jwtPubKey ed25519.PublicKey,
	userStore store.UserStore,
	licensePubKey ed25519.PublicKey,
	guard *license.Guard,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Bearer JWT (human user)
			if jwtPubKey != nil && userStore != nil {
				if token := extractBearerToken(r); token != "" {
					claims, err := auth.VerifyJWT(token, jwtPubKey)
					if err != nil {
						writeError(w, http.StatusUnauthorized, "invalid or expired token")
						return
					}
					user, err := userStore.GetUser(r.Context(), claims.Sub)
					if err != nil {
						writeError(w, http.StatusUnauthorized, "invalid or expired token")
						return
					}
					// Defense in depth: role must be a legitimate org-level role.
					// Anything else (e.g., a stale token from a demoted user) is
					// rejected. Mirrors JWTAuth's role check.
					if user.Role != "org_admin" && user.Role != "org_user" {
						writeError(w, http.StatusUnauthorized, "invalid or expired token")
						return
					}
					tc := &TenantContext{
						OrgID:  user.OrgID,
						User:   user,
						Source: AuthSourceJWT,
					}
					ctx := context.WithValue(r.Context(), tenantContextKey, tc)
					// Also set the legacy userContextKey and tenantOrgIDKey so
					// existing middleware and handlers that read them continue
					// to work during the migration window. Phase 2.4 will
					// remove these compatibility writes once all consumers are
					// migrated to TenantContextFromContext.
					ctx = context.WithValue(ctx, userContextKey, user)
					ctx = context.WithValue(ctx, tenantOrgIDKey, user.OrgID)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// 2. License token (agent)
			if licensePubKey != nil {
				if token := r.Header.Get(licenseTokenHeader); token != "" {
					lic, err := license.Parse(token, licensePubKey)
					if err != nil {
						log.Printf("unified auth: invalid license token from %s: %v", r.RemoteAddr, err)
						writeError(w, http.StatusUnauthorized, "invalid license token")
						return
					}
					if lic.OrgID != "" {
						tc := &TenantContext{
							OrgID:  lic.OrgID,
							Source: AuthSourceLicenseToken,
						}
						ctx := context.WithValue(r.Context(), tenantContextKey, tc)
						ctx = context.WithValue(ctx, tenantOrgIDKey, lic.OrgID)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
			}

			// 3. Guard fallback (single-tenant deployment)
			if guard != nil && guard.OrgID() != "" {
				tc := &TenantContext{
					OrgID:  guard.OrgID(),
					Source: AuthSourceGuard,
				}
				ctx := context.WithValue(r.Context(), tenantContextKey, tc)
				ctx = context.WithValue(ctx, tenantOrgIDKey, guard.OrgID())
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// No credentials, no guard — pass through. RequireTenant
			// will reject later if the route needs a tenant.
			next.ServeHTTP(w, r)
		})
	}
}

// RequireTenant rejects any request that reached the handler without a
// populated TenantContext. Must be chained AFTER UnifiedAuth.
//
// Use on routes that need tenant scoping (scan read, diff, trend, etc.
// — i.e., almost everything). Health checks and public endpoints should
// be OUTSIDE the UnifiedAuth/RequireTenant chain.
func RequireTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc := TenantContextFromContext(r.Context())
		if tc == nil || tc.OrgID == "" {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
