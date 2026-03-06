package server

import (
	"context"
	"crypto/ed25519"
	"log"
	"net/http"

	"github.com/amiryahaya/triton/internal/license"
)

type contextKey string

const tenantOrgIDKey contextKey = "tenant_org_id"

const licenseTokenHeader = "X-Triton-License-Token"

// TenantFromContext returns the org ID set by the TenantScope middleware.
// Returns empty string if no tenant is set (e.g. standalone mode).
func TenantFromContext(ctx context.Context) string {
	v, _ := ctx.Value(tenantOrgIDKey).(string)
	return v
}

// TenantScope is middleware that extracts the org_id for tenant-scoped queries.
//
// Resolution order:
//  1. Per-request: X-Triton-License-Token header → verify Ed25519 signature → extract oid
//  2. Fallback: server's own Guard org_id (single-tenant deployment)
//
// If a token is present but invalid, the request is rejected (401).
// If neither yields an org_id, requests pass through without tenant scoping
// (backward compatible with standalone mode).
func TenantScope(guard *license.Guard, pubKeyOverride ed25519.PublicKey) func(http.Handler) http.Handler {
	pubKey := pubKeyOverride
	if pubKey == nil {
		pubKey = license.LoadPublicKeyBytes()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try per-request token first (multi-tenant mode).
			if token := r.Header.Get(licenseTokenHeader); token != "" && pubKey != nil {
				lic, err := license.Parse(token, pubKey)
				if err != nil {
					log.Printf("tenant: invalid license token from %s: %v", r.RemoteAddr, err)
					writeError(w, http.StatusUnauthorized, "invalid license token")
					return
				}
				if lic.OrgID != "" {
					ctx := context.WithValue(r.Context(), tenantOrgIDKey, lic.OrgID)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			// Fallback to server's own guard (single-tenant mode).
			if guard != nil && guard.OrgID() != "" {
				ctx := context.WithValue(r.Context(), tenantOrgIDKey, guard.OrgID())
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
