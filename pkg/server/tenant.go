package server

import (
	"context"
)

type contextKey string

const tenantOrgIDKey contextKey = "tenant_org_id"

const licenseTokenHeader = "X-Triton-License-Token"

// TenantFromContext returns the org ID set by the UnifiedAuth middleware.
// Prefers the new tenantContextKey. Falls back to the legacy
// tenantOrgIDKey for handlers that may still rely on the old key
// (UnifiedAuth writes both during the Phase 2 → Phase 4 migration window;
// Phase 4 will remove the legacy compat write and this fallback).
//
// Returns empty string if no tenant is set — typically because the
// route bypasses UnifiedAuth (e.g., /api/v1/health) or the request is
// running in single-tenant mode without a Guard.
func TenantFromContext(ctx context.Context) string {
	if tc, _ := ctx.Value(tenantContextKey).(*TenantContext); tc != nil {
		return tc.OrgID
	}
	v, _ := ctx.Value(tenantOrgIDKey).(string)
	return v
}
