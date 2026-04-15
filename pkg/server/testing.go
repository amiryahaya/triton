package server

import (
	"context"

	"github.com/amiryahaya/triton/internal/auth"
)

// ContextWithClaimsForTesting injects UserClaims into a context using the
// same unexported key that JWTAuth uses, so ClaimsFromContext and the
// RequireRole middleware see them.
//
// This exists solely to allow out-of-package handler tests (e.g. package
// inventory_test) to exercise routes without spinning up the full JWT
// middleware stack. Production code must never call this — it grants
// caller-chosen identity unconditionally. The "ForTesting" suffix is a
// deliberate eyesore to keep that contract visible.
func ContextWithClaimsForTesting(ctx context.Context, c *auth.UserClaims) context.Context {
	return contextWithClaims(ctx, c)
}
