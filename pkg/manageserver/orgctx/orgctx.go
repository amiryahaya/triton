// Package orgctx plumbs the Manage instance_id through request context.
// Other packages (zones, hosts, scanjobs) consume it without importing
// back into pkg/manageserver (which would cycle).
package orgctx

import (
	"context"

	"github.com/google/uuid"
)

type ctxKey struct{}

// WithInstanceID returns a child context carrying the Manage instance_id.
func WithInstanceID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// InstanceIDFromContext extracts the instance_id previously stashed by
// WithInstanceID. Returns (uuid.Nil, false) when the context lacks it.
func InstanceIDFromContext(ctx context.Context) (uuid.UUID, bool) {
	v, ok := ctx.Value(ctxKey{}).(uuid.UUID)
	return v, ok
}
