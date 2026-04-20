package manage_enrol

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// ErrNotFound is returned by GetByCertSerial when no row matches. Callers
// (principally engine.MTLSMiddleware) use errors.Is to map to 401.
var ErrNotFound = errors.New("manage_enrol: not found")

// Store is the persistence boundary for enrolled Manage instances. The
// interface is intentionally narrow — enrolment is a one-way write from
// the admin Enrol handler, and reads come exclusively from the mTLS
// middleware's per-request lookup.
type Store interface {
	// Create inserts a new manage_instances row. Returns an error if a row
	// with the same ID or cert_serial already exists.
	Create(ctx context.Context, mi ManageInstance) error

	// GetByCertSerial resolves a row by the signed leaf's serial number.
	// Returns ErrNotFound when no row matches — not a generic DB error —
	// so the middleware can discriminate "never enrolled" from "DB down".
	GetByCertSerial(ctx context.Context, serial string) (ManageInstance, error)

	// Revoke flips status to 'revoked' for the row with the given ID.
	// Idempotent: revoking an already-revoked row is a no-op with no error.
	Revoke(ctx context.Context, id uuid.UUID) error

	// List returns every row ordered by enrolled_at ascending. Exposed for
	// admin tooling; the hot path uses GetByCertSerial.
	List(ctx context.Context) ([]ManageInstance, error)
}
