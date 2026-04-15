package engine

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// ErrCANotFound is returned by Store.GetCA when no CA row exists for
// the given org. Handlers use errors.Is to distinguish "bootstrap
// required" from a real database error.
var ErrCANotFound = errors.New("engine CA not found")

// ErrEngineNotFound is returned by lookup methods when the engine row
// does not exist (or exists but belongs to a different org).
var ErrEngineNotFound = errors.New("engine not found")

// Store is the persistence boundary for the engine bounded context.
// All read methods are org-scoped; the only intentional exception is
// GetEngineByFingerprint, which is called from the mTLS middleware
// before any org context is available — the cert_fingerprint UNIQUE
// constraint (migration v18) guarantees the lookup is unambiguous.
type Store interface {
	// UpsertCA writes (or replaces) the per-org engine CA. Idempotent
	// at the (org_id) primary key — calling twice with different
	// CAs replaces the existing one (use with care; existing engine
	// certs become un-verifiable).
	UpsertCA(ctx context.Context, orgID uuid.UUID, ca *CA) error

	// GetCA loads the org's engine CA. Returns an error wrapping
	// pgx.ErrNoRows if no CA has been generated for this org yet.
	GetCA(ctx context.Context, orgID uuid.UUID) (*CA, error)

	// CreateEngine inserts a new engines row at bundle-issuance time.
	CreateEngine(ctx context.Context, e Engine) (Engine, error)

	// GetEngine fetches an engine by org+id. Cross-tenant queries
	// return a not-found error.
	GetEngine(ctx context.Context, orgID, id uuid.UUID) (Engine, error)

	// GetEngineByFingerprint resolves an engine by client-cert
	// fingerprint with no org scope. Used by the mTLS middleware.
	// Callers MUST check the returned engine's Status before
	// trusting it (revoked engines still resolve here).
	GetEngineByFingerprint(ctx context.Context, fingerprint string) (Engine, error)

	// ListEngines returns all engines in the org ordered by label.
	ListEngines(ctx context.Context, orgID uuid.UUID) ([]Engine, error)

	// RecordFirstSeen attempts to claim the first-seen timestamp for
	// an engine. Returns (true, nil) on the first successful claim
	// and (false, nil) on every subsequent call (idempotent replay).
	// Callers use the bool to distinguish "first ever heartbeat"
	// (which may trigger downstream side effects) from a routine
	// resumed-after-restart heartbeat.
	//
	// Adapted from plan: plan had no return value; the bool is needed
	// so handlers can branch on the single-use claim outcome without
	// a separate read-modify-write.
	RecordFirstSeen(ctx context.Context, id uuid.UUID, publicIP string) (bool, error)

	// RecordPoll updates last_poll_at = NOW() for the engine. Cheap;
	// called on every heartbeat after RecordFirstSeen.
	RecordPoll(ctx context.Context, id uuid.UUID) error

	// SetStatus transitions an engine to a new status (enrolled,
	// online, offline, revoked). Use Revoke for the revoked case so
	// revoked_at is set atomically.
	SetStatus(ctx context.Context, id uuid.UUID, status string) error

	// Revoke marks an engine revoked and stamps revoked_at = NOW().
	Revoke(ctx context.Context, orgID, id uuid.UUID) error
}
