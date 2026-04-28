package agents

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned by Get/GetByCertSerial/Revoke when no agent
// matches. Handlers map this to HTTP 404.
var ErrNotFound = errors.New("agents: not found")

// ErrConflict is returned by Create when the cert serial collides. This
// should be impossible under normal operation (serials are 128-bit
// random) but we surface it cleanly rather than letting the pg error
// leak through.
var ErrConflict = errors.New("agents: conflict")

// Store is the persistence boundary for the agents bounded context.
// All methods operate within a single Manage Server instance — there
// is no per-tenant scoping here because Manage is single-tenant per
// install.
type Store interface {
	// Create inserts a new agent with status='pending'. Returns
	// ErrConflict on serial collision.
	Create(ctx context.Context, a Agent) (Agent, error)

	// Get fetches an agent by id.
	Get(ctx context.Context, id uuid.UUID) (Agent, error)

	// GetByCertSerial looks up an agent by its current cert serial.
	// Used by the gateway handlers to resolve the CN back to a row.
	GetByCertSerial(ctx context.Context, serial string) (Agent, error)

	// List returns every agent, ordered by name.
	List(ctx context.Context) ([]Agent, error)

	// MarkActive flips status→active and stamps last_seen_at=NOW.
	// Idempotent: safe to call on every phone-home.
	MarkActive(ctx context.Context, id uuid.UUID) error

	// UpdateCert replaces cert_serial + cert_expires_at. Used by the
	// rotate-cert gateway handler when an agent mints a fresh leaf.
	UpdateCert(ctx context.Context, id uuid.UUID, newSerial string, expiresAt time.Time) error

	// Revoke flips status→revoked. The caller is responsible for
	// writing the matching revocation row via ca.Store.Revoke — this
	// method only mutates the agent row.
	Revoke(ctx context.Context, id uuid.UUID) error

	// Count returns the total number of agent rows (any status). Used
	// by Batch H's licence-cap check.
	Count(ctx context.Context) (int64, error)

	// SetCommand stores a pending scan command for the agent. Overwrites
	// any existing pending command. Pass nil to clear without popping.
	SetCommand(ctx context.Context, id uuid.UUID, cmd *AgentCommand) error

	// PopCommand atomically reads and clears the pending command for the
	// agent. Returns (nil, nil) if no command is pending. Returns
	// ErrNotFound if the agent row does not exist.
	PopCommand(ctx context.Context, id uuid.UUID) (*AgentCommand, error)
}
