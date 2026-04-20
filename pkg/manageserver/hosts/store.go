package hosts

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// ErrNotFound is returned by Get/Update/Delete when no host matches
// the supplied ID. Handlers map this to HTTP 404.
var ErrNotFound = errors.New("hosts: not found")

// ErrConflict is returned by Create/BulkCreate when a hostname
// collision would violate the manage_hosts UNIQUE(hostname) constraint.
// Handlers map this to HTTP 409.
var ErrConflict = errors.New("hosts: conflict")

// ErrInvalidInput is returned when the store rejects malformed input
// before the row reaches the DB — e.g. a bad INET literal surfacing as
// SQLSTATE 22P02. Handlers map this to HTTP 400. The handler layer
// also validates before the call, so this is a belt-and-braces guard
// for bypasses.
var ErrInvalidInput = errors.New("hosts: invalid input")

// Store is the persistence boundary for the hosts bounded context.
// The ListByZone / ListByHostnames / CountByZone helpers exist to
// support Batch D's scanjobs.Enqueue target-expansion logic.
type Store interface {
	Create(ctx context.Context, h Host) (Host, error)
	Get(ctx context.Context, id uuid.UUID) (Host, error)
	List(ctx context.Context) ([]Host, error)
	Update(ctx context.Context, h Host) (Host, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Count(ctx context.Context) (int64, error)

	// ListByZone returns all hosts whose zone_id matches the given zone.
	ListByZone(ctx context.Context, zoneID uuid.UUID) ([]Host, error)

	// CountByZone returns the number of hosts in the given zone.
	CountByZone(ctx context.Context, zoneID uuid.UUID) (int64, error)

	// ListByHostnames returns hosts whose hostname is in names.
	// Used by the scanjobs orchestrator to resolve user-supplied
	// hostname lists into Host rows.
	ListByHostnames(ctx context.Context, names []string) ([]Host, error)

	// BulkCreate inserts a batch of hosts in a single transaction.
	// Any error (including a hostname conflict) rolls back the entire
	// batch — all-or-nothing semantics.
	BulkCreate(ctx context.Context, hosts []Host) ([]Host, error)
}
