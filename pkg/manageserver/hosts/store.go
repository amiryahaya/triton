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
type Store interface {
	Create(ctx context.Context, h Host) (Host, error)
	Get(ctx context.Context, id uuid.UUID) (Host, error)
	List(ctx context.Context) ([]Host, error)
	Update(ctx context.Context, h Host) (Host, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Count(ctx context.Context) (int64, error)

	// SetTags replaces the full tag set for a host (idempotent).
	SetTags(ctx context.Context, hostID uuid.UUID, tagIDs []uuid.UUID) error

	// ResolveTagNames returns tag IDs for the given names, creating
	// tags with defaultColor for names that do not yet exist.
	ResolveTagNames(ctx context.Context, names []string, defaultColor string) ([]uuid.UUID, error)

	// ListByTags returns hosts that have ANY of the given tags (OR semantics).
	ListByTags(ctx context.Context, tagIDs []uuid.UUID) ([]Host, error)

	// CountByTag returns the number of hosts with the given tag.
	CountByTag(ctx context.Context, tagID uuid.UUID) (int64, error)

	// ListByHostnames returns hosts whose hostname is in names.
	ListByHostnames(ctx context.Context, names []string) ([]Host, error)

	// BulkCreate inserts a batch of hosts in a single transaction.
	BulkCreate(ctx context.Context, hosts []Host) ([]Host, error)
}
