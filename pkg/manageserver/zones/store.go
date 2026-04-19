package zones

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// ErrNotFound is returned by Get/Update/Delete when no zone matches
// the supplied ID. Handlers map this to HTTP 404.
var ErrNotFound = errors.New("zones: not found")

// Store is the persistence boundary for the zones bounded context.
// All methods operate within a single Manage Server instance — there
// is no per-tenant scoping here because Manage is single-tenant per
// install.
type Store interface {
	Create(ctx context.Context, z Zone) (Zone, error)
	Get(ctx context.Context, id uuid.UUID) (Zone, error)
	List(ctx context.Context) ([]Zone, error)
	Update(ctx context.Context, z Zone) (Zone, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Count(ctx context.Context) (int64, error)
}
