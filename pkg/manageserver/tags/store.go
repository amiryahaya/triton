package tags

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// ErrNotFound is returned by Get/Update/Delete when no tag matches
// the supplied ID. Handlers map this to HTTP 404.
var ErrNotFound = errors.New("tags: not found")

// ErrConflict is returned by Create/Update when a name collision would
// violate the manage_tags UNIQUE(name) constraint. Handlers map this
// to HTTP 409.
var ErrConflict = errors.New("tags: conflict")

// Store is the persistence boundary for the tags bounded context.
// All methods operate within a single Manage Server instance — there
// is no per-tenant scoping here because Manage is single-tenant per
// install.
type Store interface {
	Create(ctx context.Context, t Tag) (Tag, error)
	Get(ctx context.Context, id uuid.UUID) (Tag, error)
	List(ctx context.Context) ([]Tag, error)
	Update(ctx context.Context, t Tag) (Tag, error)
	Delete(ctx context.Context, id uuid.UUID) error
}
