// Package zones provides CRUD primitives for the manage_zones table.
// A zone is an administrative grouping of hosts used by the Manage
// Server's scanner orchestrator to expand "scan this zone" into a set
// of target hosts. Batch B ships the CRUD layer only; membership is
// read via hosts.zone_id — the zone_memberships table is reserved for
// a future many-to-many model.
package zones

import (
	"time"

	"github.com/google/uuid"
)

// Zone is an administrative grouping of hosts within a single Manage
// Server instance. Names are globally unique (UNIQUE constraint on the
// manage_zones table).
type Zone struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
