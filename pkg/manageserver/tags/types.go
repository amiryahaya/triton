// Package tags provides CRUD primitives for the manage_tags table.
// A tag is a coloured label that can be assigned to one or more hosts,
// enabling flexible many-to-many grouping for the Manage Server's
// scanner orchestrator and dashboard filters.
package tags

import (
	"time"

	"github.com/google/uuid"
)

// Tag is a coloured label that can be assigned to one or more hosts.
type Tag struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Color     string    `json:"color"`
	HostCount int       `json:"host_count,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
