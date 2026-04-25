package hosts

import (
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/tags"
)

// Host is a single scan target. IP is nullable INET in Postgres;
// modelled as string where empty = NULL. Tags is populated on reads
// (List/Get); it is not stored directly on the host row.
type Host struct {
	ID         uuid.UUID  `json:"id"`
	Hostname   string     `json:"hostname"`
	IP         string     `json:"ip,omitempty"`
	Tags       []tags.Tag `json:"tags"`
	OS         string     `json:"os"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}
