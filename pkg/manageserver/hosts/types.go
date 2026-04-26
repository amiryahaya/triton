package hosts

import (
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/tags"
)

// Host is a single scan target. Hostname and OS are optional.
// IP is the required unique identifier; modelled as string where
// the wire form matches PostgreSQL's host(ip)::text output.
// Tags is populated on reads (List/Get); not stored on the host row.
type Host struct {
	ID         uuid.UUID  `json:"id"`
	Hostname   string     `json:"hostname,omitempty"`
	IP         string     `json:"ip"`
	Tags       []tags.Tag `json:"tags"`
	OS         string     `json:"os,omitempty"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}
