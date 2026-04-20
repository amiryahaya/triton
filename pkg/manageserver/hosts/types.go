// Package hosts provides CRUD primitives for the manage_hosts table.
// A host is a scan target tracked by the Manage Server orchestrator;
// it may optionally be a member of a zone (hosts.zone_id) so the
// orchestrator can expand "scan this zone" into a set of hosts.
package hosts

import (
	"time"

	"github.com/google/uuid"
)

// Host is a single scan target. The IP column is nullable INET in
// Postgres; we model that on the Go side as `IP string` where the
// empty string means NULL (translation happens at the store boundary).
// ZoneID is a nullable FK to manage_zones.
type Host struct {
	ID         uuid.UUID  `json:"id"`
	Hostname   string     `json:"hostname"`
	IP         string     `json:"ip,omitempty"`
	ZoneID     *uuid.UUID `json:"zone_id,omitempty"`
	OS         string     `json:"os"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}
