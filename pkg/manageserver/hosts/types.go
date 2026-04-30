package hosts

import (
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/tags"
)

// ConnectionType values reported on Host.
const (
	ConnectionTypeSSH   = "ssh"
	ConnectionTypeAgent = "agent"
)

// Host is a single scan target. OS is optional; Hostname and IP are both required.
// IP is the unique identifier; modelled as string where the wire form matches
// PostgreSQL's host(ip)::text output.
// Tags is populated on reads (List/Get); not stored on the host row.
// ConnectionType is derived at query time ("agent" if an enrolled agent exists for
// this host, "ssh" if credentials are configured, "" otherwise).
type Host struct {
	ID             uuid.UUID  `json:"id"`
	Hostname       string     `json:"hostname"`
	IP             string     `json:"ip"`
	ConnectionType string     `json:"connection_type,omitempty"`
	Tags           []tags.Tag `json:"tags"`
	OS             string     `json:"os,omitempty"`
	LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	CredentialsRef *uuid.UUID `json:"credentials_ref,omitempty"`
	SSHPort        int        `json:"ssh_port"`
}
