// Package agents is the agent-enrolment + gateway-protocol bounded
// context for the Manage Server. It owns the manage_agents table (one
// row per enrolled agent), the admin enrol/revoke endpoints, and the
// :8443 gateway handlers an agent dials with its client cert.
package agents

import (
	"time"

	"github.com/google/uuid"
)

// AgentStatus is the lifecycle state of a manage_agents row.
//
//   - pending: bundle issued but agent has not yet phoned home.
//   - active:  agent has phoned home at least once (MarkActive flips it).
//   - revoked: admin revoked; the cert serial is in the revocations table
//     and gateway mTLS will refuse the cert.
type AgentStatus string

const (
	StatusPending AgentStatus = "pending"
	StatusActive  AgentStatus = "active"
	StatusRevoked AgentStatus = "revoked"
)

// AgentCommand is the pending scan command stored on an agent row.
// Set by an admin; atomically popped by the agent on its next poll.
type AgentCommand struct {
	ScanProfile string `json:"scan_profile"`
	JobID       string `json:"job_id,omitempty"`
}

// Agent is a row in manage_agents.
type Agent struct {
	ID             uuid.UUID     `json:"id"`
	Name           string        `json:"name"`
	CertSerial     string        `json:"cert_serial"`
	CertExpiresAt  time.Time     `json:"cert_expires_at"`
	Status         AgentStatus   `json:"status"`
	LastSeenAt     *time.Time    `json:"last_seen_at,omitempty"`
	PendingCommand *AgentCommand `json:"pending_command,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}
