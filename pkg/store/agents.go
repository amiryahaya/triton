package store

import (
	"context"
	"encoding/json"
	"time"
)

// AgentRecord is the per-machine control row on the Report Server.
// See docs/plans/2026-04-19-agent-control-channel-design.md.
type AgentRecord struct {
	TenantID    string    `json:"tenantID"`
	MachineID   string    `json:"machineID"` // sha3-256 hex from license.MachineFingerprint()
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	FirstSeenAt time.Time `json:"firstSeenAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
	PausedUntil time.Time `json:"pausedUntil,omitempty"` // zero = not paused
}

// AgentCommandType enumerates the transient commands admin can issue.
// Persistent state (pause) uses a separate field on AgentRecord.
type AgentCommandType string

const (
	AgentCommandCancel   AgentCommandType = "cancel"
	AgentCommandForceRun AgentCommandType = "force_run"
)

// AgentCommand is a single queued or historical command for an agent.
// DispatchedAt is nil while the command is pending; set when the poll
// handler returns it on the wire (inside the same transaction as the
// claim). ResultStatus is nil while still pending or dispatched-but-
// unacknowledged; set by the agent's result POST.
type AgentCommand struct {
	ID           string           `json:"id"`
	TenantID     string           `json:"tenantID"`
	MachineID    string           `json:"machineID"`
	Type         AgentCommandType `json:"type"`
	Args         json.RawMessage  `json:"args"`
	IssuedBy     string           `json:"issuedBy"`
	IssuedAt     time.Time        `json:"issuedAt"`
	ExpiresAt    time.Time        `json:"expiresAt"`
	DispatchedAt *time.Time       `json:"dispatchedAt,omitempty"`
	ResultStatus *string          `json:"resultStatus,omitempty"` // executed | rejected | expired
	ResultMeta   json.RawMessage  `json:"resultMeta,omitempty"`
	ResultedAt   *time.Time       `json:"resultedAt,omitempty"`
}

// AgentStore is the persistence surface for the remote control channel.
type AgentStore interface {
	// UpsertAgent creates the row on first-seen or updates
	// hostname/os/arch + last_seen_at on subsequent polls. paused_until
	// is never written here — admin endpoints own that field.
	UpsertAgent(ctx context.Context, a *AgentRecord) error

	// GetAgent returns the row for (tenantID, machineID) or ErrNotFound
	// when the agent has never polled.
	GetAgent(ctx context.Context, tenantID, machineID string) (*AgentRecord, error)

	// ListAgentsByTenant returns all agents for a tenant, newest-last-seen
	// first. limit <= 0 means no limit.
	ListAgentsByTenant(ctx context.Context, tenantID string, limit int) ([]AgentRecord, error)

	// SetAgentPausedUntil writes paused_until. The 90-day cap is enforced
	// at the admin-API layer; the store only enforces the existence of
	// the (tenantID, machineID) row. Returns ErrNotFound for unknown
	// agents.
	SetAgentPausedUntil(ctx context.Context, tenantID, machineID string, until time.Time) error

	// ClearAgentPausedUntil sets paused_until to NULL. ErrNotFound for
	// unknown agents.
	ClearAgentPausedUntil(ctx context.Context, tenantID, machineID string) error

	// EnqueueAgentCommand inserts a pending command. cmd.ID must be
	// pre-populated by the caller (project generates UUIDs in Go, not
	// in Postgres). Returns the created record with server-assigned
	// issued_at.
	EnqueueAgentCommand(ctx context.Context, cmd *AgentCommand) (*AgentCommand, error)

	// ClaimPendingCommandsForAgent atomically marks all pending,
	// unexpired commands for (tenantID, machineID) as dispatched
	// (dispatched_at = NOW()) and returns them. Commands already
	// dispatched are not re-claimed; expired-but-not-yet-dispatched
	// commands are skipped and NOT returned.
	ClaimPendingCommandsForAgent(ctx context.Context, tenantID, machineID string) ([]AgentCommand, error)

	// SetAgentCommandResult records the agent-reported outcome. Returns
	// ErrNotFound when the command ID does not exist for this
	// (tenantID, machineID) pair — prevents cross-agent result
	// injection.
	SetAgentCommandResult(ctx context.Context, tenantID, machineID, commandID, status string, meta json.RawMessage) error

	// ListAgentCommands returns up to `limit` most-recent commands for
	// (tenantID, machineID), newest-first. Used by admin detail view.
	// limit <= 0 defaults to 50.
	ListAgentCommands(ctx context.Context, tenantID, machineID string, limit int) ([]AgentCommand, error)

	// ExpireStaleAgentCommands marks dispatched-but-unacked commands
	// whose expires_at < now as result_status = 'expired'. Returns the
	// number updated. Intended for a background sweep; no-op if nothing
	// matches.
	ExpireStaleAgentCommands(ctx context.Context) (int, error)
}
