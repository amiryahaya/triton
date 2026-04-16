// Package agentpush implements the portal-side agent push job queue:
// operators queue push-jobs, engines claim and execute them, and on
// success the agent is registered in the fleet_agents table with its
// per-host cert fingerprint. Host mode flips from agentless to agent.
package agentpush

import (
	"time"

	"github.com/google/uuid"
)

// JobStatus is the lifecycle state of an agent push job. Values mirror
// the CHECK constraint on agent_push_jobs.status (migration v23).
type JobStatus string

const (
	StatusQueued    JobStatus = "queued"
	StatusClaimed   JobStatus = "claimed"
	StatusRunning   JobStatus = "running"
	StatusCompleted JobStatus = "completed"
	StatusFailed    JobStatus = "failed"
	StatusCancelled JobStatus = "cancelled"
)

// PushJob is the persisted agent-push-job row.
type PushJob struct {
	ID                  uuid.UUID   `json:"id"`
	OrgID               uuid.UUID   `json:"org_id"`
	EngineID            uuid.UUID   `json:"engine_id"`
	GroupID             *uuid.UUID  `json:"group_id,omitempty"`
	HostIDs             []uuid.UUID `json:"host_ids"`
	CredentialProfileID uuid.UUID   `json:"credential_profile_id"`
	Status              JobStatus   `json:"status"`
	Error               string      `json:"error,omitempty"`
	RequestedBy         uuid.UUID   `json:"requested_by"`
	RequestedAt         time.Time   `json:"requested_at"`
	ClaimedAt           *time.Time  `json:"claimed_at,omitempty"`
	CompletedAt         *time.Time  `json:"completed_at,omitempty"`
	ProgressTotal       int         `json:"progress_total"`
	ProgressDone        int         `json:"progress_done"`
	ProgressFailed      int         `json:"progress_failed"`
}

// PushJobPayload is the wire shape returned by /api/v1/engine/agent-push/poll.
// Contains the resolved host targets + credential metadata the engine
// needs to execute the push.
type PushJobPayload struct {
	ID                  uuid.UUID    `json:"id"`
	CredentialSecretRef uuid.UUID    `json:"credential_secret_ref"`
	CredentialAuthType  string       `json:"credential_auth_type"`
	Hosts               []HostTarget `json:"hosts"`
}

// HostTarget is a single host to push the agent to.
type HostTarget struct {
	ID       uuid.UUID `json:"id"`
	Address  string    `json:"address"`
	Port     int       `json:"port"`
	Hostname string    `json:"hostname,omitempty"`
	OS       string    `json:"os,omitempty"`
}

// ProgressUpdate is the per-host progress event the engine streams
// back via the progress endpoint.
type ProgressUpdate struct {
	HostID      uuid.UUID `json:"host_id"`
	Status      string    `json:"status"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// FleetAgent is a persisted agent registration row.
type FleetAgent struct {
	ID              uuid.UUID  `json:"id"`
	OrgID           uuid.UUID  `json:"org_id"`
	HostID          uuid.UUID  `json:"host_id"`
	EngineID        uuid.UUID  `json:"engine_id"`
	CertFingerprint string     `json:"cert_fingerprint"`
	InstalledAt     time.Time  `json:"installed_at"`
	LastHeartbeat   *time.Time `json:"last_heartbeat,omitempty"`
	Version         string     `json:"version,omitempty"`
	Status          string     `json:"status"`
}
