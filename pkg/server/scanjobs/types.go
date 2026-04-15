// Package scanjobs implements the per-engine scan job queue: portal
// queues one row per (engine, group/host-set) request, the engine
// long-polls, claims, runs the scan against each host, and submits
// findings back through the gateway. See
// docs/plans/2026-04-14-onboarding-phase-5-scan-jobs-plan.md for the
// full design.
//
// Architecture: 4th copy of the engine job-queue pattern (after
// discovery + credential-delivery + credential-test). All four
// implement the same claim/ack/reclaim shape — the abstraction
// extraction is tracked as Phase 5.5 tech debt.
package scanjobs

import (
	"time"

	"github.com/google/uuid"
)

// JobStatus is the lifecycle state of a scan job. Values mirror the
// CHECK constraint on scan_jobs.status (migration v21).
type JobStatus string

const (
	StatusQueued    JobStatus = "queued"
	StatusClaimed   JobStatus = "claimed"
	StatusRunning   JobStatus = "running"
	StatusCompleted JobStatus = "completed"
	StatusFailed    JobStatus = "failed"
	StatusCancelled JobStatus = "cancelled"
)

// ScanProfile mirrors the CHECK constraint on scan_jobs.scan_profile.
// Maps to the existing scanner profiles in internal/config.
type ScanProfile string

const (
	ProfileQuick         ScanProfile = "quick"
	ProfileStandard      ScanProfile = "standard"
	ProfileComprehensive ScanProfile = "comprehensive"
)

// Job is the persisted scan-job row. RequestedBy is uuid.Nil for
// system-initiated jobs (none today; reserved for scheduled scans).
type Job struct {
	ID                  uuid.UUID   `json:"id"`
	OrgID               uuid.UUID   `json:"org_id"`
	EngineID            uuid.UUID   `json:"engine_id"`
	GroupID             *uuid.UUID  `json:"group_id,omitempty"`
	HostIDs             []uuid.UUID `json:"host_ids"`
	ScanProfile         ScanProfile `json:"scan_profile"`
	CredentialProfileID *uuid.UUID  `json:"credential_profile_id,omitempty"`
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

// HostTarget is the per-host scan target the engine receives. Address
// is a bare IP / hostname (no /32 or /128 suffix). Port is resolved
// server-side from the credential auth_type (ssh-* → 22, winrm → 5985)
// so the engine never has to parse credential metadata for routing.
type HostTarget struct {
	ID       uuid.UUID `json:"id"`
	Address  string    `json:"address"`
	Port     int       `json:"port"`
	Hostname string    `json:"hostname,omitempty"`
	OS       string    `json:"os,omitempty"`
}

// JobPayload is the wire shape returned by /api/v1/engine/scans/poll.
// CredentialSecretRef + CredentialAuthType are absent for jobs without
// a credential profile (the engine then must already have host-local
// credentials available — currently unused but reserved).
type JobPayload struct {
	ID                  uuid.UUID    `json:"id"`
	ScanProfile         ScanProfile  `json:"scan_profile"`
	CredentialSecretRef *uuid.UUID   `json:"credential_secret_ref,omitempty"`
	CredentialAuthType  string       `json:"credential_auth_type,omitempty"`
	Hosts               []HostTarget `json:"hosts"`
}

// ProgressUpdate is the per-host progress event the engine streams
// back via /api/v1/engine/scans/{id}/progress. Status is one of
// "running", "completed", or "failed".
type ProgressUpdate struct {
	HostID        uuid.UUID `json:"host_id"`
	Status        string    `json:"status"`
	FindingsCount int       `json:"findings_count"`
	Error         string    `json:"error,omitempty"`
}
