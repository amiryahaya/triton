// Package scanjobs owns the `manage_scan_jobs` bounded context: the
// queue of scan jobs consumed by the Manage Server's in-process
// orchestrator worker pool. The types here are the stable surface
// shared between the postgres store, the orchestrator, and the admin
// HTTP handlers.
package scanjobs

import (
	"time"

	"github.com/google/uuid"
)

// Status enumerates the terminal and non-terminal states a scan job
// can occupy. The DB check constraint in migration v3 pins this list;
// keep the two in sync when extending.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Profile enumerates the Triton scanner profiles exposed to Manage.
// The DB CHECK constraint on `manage_scan_jobs.profile` pins this list.
type Profile string

const (
	ProfileQuick         Profile = "quick"
	ProfileStandard      Profile = "standard"
	ProfileComprehensive Profile = "comprehensive"
)

// JobType discriminates the scan execution strategy.
type JobType string

const (
	JobTypeFilesystem JobType = "filesystem"
	JobTypePortSurvey JobType = "port_survey"
)

// Job models one row of `manage_scan_jobs`. Nullable DB columns are
// surfaced as pointer-typed fields (`*time.Time`, `*uuid.UUID`) so a
// consumer can distinguish "not yet set" from "zero value".
type Job struct {
	ID                 uuid.UUID  `json:"id"`
	TenantID           uuid.UUID  `json:"tenant_id"`
	HostID             uuid.UUID  `json:"host_id"`
	Profile            Profile    `json:"profile"`
	CredentialsRef     *uuid.UUID `json:"credentials_ref,omitempty"`
	Status             Status     `json:"status"`
	CancelRequested    bool       `json:"cancel_requested"`
	WorkerID           string     `json:"worker_id,omitempty"`
	EnqueuedAt         time.Time  `json:"enqueued_at"`
	StartedAt          *time.Time `json:"started_at,omitempty"`
	FinishedAt         *time.Time `json:"finished_at,omitempty"`
	RunningHeartbeatAt *time.Time `json:"running_heartbeat_at,omitempty"`
	ProgressText       string     `json:"progress_text"`
	ErrorMessage       string     `json:"error_message"`
	JobType            JobType    `json:"job_type"`
	ScheduledAt        *time.Time `json:"scheduled_at,omitempty"`
	PortOverride       []uint16   `json:"port_override,omitempty"`
}

// EnqueueReq is the input to Store.Enqueue. TenantID is injected from
// orgctx at the handler boundary, never from the client body, which is
// why it carries `json:"-"`. TagIDs + HostFilter jointly resolve to
// the Host rows the orchestrator will scan; HostFilter is a simple
// glob against hostname (empty means "all hosts with the tags").
type EnqueueReq struct {
	TenantID       uuid.UUID   `json:"-"`
	TagIDs         []uuid.UUID `json:"tags"`
	HostFilter     string      `json:"host_filter"`
	Profile        Profile     `json:"profile"`
	CredentialsRef *uuid.UUID  `json:"credentials_ref,omitempty"`
}

// PortSurveyEnqueueReq is the input to Store.EnqueuePortSurvey.
// Operators select individual hosts by ID (not by tag) since port
// surveys target specific machines. ScheduledAt nil = run immediately.
type PortSurveyEnqueueReq struct {
	TenantID     uuid.UUID   `json:"-"`
	HostIDs      []uuid.UUID `json:"host_ids"`
	Profile      Profile     `json:"profile"`
	ScheduledAt  *time.Time  `json:"scheduled_at,omitempty"`
	PortOverride []uint16    `json:"port_override,omitempty"`
}
