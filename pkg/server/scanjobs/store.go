package scanjobs

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors. Handlers map these to HTTP status codes (404 / 409).
var (
	// ErrJobNotFound: GetJob / CancelJob received an (org, id) pair
	// with no matching row.
	ErrJobNotFound = errors.New("scanjobs: job not found")

	// ErrJobNotCancellable: CancelJob targeted a job that has already
	// been claimed/running/terminal — only queued jobs can be cancelled
	// by operators (the engine handles in-flight cancellation itself
	// via reaper or context expiry).
	ErrJobNotCancellable = errors.New("scanjobs: job not cancellable (must be queued)")

	// ErrJobAlreadyTerminal: FinishJob called for a job that is already
	// completed/failed/cancelled. Idempotent retry from a crashed
	// engine sees this and can move on.
	ErrJobAlreadyTerminal = errors.New("scanjobs: job already in terminal state")
)

// Store persists scan jobs and brokers the engine claim/progress/finish
// flow. Concrete implementation in postgres.go.
//
// All four engine job-queues (discovery, credential-delivery,
// credential-test, scan-jobs) share the same shape — the abstraction
// extraction is tracked as Phase 5.5 tech debt.
type Store interface {
	// CreateJob persists a new queued job. Returns the job with
	// server-populated fields (RequestedAt, Status).
	CreateJob(ctx context.Context, j Job) (Job, error)

	// GetJob returns the job matching (org_id, id) or ErrJobNotFound.
	GetJob(ctx context.Context, orgID, id uuid.UUID) (Job, error)

	// ListJobs returns all jobs for the org ordered by requested_at
	// descending. limit <= 0 falls back to a sensible default.
	ListJobs(ctx context.Context, orgID uuid.UUID, limit int) ([]Job, error)

	// CancelJob flips a queued job to cancelled. Returns
	// ErrJobNotCancellable if the job is past queued, ErrJobNotFound
	// if the (org, id) pair does not exist.
	CancelJob(ctx context.Context, orgID, id uuid.UUID) error

	// ClaimNext atomically grabs the oldest queued job for engineID
	// and returns the wire payload the engine needs (resolved host
	// addresses + credential metadata). Bool is false when the queue
	// is empty.
	ClaimNext(ctx context.Context, engineID uuid.UUID) (JobPayload, bool, error)

	// UpdateProgress increments per-host counters and flips status
	// from claimed → running on the first call (atomically).
	UpdateProgress(ctx context.Context, jobID uuid.UUID, done, failed int) error

	// FinishJob transitions a job to its terminal state and stamps
	// completed_at. Returns ErrJobAlreadyTerminal on a second call.
	FinishJob(ctx context.Context, jobID uuid.UUID, status JobStatus, errMsg string) error

	// ReclaimStale flips claimed/running rows whose claimed_at is
	// older than cutoff back to queued so another (or the same)
	// engine can retry them.
	ReclaimStale(ctx context.Context, cutoff time.Time) error

	// RecordScanResult ingests a per-host scan result (JSON-marshalled
	// model.ScanResult) and persists it into the scans + findings
	// tables tagged with the originating engine + job.
	RecordScanResult(ctx context.Context, jobID, engineID, hostID uuid.UUID, scanPayload []byte) error
}
