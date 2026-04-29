package scanjobs

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned by Get/Heartbeat/RequestCancel when no row
// matches. Handlers map this to HTTP 404.
var ErrNotFound = errors.New("scanjobs: not found")

// ErrAlreadyClaimed is returned by ClaimByID when the job exists but is no
// longer in 'queued' status (already claimed by another worker or cancelled).
var ErrAlreadyClaimed = errors.New("scanjobs: job already claimed or not queued")

// Store is the persistence boundary for the scan-job state machine.
// The orchestrator and the admin HTTP handlers both go through this
// interface; see PostgresStore for the concrete implementation.
//
// The interface is deliberately narrow — only the operations the
// orchestrator worker loop and the admin API need. In particular it
// does NOT expose QueueDepth / saturation checks: those belong to
// the sibling `scanresults` package (Batch E), which tracks the
// downstream push queue, not the job queue.
type Store interface {
	// Enqueue expands (TagIDs, HostFilter) into a set of Host rows
	// and inserts one manage_scan_jobs row per host, all in a single
	// transaction. Returns the inserted Job rows.
	Enqueue(ctx context.Context, req EnqueueReq) ([]Job, error)

	// EnqueuePortSurvey creates one port_survey job per host ID.
	// ScheduledAt nil means "run immediately".
	EnqueuePortSurvey(ctx context.Context, req PortSurveyEnqueueReq) ([]Job, error)

	// Get fetches a job by id. Returns ErrNotFound if no row matches.
	Get(ctx context.Context, id uuid.UUID) (Job, error)

	// List returns the `limit` most-recently-enqueued jobs for the
	// given tenant, ordered by enqueued_at descending. A limit <= 0
	// falls back to a safe default.
	List(ctx context.Context, tenantID uuid.UUID, limit int) ([]Job, error)

	// RequestCancel flips cancel_requested=true on the row. The
	// orchestrator's heartbeat loop polls IsCancelRequested and
	// terminates the in-flight scan; the terminal state write is
	// performed by Cancel from the orchestrator side.
	RequestCancel(ctx context.Context, id uuid.UUID) error

	// ClaimNext atomically transitions one queued job to running and
	// stamps worker_id + started_at + running_heartbeat_at. Uses
	// FOR UPDATE SKIP LOCKED so N workers can claim concurrently
	// without serialising on the same row. The boolean return is
	// false when the queue is empty; callers should poll.
	ClaimNext(ctx context.Context, workerID string) (Job, bool, error)

	// Heartbeat refreshes running_heartbeat_at and progress_text on
	// a running job. Returns ErrNotFound if the row is gone (e.g. a
	// prior Cancel beat us to the update).
	Heartbeat(ctx context.Context, id uuid.UUID, progress string) error

	// IsCancelRequested reads the cancel_requested flag.
	IsCancelRequested(ctx context.Context, id uuid.UUID) (bool, error)

	// Complete transitions a running job to completed + finished_at.
	// Idempotent: the WHERE guard on status='running' means a second
	// call after Cancel or Fail is a silent no-op.
	Complete(ctx context.Context, id uuid.UUID) error

	// Fail transitions a running job to failed + finished_at and
	// stores the error string for audit. Guarded by status='running'
	// like Complete so terminal races are no-ops.
	Fail(ctx context.Context, id uuid.UUID, errMsg string) error

	// Cancel transitions a queued or running job to cancelled +
	// finished_at. Guarded by status IN ('queued','running') so
	// post-terminal writes are no-ops.
	Cancel(ctx context.Context, id uuid.UUID) error

	// ReapStale flips any running row whose running_heartbeat_at is
	// older than staleAfter back to queued (and clears worker_id +
	// started_at + running_heartbeat_at). Returns the number of rows
	// reverted. A crashed worker's claim is thus freed for pickup.
	ReapStale(ctx context.Context, staleAfter time.Duration) (int, error)

	// PlanEnqueueCount returns how many manage_hosts rows the given
	// EnqueueReq would expand to WITHOUT actually inserting any jobs.
	// Used by Batch H's soft-buffer scan-cap enforcement at the admin
	// handler layer: the handler pre-checks cap+usage before delegating
	// to Enqueue so a rejected request never mutates state.
	//
	// Implementation runs the same tag/host expansion query as
	// Enqueue so numeric parity is guaranteed.
	PlanEnqueueCount(ctx context.Context, req EnqueueReq) (int64, error)

	// CountCompletedSince returns the number of scan jobs for the given
	// tenant that transitioned to status='completed' at or after `since`.
	// Used by the Manage Server's usage pusher to populate the scans/
	// monthly metric the Licence Server consults for soft-buffer cap
	// enforcement.
	//
	// Only rows with finished_at >= since are counted; finished_at is
	// UTC in the DB, so callers must supply `since` in UTC (or any zone
	// — the comparison is timestamp-absolute).
	CountCompletedSince(ctx context.Context, tenantID uuid.UUID, since time.Time) (int64, error)

	// CountActive returns the number of scan jobs in queued or running
	// state for the given tenant. Used by the deactivation watcher to
	// determine whether it is safe to proceed with licence deactivation.
	CountActive(ctx context.Context, tenantID uuid.UUID) (int64, error)

	// ListQueued returns up to limit queued jobs matching any of the given
	// job_types, with scheduled_at <= NOW(), ordered by enqueued_at ascending.
	ListQueued(ctx context.Context, jobTypes []string, limit int) ([]Job, error)

	// ClaimByID atomically transitions the named job from queued → running.
	// Returns ErrNotFound when no such job exists.
	// Returns ErrAlreadyClaimed when the job is not in 'queued' status.
	ClaimByID(ctx context.Context, id uuid.UUID, workerID string) (Job, error)
}

// BatchStore is the persistence boundary for scan batches.
type BatchStore interface {
	// EnqueueBatch creates one manage_scan_batches row and one
	// manage_scan_jobs row per spec, atomically. Returns the new batch ID
	// and a count of jobs inserted. skipped is stored on the response but
	// not persisted to DB.
	EnqueueBatch(ctx context.Context, req BatchEnqueueReq, specs []JobSpec, skipped []SkippedJob) (BatchEnqueueResp, error)

	// GetBatch returns a single batch by ID with an aggregated jobs_created
	// count. Returns ErrNotFound when the batch does not exist.
	GetBatch(ctx context.Context, id uuid.UUID) (Batch, error)

	// ListBatches returns the most recent batches for a tenant, newest first.
	// limit <= 0 falls back to 50.
	ListBatches(ctx context.Context, tenantID uuid.UUID, limit int) ([]Batch, error)

	// CountPendingJobs returns the number of manage_scan_jobs rows in
	// queued or running state across all tenants. Used by EnqueueBatch to
	// enforce the 10,000-job saturation cap.
	CountPendingJobs(ctx context.Context) (int64, error)
}
