package discovery

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// Sentinel errors for store consumers. Handlers map these to HTTP
// status codes (404 for NotFound, 409 for NotCancellable) without
// depending on pgx internals.
var (
	// ErrJobNotFound is returned by GetJob / ListCandidates when the
	// requested job does not exist (or is not visible to the caller's
	// org).
	ErrJobNotFound = errors.New("discovery job not found")

	// ErrJobNotCancellable is returned by CancelJob when the job exists
	// but is no longer queued — an engine has already claimed it and
	// owns the lifecycle from here.
	ErrJobNotCancellable = errors.New("discovery job not cancellable")
)

// Store is the persistence contract for discovery jobs + candidates.
// Operator-facing methods (CreateJob, GetJob, ListJobs,
// ListCandidates, MarkCandidatesPromoted, CancelJob) expect an org
// scope and enforce tenant isolation. Engine-facing methods
// (ClaimNext, InsertCandidates, FinishJob) are keyed by engine ID or
// job ID and trust the mTLS middleware to have authenticated the
// caller.
type Store interface {
	// CreateJob inserts a queued job and returns the stored row.
	// status defaults to 'queued'; requested_at defaults to NOW().
	CreateJob(ctx context.Context, j Job) (Job, error)

	// GetJob returns the job row for (orgID, id) or ErrJobNotFound.
	GetJob(ctx context.Context, orgID, id uuid.UUID) (Job, error)

	// ListJobs returns all jobs for an org ordered by requested_at DESC.
	ListJobs(ctx context.Context, orgID uuid.UUID) ([]Job, error)

	// ListCandidates returns all candidates for a job ordered by
	// detected_at ASC.
	ListCandidates(ctx context.Context, jobID uuid.UUID) ([]Candidate, error)

	// MarkCandidatesPromoted flips promoted=TRUE for the given IDs.
	// Unknown IDs are silently ignored.
	MarkCandidatesPromoted(ctx context.Context, ids []uuid.UUID) error

	// CancelJob flips a queued job to 'cancelled'. Returns
	// ErrJobNotCancellable if the job exists but is past queued.
	CancelJob(ctx context.Context, orgID, id uuid.UUID) error

	// ClaimNext atomically claims the oldest queued job for the given
	// engine and returns it with status=claimed. found=false,err=nil
	// means no queued work is available.
	ClaimNext(ctx context.Context, engineID uuid.UUID) (Job, bool, error)

	// InsertCandidates bulk-inserts candidates with ON CONFLICT DO
	// NOTHING on (job_id, address) so engine retries are idempotent.
	InsertCandidates(ctx context.Context, jobID uuid.UUID, cs []Candidate) error

	// FinishJob flips a claimed/running job to the given terminal
	// status, stamps completed_at, stores any error message, and
	// records the final candidate count.
	FinishJob(ctx context.Context, jobID uuid.UUID, status JobStatus, errMsg string, candidateCount int) error
}
