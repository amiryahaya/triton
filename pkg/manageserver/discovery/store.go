package discovery

import (
	"context"

	"github.com/google/uuid"
)

// Store is the persistence boundary for the discovery bounded context.
type Store interface {
	// CreateJob replaces any existing job+candidates for the tenant in one transaction,
	// then inserts the new job row. Returns the created Job.
	CreateJob(ctx context.Context, req EnqueueReq, tenantID uuid.UUID) (Job, error)

	// GetCurrentJob returns the most recent job for the tenant.
	// Returns ErrNotFound if no job exists yet.
	GetCurrentJob(ctx context.Context, tenantID uuid.UUID) (Job, error)

	// ActiveJobExists returns true if a queued or running job exists for the tenant.
	ActiveJobExists(ctx context.Context, tenantID uuid.UUID) (bool, error)

	// SetCancelRequested sets cancel_requested=true for the job.
	SetCancelRequested(ctx context.Context, jobID uuid.UUID) error

	// UpdateProgress sets scanned_ips on the job row.
	UpdateProgress(ctx context.Context, jobID uuid.UUID, scannedIPs int) error

	// UpdateStatus sets status, started_at/finished_at, error_message on the job.
	UpdateStatus(ctx context.Context, upd StatusUpdate) error

	// InsertCandidate inserts a single discovered candidate.
	InsertCandidate(ctx context.Context, c Candidate) error

	// ListCandidates returns all candidates for the job ordered by created_at.
	ListCandidates(ctx context.Context, jobID uuid.UUID) ([]Candidate, error)

	// GetCandidates fetches specific candidates by ID scoped to tenantID,
	// joining through manage_discovery_jobs to prevent cross-tenant IDOR.
	GetCandidates(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]Candidate, error)
}
