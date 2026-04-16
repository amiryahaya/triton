package agentpush

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors. Handlers map these to HTTP status codes.
var (
	ErrJobNotFound        = errors.New("agentpush: job not found")
	ErrJobNotCancellable  = errors.New("agentpush: job not cancellable (must be queued)")
	ErrJobAlreadyTerminal = errors.New("agentpush: job already in terminal state")
	ErrJobNotOwned        = errors.New("agentpush: job not owned by this engine")
	ErrAgentNotFound      = errors.New("agentpush: agent not found")
)

// Store persists agent push jobs and fleet agents, brokering the
// engine claim/progress/finish flow. Concrete implementation in
// postgres.go.
type Store interface {
	// Push jobs
	CreatePushJob(ctx context.Context, j PushJob) (PushJob, error)
	GetPushJob(ctx context.Context, orgID, id uuid.UUID) (PushJob, error)
	ListPushJobs(ctx context.Context, orgID uuid.UUID, limit int) ([]PushJob, error)
	CancelPushJob(ctx context.Context, orgID, id uuid.UUID) error
	ClaimNext(ctx context.Context, engineID uuid.UUID) (PushJobPayload, bool, error)
	UpdateProgress(ctx context.Context, jobID uuid.UUID, done, failed int) error
	FinishJob(ctx context.Context, engineID, jobID uuid.UUID, status JobStatus, errMsg string) error
	ReclaimStale(ctx context.Context, cutoff time.Time) error

	// Fleet agents
	RegisterAgent(ctx context.Context, a FleetAgent) error
	GetAgent(ctx context.Context, orgID, id uuid.UUID) (FleetAgent, error)
	ListAgents(ctx context.Context, orgID uuid.UUID) ([]FleetAgent, error)
	UpdateAgentHeartbeat(ctx context.Context, agentID uuid.UUID) error
	RecordAgentHeartbeat(ctx context.Context, hostID uuid.UUID) error
	SetAgentStatus(ctx context.Context, agentID uuid.UUID, status string) error
}
