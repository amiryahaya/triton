package agentpush

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/server/jobqueue"
)

// PostgresStore implements Store backed by PostgreSQL. Push-job queue
// operations (claim, cancel, reclaim, finish) are delegated to the
// embedded jobqueue.Queue; domain-specific enrichment remains here.
type PostgresStore struct {
	pool  *pgxpool.Pool
	queue *jobqueue.Queue
}

// NewPostgresStore wires the dependencies and constructs the jobqueue
// for the agent_push_jobs table.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	q := jobqueue.New(pool, jobqueue.Config{
		Table:             "agent_push_jobs",
		EngineIDColumn:    "engine_id",
		StatusColumn:      "status",
		ClaimedAtColumn:   "claimed_at",
		RequestedAtColumn: "requested_at",
		CompletedAtColumn: "completed_at",
		QueuedStatus:      "queued",
		ClaimedStatus:     "claimed",
		TerminalStatuses:  []string{"completed", "failed", "cancelled"},
	})
	return &PostgresStore{pool: pool, queue: q}
}

// Compile-time interface satisfaction assertion.
var _ Store = (*PostgresStore)(nil)

// jobSelectCols matches the column order expected by scanPushJob.
const jobSelectCols = `id, org_id, engine_id, group_id, host_ids,
	credential_profile_id, status, COALESCE(error, ''),
	COALESCE(requested_by, '00000000-0000-0000-0000-000000000000'::uuid),
	requested_at, claimed_at, completed_at,
	progress_total, progress_done, progress_failed`

func scanPushJob(row pgx.Row) (PushJob, error) {
	var j PushJob
	var statusStr string
	if err := row.Scan(
		&j.ID, &j.OrgID, &j.EngineID, &j.GroupID, &j.HostIDs,
		&j.CredentialProfileID, &statusStr, &j.Error,
		&j.RequestedBy, &j.RequestedAt, &j.ClaimedAt, &j.CompletedAt,
		&j.ProgressTotal, &j.ProgressDone, &j.ProgressFailed,
	); err != nil {
		return PushJob{}, err
	}
	j.Status = JobStatus(statusStr)
	return j, nil
}

// CreatePushJob persists a new queued push job.
func (s *PostgresStore) CreatePushJob(ctx context.Context, j PushJob) (PushJob, error) {
	progressTotal := len(j.HostIDs)
	row := s.pool.QueryRow(ctx,
		`INSERT INTO agent_push_jobs
		 (id, org_id, engine_id, group_id, host_ids,
		  credential_profile_id, requested_by, progress_total)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING status, requested_at, progress_total`,
		j.ID, j.OrgID, j.EngineID, j.GroupID, j.HostIDs,
		j.CredentialProfileID, j.RequestedBy, progressTotal,
	)
	var statusStr string
	if err := row.Scan(&statusStr, &j.RequestedAt, &j.ProgressTotal); err != nil {
		return PushJob{}, fmt.Errorf("create push job: %w", err)
	}
	j.Status = JobStatus(statusStr)
	return j, nil
}

func (s *PostgresStore) GetPushJob(ctx context.Context, orgID, id uuid.UUID) (PushJob, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+jobSelectCols+` FROM agent_push_jobs WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	j, err := scanPushJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PushJob{}, ErrJobNotFound
		}
		return PushJob{}, fmt.Errorf("get push job: %w", err)
	}
	return j, nil
}

func (s *PostgresStore) ListPushJobs(ctx context.Context, orgID uuid.UUID, limit int) ([]PushJob, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobSelectCols+` FROM agent_push_jobs
		 WHERE org_id = $1 ORDER BY requested_at DESC LIMIT $2`,
		orgID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list push jobs: %w", err)
	}
	defer rows.Close()

	out := []PushJob{}
	for rows.Next() {
		j, err := scanPushJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *PostgresStore) CancelPushJob(ctx context.Context, orgID, id uuid.UUID) error {
	err := s.queue.Cancel(ctx, orgID, id)
	switch {
	case errors.Is(err, jobqueue.ErrNotFound):
		return ErrJobNotFound
	case errors.Is(err, jobqueue.ErrNotCancellable):
		return ErrJobNotCancellable
	default:
		return err
	}
}

// ClaimNext atomically grabs the oldest queued push job for engineID
// and enriches it with resolved host addresses + credential metadata.
func (s *PostgresStore) ClaimNext(ctx context.Context, engineID uuid.UUID) (PushJobPayload, bool, error) {
	id, found, err := s.queue.ClaimNextID(ctx, engineID)
	if !found || err != nil {
		return PushJobPayload{}, false, err
	}
	return s.enrichClaimedJob(ctx, id)
}

func (s *PostgresStore) enrichClaimedJob(ctx context.Context, jobID uuid.UUID) (PushJobPayload, bool, error) {
	var (
		hostIDs       []uuid.UUID
		credProfileID uuid.UUID
	)
	err := s.pool.QueryRow(ctx,
		`SELECT host_ids, credential_profile_id
		 FROM agent_push_jobs WHERE id = $1`,
		jobID,
	).Scan(&hostIDs, &credProfileID)
	if err != nil {
		return PushJobPayload{}, false, fmt.Errorf("enrich claimed push job: %w", err)
	}

	hosts, err := loadHostTargets(ctx, s.pool, hostIDs)
	if err != nil {
		return PushJobPayload{}, false, err
	}

	// Resolve credential secret ref + auth type.
	var secretRef uuid.UUID
	var authType string
	if err := s.pool.QueryRow(ctx,
		`SELECT secret_ref, auth_type FROM credentials_profiles WHERE id = $1`,
		credProfileID,
	).Scan(&secretRef, &authType); err != nil {
		return PushJobPayload{}, false, fmt.Errorf("load credential profile: %w", err)
	}

	// Port resolution: ssh-* / bootstrap-admin -> 22.
	port := 22
	for i := range hosts {
		hosts[i].Port = port
	}

	return PushJobPayload{
		ID:                  jobID,
		CredentialSecretRef: secretRef,
		CredentialAuthType:  authType,
		Hosts:               hosts,
	}, true, nil
}

// loadHostTargets loads host targets from inventory_hosts by ID.
func loadHostTargets(ctx context.Context, pool *pgxpool.Pool, hostIDs []uuid.UUID) ([]HostTarget, error) {
	if len(hostIDs) == 0 {
		return nil, nil
	}
	rows, err := pool.Query(ctx,
		`SELECT id, COALESCE(address::text, ''),
		        COALESCE(hostname, ''), COALESCE(os, '')
		 FROM inventory_hosts WHERE id = ANY($1)`,
		hostIDs,
	)
	if err != nil {
		return nil, fmt.Errorf("query host targets: %w", err)
	}
	defer rows.Close()

	out := make([]HostTarget, 0, len(hostIDs))
	for rows.Next() {
		var h HostTarget
		var addr string
		if err := rows.Scan(&h.ID, &addr, &h.Hostname, &h.OS); err != nil {
			return nil, fmt.Errorf("scan host target: %w", err)
		}
		if i := strings.IndexByte(addr, '/'); i >= 0 {
			addr = addr[:i]
		}
		h.Address = addr
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateProgress(ctx context.Context, jobID uuid.UUID, done, failed int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE agent_push_jobs
		 SET progress_done   = progress_done + $2,
		     progress_failed = progress_failed + $3,
		     status          = CASE WHEN status = 'claimed' THEN 'running' ELSE status END
		 WHERE id = $1`,
		jobID, done, failed,
	)
	if err != nil {
		return fmt.Errorf("update push job progress: %w", err)
	}
	return nil
}

func (s *PostgresStore) FinishJob(ctx context.Context, engineID, jobID uuid.UUID, status JobStatus, errMsg string) error {
	err := s.queue.Finish(ctx, engineID, jobID, string(status), errMsg)
	switch {
	case errors.Is(err, jobqueue.ErrNotFound):
		return ErrJobNotFound
	case errors.Is(err, jobqueue.ErrNotOwned):
		return ErrJobNotOwned
	case errors.Is(err, jobqueue.ErrAlreadyTerminal):
		return ErrJobAlreadyTerminal
	default:
		return err
	}
}

func (s *PostgresStore) ReclaimStale(ctx context.Context, cutoff time.Time) error {
	return s.queue.ReclaimStale(ctx, cutoff)
}

// RegisterAgent upserts a fleet agent row and flips the inventory
// host mode from 'agentless' to 'agent'. The UPSERT handles the case
// where the agent is re-pushed to the same host (e.g. cert renewal).
func (s *PostgresStore) RegisterAgent(ctx context.Context, a FleetAgent) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin register agent: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	_, err = tx.Exec(ctx,
		`INSERT INTO fleet_agents (id, org_id, host_id, engine_id, cert_fingerprint, version, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (host_id) DO UPDATE SET
		     cert_fingerprint = EXCLUDED.cert_fingerprint,
		     engine_id        = EXCLUDED.engine_id,
		     version          = EXCLUDED.version,
		     status           = EXCLUDED.status,
		     installed_at     = NOW()`,
		a.ID, a.OrgID, a.HostID, a.EngineID, a.CertFingerprint, a.Version, a.Status,
	)
	if err != nil {
		return fmt.Errorf("upsert fleet agent: %w", err)
	}

	// Flip inventory host mode to 'agent'.
	_, err = tx.Exec(ctx,
		`UPDATE inventory_hosts SET mode = 'agent' WHERE id = $1`,
		a.HostID,
	)
	if err != nil {
		return fmt.Errorf("flip host mode: %w", err)
	}

	return tx.Commit(ctx)
}

func (s *PostgresStore) GetAgent(ctx context.Context, orgID, id uuid.UUID) (FleetAgent, error) {
	var a FleetAgent
	err := s.pool.QueryRow(ctx,
		`SELECT id, org_id, host_id, engine_id, cert_fingerprint,
		        installed_at, last_heartbeat, COALESCE(version, ''), status
		 FROM fleet_agents WHERE org_id = $1 AND id = $2`,
		orgID, id,
	).Scan(&a.ID, &a.OrgID, &a.HostID, &a.EngineID, &a.CertFingerprint,
		&a.InstalledAt, &a.LastHeartbeat, &a.Version, &a.Status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return FleetAgent{}, ErrAgentNotFound
		}
		return FleetAgent{}, fmt.Errorf("get fleet agent: %w", err)
	}
	return a, nil
}

func (s *PostgresStore) ListAgents(ctx context.Context, orgID uuid.UUID) ([]FleetAgent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, org_id, host_id, engine_id, cert_fingerprint,
		        installed_at, last_heartbeat, COALESCE(version, ''), status
		 FROM fleet_agents WHERE org_id = $1 ORDER BY installed_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list fleet agents: %w", err)
	}
	defer rows.Close()

	out := []FleetAgent{}
	for rows.Next() {
		var a FleetAgent
		if err := rows.Scan(&a.ID, &a.OrgID, &a.HostID, &a.EngineID, &a.CertFingerprint,
			&a.InstalledAt, &a.LastHeartbeat, &a.Version, &a.Status); err != nil {
			return nil, fmt.Errorf("scan fleet agent: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateAgentHeartbeat(ctx context.Context, agentID uuid.UUID) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE fleet_agents SET last_heartbeat = NOW() WHERE id = $1`,
		agentID,
	)
	if err != nil {
		return fmt.Errorf("update agent heartbeat: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrAgentNotFound
	}
	return nil
}

// RecordAgentHeartbeat atomically updates last_heartbeat for the agent
// identified by host_id and flips status from 'installing' to 'healthy'
// on first heartbeat. Uninstalled agents are not re-activated.
func (s *PostgresStore) RecordAgentHeartbeat(ctx context.Context, hostID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE fleet_agents
		 SET last_heartbeat = NOW(),
		     status = CASE WHEN status = 'installing' THEN 'healthy' ELSE status END
		 WHERE host_id = $1 AND status != 'uninstalled'`,
		hostID,
	)
	if err != nil {
		return fmt.Errorf("record agent heartbeat: %w", err)
	}
	return nil
}

func (s *PostgresStore) SetAgentStatus(ctx context.Context, agentID uuid.UUID, status string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE fleet_agents SET status = $2 WHERE id = $1`,
		agentID, status,
	)
	if err != nil {
		return fmt.Errorf("set agent status: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrAgentNotFound
	}
	return nil
}
