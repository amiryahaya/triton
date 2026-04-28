package discovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

var _ Store = (*PostgresStore)(nil)

const jobSelectCols = `id, tenant_id, cidr, ssh_port, status, total_ips, scanned_ips, found_ips,
	cancel_requested, started_at, finished_at, error_message, created_at`

const candidateSelectCols = `id, job_id, ip, hostname, existing_host_id, created_at`

func scanJob(row pgx.Row) (Job, error) {
	var j Job
	if err := row.Scan(
		&j.ID, &j.TenantID, &j.CIDR, &j.SSHPort, &j.Status,
		&j.TotalIPs, &j.ScannedIPs, &j.FoundIPs, &j.CancelRequested,
		&j.StartedAt, &j.FinishedAt, &j.ErrorMessage, &j.CreatedAt,
	); err != nil {
		return Job{}, err
	}
	return j, nil
}

func scanCandidate(row pgx.Row) (Candidate, error) {
	var c Candidate
	if err := row.Scan(
		&c.ID, &c.JobID, &c.IP, &c.Hostname, &c.ExistingHostID, &c.CreatedAt,
	); err != nil {
		return Candidate{}, err
	}
	return c, nil
}

func (s *PostgresStore) CreateJob(ctx context.Context, req EnqueueReq, tenantID uuid.UUID) (Job, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Job{}, fmt.Errorf("discovery: create job: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx,
		`DELETE FROM manage_discovery_jobs WHERE tenant_id = $1`,
		tenantID,
	); err != nil {
		return Job{}, fmt.Errorf("discovery: create job: delete old job: %w", err)
	}

	row := tx.QueryRow(ctx,
		`INSERT INTO manage_discovery_jobs (tenant_id, cidr, ssh_port, status, total_ips)
		 VALUES ($1, $2, $3, 'queued', $4)
		 RETURNING `+jobSelectCols,
		tenantID, req.CIDR, req.SSHPort, req.TotalIPs,
	)
	j, err := scanJob(row)
	if err != nil {
		return Job{}, fmt.Errorf("discovery: create job: insert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Job{}, fmt.Errorf("discovery: create job: commit: %w", err)
	}
	return j, nil
}

func (s *PostgresStore) GetCurrentJob(ctx context.Context, tenantID uuid.UUID) (Job, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+jobSelectCols+`
		 FROM manage_discovery_jobs
		 WHERE tenant_id = $1
		 ORDER BY created_at DESC
		 LIMIT 1`,
		tenantID,
	)
	j, err := scanJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, fmt.Errorf("discovery: get current job: %w", err)
	}
	return j, nil
}

func (s *PostgresStore) ActiveJobExists(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM manage_discovery_jobs
			WHERE tenant_id = $1 AND status IN ('queued','running')
		)`,
		tenantID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("discovery: active job exists: %w", err)
	}
	return exists, nil
}

func (s *PostgresStore) SetCancelRequested(ctx context.Context, jobID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE manage_discovery_jobs SET cancel_requested = TRUE WHERE id = $1`,
		jobID,
	)
	if err != nil {
		return fmt.Errorf("discovery: set cancel requested: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateProgress(ctx context.Context, jobID uuid.UUID, scannedIPs, foundIPs int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE manage_discovery_jobs SET scanned_ips = $1, found_ips = $2 WHERE id = $3`,
		scannedIPs, foundIPs, jobID,
	)
	if err != nil {
		return fmt.Errorf("discovery: update progress: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateStatus(ctx context.Context, upd StatusUpdate) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE manage_discovery_jobs
		 SET status = $1, error_message = $2, started_at = $3, finished_at = $4
		 WHERE id = $5`,
		upd.Status, upd.ErrorMessage, upd.StartedAt, upd.FinishedAt, upd.JobID,
	)
	if err != nil {
		return fmt.Errorf("discovery: update status: %w", err)
	}
	return nil
}

func (s *PostgresStore) InsertCandidate(ctx context.Context, c Candidate) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO manage_discovery_candidates (job_id, ip, hostname, existing_host_id)
		 VALUES ($1, $2, $3, $4)`,
		c.JobID, c.IP, c.Hostname, c.ExistingHostID,
	)
	if err != nil {
		return fmt.Errorf("discovery: insert candidate: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListCandidates(ctx context.Context, jobID uuid.UUID) ([]Candidate, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+candidateSelectCols+`
		 FROM manage_discovery_candidates
		 WHERE job_id = $1
		 ORDER BY created_at`,
		jobID,
	)
	if err != nil {
		return nil, fmt.Errorf("discovery: list candidates: %w", err)
	}
	defer rows.Close()

	var out []Candidate
	for rows.Next() {
		c, err := scanCandidate(rows)
		if err != nil {
			return nil, fmt.Errorf("discovery: list candidates: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("discovery: list candidates: %w", err)
	}
	if out == nil {
		out = []Candidate{}
	}
	return out, nil
}

func (s *PostgresStore) GetCandidates(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]Candidate, error) {
	if len(ids) == 0 {
		return []Candidate{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT c.id, c.job_id, c.ip, c.hostname, c.existing_host_id, c.created_at
		 FROM manage_discovery_candidates c
		 JOIN manage_discovery_jobs j ON j.id = c.job_id
		 WHERE c.id = ANY($1) AND j.tenant_id = $2`,
		ids, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("discovery: get candidates: %w", err)
	}
	defer rows.Close()

	var out []Candidate
	for rows.Next() {
		c, err := scanCandidate(rows)
		if err != nil {
			return nil, fmt.Errorf("discovery: get candidates: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("discovery: get candidates: %w", err)
	}
	if out == nil {
		out = []Candidate{}
	}
	return out, nil
}
