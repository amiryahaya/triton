package discovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against a pgx connection pool.
// The caller owns the pool's lifetime.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps a pgxpool.Pool. The caller must have already run
// managestore.Migrate to version >= 10 so the discovery tables exist.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Compile-time interface satisfaction assertion.
var _ Store = (*PostgresStore)(nil)

// jobSelectCols lists the columns expected by scanJob in scan order.
// Ports are scanned as []int32 because pgx maps Postgres INT[] to int32
// slices; fromInt32Array converts them to []int for domain use.
const jobSelectCols = `id, tenant_id, cidr, ports, status, total_ips, scanned_ips,
	cancel_requested, started_at, finished_at, error_message, created_at`

// candidateSelectCols lists columns expected by scanCandidate in scan order.
const candidateSelectCols = `id, job_id, ip, hostname, open_ports, os, mac_address, mdns_name, existing_host_id, created_at`

// scanJob decodes a single row into a Job.
func scanJob(row pgx.Row) (Job, error) {
	var j Job
	var ports []int32
	if err := row.Scan(
		&j.ID, &j.TenantID, &j.CIDR, &ports, &j.Status,
		&j.TotalIPs, &j.ScannedIPs, &j.CancelRequested,
		&j.StartedAt, &j.FinishedAt, &j.ErrorMessage, &j.CreatedAt,
	); err != nil {
		return Job{}, err
	}
	j.Ports = fromInt32Array(ports)
	return j, nil
}

// scanCandidate decodes a single row into a Candidate.
func scanCandidate(row pgx.Row) (Candidate, error) {
	var c Candidate
	var ports []int32
	if err := row.Scan(
		&c.ID, &c.JobID, &c.IP, &c.Hostname, &ports,
		&c.OS, &c.MACAddress, &c.MDNSName, &c.ExistingHostID, &c.CreatedAt,
	); err != nil {
		return Candidate{}, err
	}
	c.OpenPorts = fromInt32Array(ports)
	return c, nil
}

// CreateJob replaces any existing job+candidates for the tenant in one
// serializable transaction, then inserts the new job row.
func (s *PostgresStore) CreateJob(ctx context.Context, req EnqueueReq, tenantID uuid.UUID) (Job, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Job{}, fmt.Errorf("discovery: create job: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Delete previous job (cascades to candidates via FK).
	if _, err := tx.Exec(ctx,
		`DELETE FROM manage_discovery_jobs WHERE tenant_id = $1`,
		tenantID,
	); err != nil {
		return Job{}, fmt.Errorf("discovery: create job: delete old job: %w", err)
	}

	// Insert the new job row.
	row := tx.QueryRow(ctx,
		`INSERT INTO manage_discovery_jobs (tenant_id, cidr, ports, status, total_ips)
		 VALUES ($1, $2, $3, 'queued', $4)
		 RETURNING `+jobSelectCols,
		tenantID, req.CIDR, toInt32Array(req.Ports), req.TotalIPs,
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

// GetCurrentJob returns the most recent job for the tenant.
// Returns ErrNotFound if no job exists yet.
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

// ActiveJobExists returns true if a queued or running job exists for the tenant.
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

// SetCancelRequested sets cancel_requested=true for the job.
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

// UpdateProgress sets scanned_ips on the job row.
func (s *PostgresStore) UpdateProgress(ctx context.Context, jobID uuid.UUID, scannedIPs int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE manage_discovery_jobs SET scanned_ips = $1 WHERE id = $2`,
		scannedIPs, jobID,
	)
	if err != nil {
		return fmt.Errorf("discovery: update progress: %w", err)
	}
	return nil
}

// UpdateStatus sets status, started_at, finished_at, and error_message on the job.
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

// InsertCandidate inserts a single discovered candidate.
// Hostname and ExistingHostID may be nil.
func (s *PostgresStore) InsertCandidate(ctx context.Context, c Candidate) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO manage_discovery_candidates
		 (job_id, ip, hostname, open_ports, os, mac_address, mdns_name, existing_host_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		c.JobID, c.IP, c.Hostname, toInt32Array(c.OpenPorts), c.OS, c.MACAddress, c.MDNSName, c.ExistingHostID,
	)
	if err != nil {
		return fmt.Errorf("discovery: insert candidate: %w", err)
	}
	return nil
}

// ListCandidates returns all candidates for the job ordered by created_at.
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

// GetCandidates fetches specific candidates by ID (for import validation).
func (s *PostgresStore) GetCandidates(ctx context.Context, ids []uuid.UUID) ([]Candidate, error) {
	if len(ids) == 0 {
		return []Candidate{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+candidateSelectCols+`
		 FROM manage_discovery_candidates
		 WHERE id = ANY($1)`,
		ids,
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

// toInt32Array converts []int to []int32 for pgx INT[] binding.
// Postgres INTEGER is 32-bit; port values are always within range.
func toInt32Array(xs []int) []int32 {
	out := make([]int32, len(xs))
	for i, x := range xs {
		out[i] = int32(x)
	}
	return out
}

// fromInt32Array converts pgx's []int32 back to []int for domain use.
func fromInt32Array(xs []int32) []int {
	out := make([]int, len(xs))
	for i, x := range xs {
		out[i] = int(x)
	}
	return out
}
