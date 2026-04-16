package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/server/jobqueue"
)

// PostgresStore implements Store against a pgx connection pool.
// The caller owns the pool's lifetime. Queue operations (claim,
// finish, cancel, reclaim) are delegated to the embedded
// jobqueue.Queue; domain-specific enrichment (candidate_count,
// full Job hydration) remains here.
type PostgresStore struct {
	pool  *pgxpool.Pool
	queue *jobqueue.Queue
}

// NewPostgresStore wraps a pool and constructs the generic job queue
// for discovery_jobs.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	q := jobqueue.New(pool, jobqueue.Config{
		Table:             "discovery_jobs",
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

// jobSelectCols matches the column order expected by scanJob. Ports are
// scanned as []int32 because pgx binds Postgres INTEGER[] to the int32
// slice type; we translate to []int via fromInt32Array.
const jobSelectCols = `id, org_id, engine_id, requested_by, cidrs, ports,
		status, COALESCE(error, ''), requested_at, claimed_at,
		completed_at, candidate_count`

func scanJob(row pgx.Row) (Job, error) {
	var j Job
	var ports []int32
	var status string
	if err := row.Scan(
		&j.ID, &j.OrgID, &j.EngineID, &j.RequestedBy, &j.CIDRs, &ports,
		&status, &j.Error, &j.RequestedAt, &j.ClaimedAt, &j.CompletedAt,
		&j.CandidateCount,
	); err != nil {
		return Job{}, err
	}
	j.Ports = fromInt32Array(ports)
	j.Status = JobStatus(status)
	return j, nil
}

func (s *PostgresStore) CreateJob(ctx context.Context, j Job) (Job, error) {
	if j.ID == uuid.Nil {
		return Job{}, errors.New("job ID must be set")
	}
	if j.Status == "" {
		j.Status = StatusQueued
	}
	row := s.pool.QueryRow(ctx,
		`INSERT INTO discovery_jobs
		   (id, org_id, engine_id, requested_by, cidrs, ports, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING `+jobSelectCols,
		j.ID, j.OrgID, j.EngineID, j.RequestedBy, j.CIDRs,
		toInt32Array(j.Ports), string(j.Status),
	)
	out, err := scanJob(row)
	if err != nil {
		return Job{}, fmt.Errorf("create discovery job: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) GetJob(ctx context.Context, orgID, id uuid.UUID) (Job, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+jobSelectCols+` FROM discovery_jobs WHERE org_id = $1 AND id = $2`,
		orgID, id,
	)
	j, err := scanJob(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, fmt.Errorf("%w: %s in org %s", ErrJobNotFound, id, orgID)
		}
		return Job{}, fmt.Errorf("get discovery job: %w", err)
	}
	return j, nil
}

func (s *PostgresStore) ListJobs(ctx context.Context, orgID uuid.UUID) ([]Job, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobSelectCols+` FROM discovery_jobs
		 WHERE org_id = $1 ORDER BY requested_at DESC`,
		orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("list discovery jobs: %w", err)
	}
	defer rows.Close()

	out := make([]Job, 0)
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("scan discovery job: %w", err)
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list discovery jobs: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) ListCandidates(ctx context.Context, jobID uuid.UUID) ([]Candidate, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, job_id, address::text, COALESCE(hostname, ''), open_ports,
		        detected_at, promoted
		 FROM discovery_candidates
		 WHERE job_id = $1
		 ORDER BY detected_at ASC`,
		jobID,
	)
	if err != nil {
		return nil, fmt.Errorf("list discovery candidates: %w", err)
	}
	defer rows.Close()

	out := make([]Candidate, 0)
	for rows.Next() {
		var c Candidate
		var addrText string
		var ports []int32
		if err := rows.Scan(
			&c.ID, &c.JobID, &addrText, &c.Hostname, &ports,
			&c.DetectedAt, &c.Promoted,
		); err != nil {
			return nil, fmt.Errorf("scan discovery candidate: %w", err)
		}
		c.Address = parseINET(addrText)
		c.OpenPorts = fromInt32Array(ports)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list discovery candidates: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) MarkCandidatesPromoted(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE discovery_candidates SET promoted = TRUE WHERE id = ANY($1)`,
		ids,
	)
	if err != nil {
		return fmt.Errorf("mark candidates promoted: %w", err)
	}
	return nil
}

func (s *PostgresStore) CancelJob(ctx context.Context, orgID, id uuid.UUID) error {
	err := s.queue.Cancel(ctx, orgID, id)
	switch {
	case errors.Is(err, jobqueue.ErrNotFound):
		return fmt.Errorf("%w: %s in org %s", ErrJobNotFound, id, orgID)
	case errors.Is(err, jobqueue.ErrNotCancellable):
		return fmt.Errorf("%w: job is past queued", ErrJobNotCancellable)
	default:
		return err
	}
}

func (s *PostgresStore) ClaimNext(ctx context.Context, engineID uuid.UUID) (Job, bool, error) {
	id, found, err := s.queue.ClaimNextID(ctx, engineID)
	if !found || err != nil {
		return Job{}, false, err
	}
	// Enrich the claimed row into a full Job. The row is already
	// claimed (status='claimed', claimed_at=NOW()) so a plain SELECT
	// is safe — no concurrent mutation risk.
	row := s.pool.QueryRow(ctx,
		`SELECT `+jobSelectCols+` FROM discovery_jobs WHERE id = $1`, id,
	)
	j, err := scanJob(row)
	if err != nil {
		return Job{}, false, fmt.Errorf("enrich claimed discovery job: %w", err)
	}
	return j, true, nil
}

func (s *PostgresStore) InsertCandidates(ctx context.Context, jobID uuid.UUID, cs []Candidate) error {
	if len(cs) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for i := range cs {
		c := &cs[i]
		id := c.ID
		if id == uuid.Nil {
			id = uuid.Must(uuid.NewV7())
		}
		var hostname *string
		if c.Hostname != "" {
			h := c.Hostname
			hostname = &h
		}
		addr := ""
		if c.Address != nil {
			addr = c.Address.String()
		}
		batch.Queue(
			`INSERT INTO discovery_candidates
			   (id, job_id, address, hostname, open_ports)
			 VALUES ($1, $2, $3::inet, $4, $5)
			 ON CONFLICT (job_id, address) DO NOTHING`,
			id, jobID, addr, hostname, toInt32Array(c.OpenPorts),
		)
	}
	br := s.pool.SendBatch(ctx, batch)
	defer func() { _ = br.Close() }()
	for range cs {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("insert discovery candidate: %w", err)
		}
	}
	return nil
}

func (s *PostgresStore) FinishJob(ctx context.Context, engineID, jobID uuid.UUID, status JobStatus, errMsg string, candidateCount int) error {
	// Delegate terminal-state transition + ownership guard to jobqueue.
	if err := s.queue.Finish(ctx, engineID, jobID, string(status), errMsg); err != nil {
		return translateJobqueueError(err)
	}
	// Domain-specific: update candidate_count separately.
	if candidateCount >= 0 {
		_, err := s.pool.Exec(ctx,
			`UPDATE discovery_jobs SET candidate_count = $2 WHERE id = $1`,
			jobID, candidateCount,
		)
		if err != nil {
			return fmt.Errorf("update discovery candidate_count: %w", err)
		}
	}
	return nil
}

// translateJobqueueError maps generic jobqueue sentinels to discovery-
// domain sentinels so handler-layer error matching is stable.
func translateJobqueueError(err error) error {
	switch {
	case errors.Is(err, jobqueue.ErrNotFound):
		return fmt.Errorf("%w: %v", ErrJobNotFound, err)
	case errors.Is(err, jobqueue.ErrNotOwned):
		return ErrJobNotOwned
	case errors.Is(err, jobqueue.ErrAlreadyTerminal):
		return ErrJobAlreadyTerminal
	default:
		return err
	}
}

// ReclaimStale resets jobs that were claimed or running but whose
// claimed_at timestamp is older than cutoff. Delegates to the
// generic jobqueue.Queue implementation.
func (s *PostgresStore) ReclaimStale(ctx context.Context, cutoff time.Time) error {
	return s.queue.ReclaimStale(ctx, cutoff)
}

// parseINET strips the /32 or /128 CIDR suffix pgx appends when an INET
// column is cast to text, so callers receive a plain net.IP.
func parseINET(s string) net.IP {
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	return net.ParseIP(s)
}

// toInt32Array converts []int to []int32 for pgx INTEGER[] binding.
// Postgres INTEGER is 32-bit; values outside int32 range will wrap.
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
