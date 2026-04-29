package scanjobs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	cron "github.com/robfig/cron/v3"
)

// PostgresStore implements Store against a pgx pool. The pool's
// lifetime is owned by the caller (managestore).
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps a pgxpool. The caller must have already run
// managestore.Migrate to version >= 3 so manage_scan_jobs exists.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Compile-time interface satisfaction assertion.
var _ Store = (*PostgresStore)(nil)

// jobSelectCols lists the columns expected by scanJob. COALESCE on
// worker_id lets us read the nullable TEXT column into a plain
// `string` Go field (empty-string = not-yet-claimed).
const jobSelectCols = `id, tenant_id, host_id, profile, credentials_ref, status, cancel_requested,
	COALESCE(worker_id,''), enqueued_at, started_at, finished_at, running_heartbeat_at,
	progress_text, error_message, COALESCE(job_type,'filesystem'), scheduled_at, port_override,
	batch_id, max_cpu_pct, max_memory_mb, max_duration_s`

// defaultListLimit is the fallback page size for List when a non-positive
// limit is supplied. 100 keeps API responses bounded without operator
// configuration; admin UIs paginate explicitly when they need more.
const defaultListLimit = 100

// scanJob decodes a single row into a Job. HostID is nullable in DB
// (for audit preservation across host deletes) but Job models it as a
// non-pointer uuid.UUID — historical rows with NULL host surface as uuid.Nil.
func scanJob(row pgx.Row) (Job, error) {
	var (
		j            Job
		credRef      *uuid.UUID
		hostID       *uuid.UUID
		workerID     string
		jobTypeStr   string
		portOverride []int32
	)
	if err := row.Scan(
		&j.ID, &j.TenantID, &hostID, &j.Profile, &credRef,
		&j.Status, &j.CancelRequested, &workerID, &j.EnqueuedAt,
		&j.StartedAt, &j.FinishedAt, &j.RunningHeartbeatAt,
		&j.ProgressText, &j.ErrorMessage,
		&jobTypeStr, &j.ScheduledAt, &portOverride,
		&j.BatchID, &j.MaxCPUPct, &j.MaxMemoryMB, &j.MaxDurationS,
	); err != nil {
		return Job{}, err
	}
	if hostID != nil {
		j.HostID = *hostID
	}
	j.CredentialsRef = credRef
	j.WorkerID = workerID
	j.JobType = JobType(jobTypeStr)
	for _, p := range portOverride {
		j.PortOverride = append(j.PortOverride, uint16(p)) //nolint:gosec // port values are 1–65535, validated at enqueue time
	}
	return j, nil
}

// credRefArg converts a *uuid.UUID to a driver-safe value (nil
// pointer becomes untyped nil so INSERT picks up NULL).
func credRefArg(p *uuid.UUID) any {
	if p == nil {
		return nil
	}
	return *p
}

// sqlGlob translates the user-facing glob syntax (`*`) into SQL LIKE
// wildcards (`%`). An empty filter matches all hostnames.
func sqlGlob(f string) string {
	if f == "" {
		return "%"
	}
	return strings.ReplaceAll(f, "*", "%")
}

// Enqueue expands (TagIDs, HostFilter) into Host rows then inserts
// one job per host in a single transaction. All-or-nothing semantics:
// any failure mid-batch rolls back the whole set.
//
// Saturation checking against the downstream result queue is
// intentionally NOT done here (see package doc for rationale) — it
// belongs in the scanresults package and is wired at the handler
// call-site.
func (s *PostgresStore) Enqueue(ctx context.Context, req EnqueueReq) ([]Job, error) {
	if len(req.TagIDs) == 0 {
		return []Job{}, nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin enqueue tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx,
		`SELECT DISTINCT h.id FROM manage_hosts h
		 JOIN manage_host_tags ht ON ht.host_id = h.id
		 WHERE ht.tag_id = ANY($1) AND h.hostname LIKE $2`,
		req.TagIDs, sqlGlob(req.HostFilter),
	)
	if err != nil {
		return nil, fmt.Errorf("expand tags to hosts: %w", err)
	}
	var hostIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan host id: %w", err)
		}
		hostIDs = append(hostIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate host ids: %w", err)
	}

	out := make([]Job, 0, len(hostIDs))
	for _, hid := range hostIDs {
		row := tx.QueryRow(ctx,
			`INSERT INTO manage_scan_jobs (tenant_id, host_id, profile, credentials_ref)
			 VALUES ($1, $2, $3, $4)
			 RETURNING `+jobSelectCols,
			req.TenantID, hid, string(req.Profile), credRefArg(req.CredentialsRef),
		)
		j, err := scanJob(row)
		if err != nil {
			return nil, fmt.Errorf("insert scan job for host %s: %w", hid, err)
		}
		out = append(out, j)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit enqueue tx: %w", err)
	}
	return out, nil
}

// EnqueuePortSurvey inserts one port_survey job per HostID in a single
// transaction. An empty HostIDs slice is a no-op.
func (s *PostgresStore) EnqueuePortSurvey(ctx context.Context, req PortSurveyEnqueueReq) ([]Job, error) {
	if len(req.HostIDs) == 0 {
		return []Job{}, nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin port survey enqueue tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Convert PortOverride once outside the host loop — same ports for all hosts.
	var portOverride []int32
	for _, p := range req.PortOverride {
		portOverride = append(portOverride, int32(p))
	}

	out := make([]Job, 0, len(req.HostIDs))
	for _, hid := range req.HostIDs {
		row := tx.QueryRow(ctx,
			`INSERT INTO manage_scan_jobs
			   (tenant_id, host_id, profile, job_type, scheduled_at, port_override, credentials_ref)
			 SELECT $1, $2, $3, 'port_survey', $4, $5, h.credentials_ref
			 FROM manage_hosts h WHERE h.id = $2
			 RETURNING `+jobSelectCols,
			req.TenantID, hid, string(req.Profile), req.ScheduledAt, portOverride,
		)
		j, err := scanJob(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("insert port survey job for host %s: %w", hid, ErrNotFound)
		}
		if err != nil {
			return nil, fmt.Errorf("insert port survey job for host %s: %w", hid, err)
		}
		out = append(out, j)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit port survey enqueue tx: %w", err)
	}
	return out, nil
}

// Get fetches a job by id.
func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Job, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+jobSelectCols+` FROM manage_scan_jobs WHERE id = $1`,
		id,
	)
	j, err := scanJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, fmt.Errorf("get scan job: %w", err)
	}
	return j, nil
}

// List returns the most-recently-enqueued jobs for the tenant.
func (s *PostgresStore) List(ctx context.Context, tenantID uuid.UUID, limit int) ([]Job, error) {
	if limit <= 0 {
		limit = defaultListLimit
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+jobSelectCols+` FROM manage_scan_jobs
		 WHERE tenant_id = $1
		 ORDER BY enqueued_at DESC
		 LIMIT $2`,
		tenantID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list scan jobs: %w", err)
	}
	defer rows.Close()

	out := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("scan scan_jobs row: %w", err)
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// RequestCancel flips cancel_requested=true on the row. Safe to call
// on any status — if the job is already terminal, the flag is
// meaningless but harmless.
func (s *PostgresStore) RequestCancel(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_scan_jobs SET cancel_requested = TRUE WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("request cancel: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimNext atomically pops one queued job and marks it running.
// Uses FOR UPDATE SKIP LOCKED on an inner SELECT so concurrent workers
// pick different rows. The RETURNING clause pulls the full Job row
// post-UPDATE, so the caller sees status='running' and the stamped
// worker_id / started_at. The batch status rollup is applied within
// the same transaction so the batch row reflects 'running' immediately.
func (s *PostgresStore) ClaimNext(ctx context.Context, workerID string) (Job, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Job{}, false, fmt.Errorf("claim next: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx,
		`UPDATE manage_scan_jobs
		    SET status = 'running',
		        started_at = NOW(),
		        running_heartbeat_at = NOW(),
		        worker_id = $1
		  WHERE id = (
		     SELECT id FROM manage_scan_jobs
		      WHERE status = 'queued'
		        AND COALESCE(job_type,'filesystem') = 'filesystem'
		        AND (scheduled_at IS NULL OR scheduled_at <= NOW())
		      ORDER BY enqueued_at
		      LIMIT 1
		      FOR UPDATE SKIP LOCKED
		  )
		  RETURNING `+jobSelectCols,
		workerID,
	)
	j, err := scanJob(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, fmt.Errorf("claim next scan job: %w", err)
	}
	if j.BatchID != nil {
		if err := recomputeBatchStatus(ctx, tx, *j.BatchID); err != nil {
			return Job{}, false, fmt.Errorf("claim next: recompute batch: %w", err)
		}
	}
	return j, true, tx.Commit(ctx)
}

// Heartbeat refreshes running_heartbeat_at + progress_text on a running
// job. The status='running' guard makes the write a silent no-op
// (ErrNotFound) on any terminal row — critical so that a heartbeat tick
// firing between a Cancel write and the orchestrator noticing the
// cancel doesn't resurrect running_heartbeat_at on the cancelled row.
// Returns ErrNotFound when the row is missing OR is no longer running.
func (s *PostgresStore) Heartbeat(ctx context.Context, id uuid.UUID, progress string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_scan_jobs
		    SET running_heartbeat_at = NOW(), progress_text = $1
		  WHERE id = $2 AND status = 'running'`,
		progress, id,
	)
	if err != nil {
		return fmt.Errorf("heartbeat scan job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// IsCancelRequested reads the cancel_requested flag.
func (s *PostgresStore) IsCancelRequested(ctx context.Context, id uuid.UUID) (bool, error) {
	var requested bool
	err := s.pool.QueryRow(ctx,
		`SELECT cancel_requested FROM manage_scan_jobs WHERE id = $1`,
		id,
	).Scan(&requested)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("read cancel flag: %w", err)
	}
	return requested, nil
}

// recomputeBatchStatus updates the batch rollup atomically within an open
// transaction. It is a no-op when the batch is already in a terminal state
// (completed/failed/cancelled). The CASE expression mirrors the DB lifecycle:
//
//   - Any child running          → batch running
//   - All terminal, any failed   → batch failed
//   - All cancelled              → batch cancelled
//   - All terminal, none failed  → batch completed
//   - Otherwise (e.g. mix of queued+terminal) → leave batch status as-is
func recomputeBatchStatus(ctx context.Context, tx pgx.Tx, batchID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		UPDATE manage_scan_batches b
		SET
		  status = (
		    SELECT CASE
		      WHEN bool_or(j.status = 'running')  THEN 'running'
		      WHEN bool_and(j.status IN ('completed','failed','cancelled'))
		           AND bool_or(j.status = 'failed')   THEN 'failed'
		      WHEN bool_and(j.status = 'cancelled')   THEN 'cancelled'
		      WHEN bool_and(j.status IN ('completed','failed','cancelled'))
		           AND NOT bool_or(j.status = 'failed') THEN 'completed'
		      ELSE b.status
		    END
		    FROM manage_scan_jobs j
		    WHERE j.batch_id = b.id
		  ),
		  finished_at = CASE
		    WHEN (
		      SELECT bool_and(j.status IN ('completed','failed','cancelled'))
		      FROM manage_scan_jobs j
		      WHERE j.batch_id = b.id
		    ) AND b.finished_at IS NULL THEN NOW()
		    ELSE b.finished_at
		  END
		WHERE b.id = $1
		  AND b.status NOT IN ('completed','failed','cancelled')`,
		batchID,
	)
	return err
}

// Complete transitions running→completed. The status guard makes the
// call idempotent: a second Complete after Cancel is a silent no-op
// (RowsAffected=0) but not an error — terminal-state collisions are
// expected in the orchestrator's cancel race.
func (s *PostgresStore) Complete(ctx context.Context, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("complete: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var batchID *uuid.UUID
	err = tx.QueryRow(ctx,
		`UPDATE manage_scan_jobs
		    SET status = 'completed', finished_at = NOW()
		  WHERE id = $1 AND status = 'running'
		  RETURNING batch_id`,
		id,
	).Scan(&batchID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("complete scan job: %w", err)
	}
	if batchID != nil {
		if err := recomputeBatchStatus(ctx, tx, *batchID); err != nil {
			return fmt.Errorf("complete: recompute batch: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// Fail transitions running→failed and stores errMsg for audit.
// Like Complete, the status guard makes it idempotent.
func (s *PostgresStore) Fail(ctx context.Context, id uuid.UUID, errMsg string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("fail: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var batchID *uuid.UUID
	err = tx.QueryRow(ctx,
		`UPDATE manage_scan_jobs
		    SET status = 'failed', finished_at = NOW(), error_message = $2
		  WHERE id = $1 AND status = 'running'
		  RETURNING batch_id`,
		id, errMsg,
	).Scan(&batchID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("fail scan job: %w", err)
	}
	if batchID != nil {
		if err := recomputeBatchStatus(ctx, tx, *batchID); err != nil {
			return fmt.Errorf("fail: recompute batch: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// Cancel transitions queued|running→cancelled. Guarded on the non-
// terminal states so terminal-state collisions (e.g. the orchestrator
// completed the scan a microsecond before the admin cancelled it) are
// silent no-ops rather than errors.
func (s *PostgresStore) Cancel(ctx context.Context, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("cancel: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var batchID *uuid.UUID
	err = tx.QueryRow(ctx,
		`UPDATE manage_scan_jobs
		    SET status = 'cancelled', finished_at = NOW()
		  WHERE id = $1 AND status IN ('queued','running')
		  RETURNING batch_id`,
		id,
	).Scan(&batchID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("cancel scan job: %w", err)
	}
	if batchID != nil {
		if err := recomputeBatchStatus(ctx, tx, *batchID); err != nil {
			return fmt.Errorf("cancel: recompute batch: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// PlanEnqueueCount runs the same tag/host expansion query as
// Enqueue but returns only the count, without writing anything. The
// admin handler's soft-buffer scan-cap check calls this to know how
// many jobs a request would create before deciding whether to let
// the caller through.
//
// Returns 0 for an empty TagIDs list — matches Enqueue's short-
// circuit, which also inserts nothing in that case.
func (s *PostgresStore) PlanEnqueueCount(ctx context.Context, req EnqueueReq) (int64, error) {
	if len(req.TagIDs) == 0 {
		return 0, nil
	}
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT h.id) FROM manage_hosts h
		 JOIN manage_host_tags ht ON ht.host_id = h.id
		 WHERE ht.tag_id = ANY($1) AND h.hostname LIKE $2`,
		req.TagIDs, sqlGlob(req.HostFilter),
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("plan enqueue count: %w", err)
	}
	return n, nil
}

// CountCompletedSince returns the number of completed scan jobs for
// the tenant whose finished_at is at or after the supplied timestamp.
// Used by the Manage Server's usage pusher to feed scans/monthly into
// the License Server's soft-buffer cap arithmetic.
//
// The query is bounded by (tenant_id, finished_at) and the existing
// manage_scan_jobs index on status + tenant_id keeps it cheap even on
// a large history table.
func (s *PostgresStore) CountCompletedSince(ctx context.Context, tenantID uuid.UUID, since time.Time) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_scan_jobs
		 WHERE tenant_id = $1 AND status = 'completed' AND finished_at >= $2`,
		tenantID, since,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count completed scan jobs: %w", err)
	}
	return n, nil
}

// CountActive returns the number of scan jobs in queued or running state
// for the given tenant. Used by the deactivation watcher to determine
// whether it is safe to proceed with licence deactivation.
func (s *PostgresStore) CountActive(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_scan_jobs
		 WHERE tenant_id = $1 AND status IN ('queued', 'running')`,
		tenantID,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count active scan jobs: %w", err)
	}
	return n, nil
}

// ReapStale reverts running jobs whose heartbeat is older than
// staleAfter back to queued so another worker can pick them up.
// Returns the number of rows revived.
//
// The staleness threshold is passed through as a TIMESTAMPTZ value
// computed in Go — a Postgres interval literal would work too, but
// this way the unit test can exercise arbitrary durations without
// constructing interval strings.
func (s *PostgresStore) ReapStale(ctx context.Context, staleAfter time.Duration) (int, error) {
	threshold := time.Now().Add(-staleAfter)
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_scan_jobs
		    SET status = 'queued',
		        worker_id = NULL,
		        started_at = NULL,
		        running_heartbeat_at = NULL
		  WHERE status = 'running' AND running_heartbeat_at < $1`,
		threshold,
	)
	if err != nil {
		return 0, fmt.Errorf("reap stale scan jobs: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ListQueued returns up to limit queued jobs whose job_type matches one of
// the given jobTypes and whose scheduled_at is NULL or in the past, ordered
// by enqueued_at ascending (oldest-first, FIFO). Used by the port-survey
// dispatcher to find work without racing with the filesystem orchestrator.
func (s *PostgresStore) ListQueued(ctx context.Context, jobTypes []string, limit int) ([]Job, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+jobSelectCols+`
		FROM manage_scan_jobs
		WHERE status = 'queued'
		  AND job_type = ANY($1)
		  AND (scheduled_at IS NULL OR scheduled_at <= NOW())
		ORDER BY enqueued_at
		LIMIT $2`,
		jobTypes, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list queued scan jobs: %w", err)
	}
	defer rows.Close()
	var jobs []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, fmt.Errorf("scan queued job row: %w", err)
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// ClaimByID atomically transitions a specific queued job to running and
// stamps worker_id + started_at + running_heartbeat_at. Returns ErrNotFound
// when no row with the given id exists, or ErrAlreadyClaimed when the row
// exists but is no longer in 'queued' status (race with another worker or a
// prior cancel/complete). The batch status rollup is applied within the same
// transaction so the batch row reflects 'running' immediately.
func (s *PostgresStore) ClaimByID(ctx context.Context, id uuid.UUID, workerID string) (Job, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Job{}, fmt.Errorf("claim by id: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		UPDATE manage_scan_jobs
		SET status = 'running',
		    worker_id = $2,
		    started_at = NOW(),
		    running_heartbeat_at = NOW()
		WHERE id = $1 AND status = 'queued'
		RETURNING `+jobSelectCols,
		id, workerID,
	)
	j, err := scanJob(row)
	if err == nil {
		if j.BatchID != nil {
			if rerr := recomputeBatchStatus(ctx, tx, *j.BatchID); rerr != nil {
				return Job{}, fmt.Errorf("claim by id: recompute batch: %w", rerr)
			}
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return Job{}, fmt.Errorf("claim by id: commit: %w", cerr)
		}
		return j, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Job{}, fmt.Errorf("claim scan job by id: %w", err)
	}
	// ErrNoRows: distinguish job-not-found from job-already-claimed atomically.
	// Use the open transaction for the existence check to avoid a separate roundtrip.
	var total, queued int
	if qerr := tx.QueryRow(ctx,
		`SELECT COUNT(*) FILTER (WHERE TRUE),
		        COUNT(*) FILTER (WHERE status = 'queued')
		 FROM manage_scan_jobs WHERE id = $1`, id).Scan(&total, &queued); qerr != nil {
		return Job{}, fmt.Errorf("claim by id existence check: %w", qerr)
	}
	if total == 0 {
		return Job{}, ErrNotFound
	}
	return Job{}, ErrAlreadyClaimed
}

// Compile-time assertion: PostgresStore must implement BatchStore.
var _ BatchStore = (*PostgresStore)(nil)

// CountPendingJobs returns the total number of manage_scan_jobs rows in queued
// or running state across all tenants. Used by the EnqueueBatch handler to
// enforce the 10,000-job saturation cap before inserting new work.
func (s *PostgresStore) CountPendingJobs(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_scan_jobs WHERE status IN ('queued','running')`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count pending jobs: %w", err)
	}
	return n, nil
}

func jobTypesToStrings(jts []JobType) []string {
	out := make([]string, len(jts))
	for i, jt := range jts {
		out[i] = string(jt)
	}
	return out
}

// EnqueueBatch creates one manage_scan_batches row and one manage_scan_jobs
// row per spec, atomically. skipped is returned in the response but not
// persisted to the DB.
func (s *PostgresStore) EnqueueBatch(ctx context.Context, req BatchEnqueueReq, specs []JobSpec, skipped []SkippedJob) (BatchEnqueueResp, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return BatchEnqueueResp{}, fmt.Errorf("begin batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var batchID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO manage_scan_batches
		  (tenant_id, job_types, host_ids, profile, max_cpu_pct, max_memory_mb, max_duration_s, schedule_id)
		VALUES ($1, $2::text[], $3::uuid[], $4, $5, $6, $7, $8)
		RETURNING id`,
		req.TenantID,
		jobTypesToStrings(req.JobTypes),
		req.HostIDs,
		string(req.Profile),
		req.MaxCPUPct,
		req.MaxMemoryMB,
		req.MaxDurationS,
		req.ScheduleID,
	).Scan(&batchID)
	if err != nil {
		return BatchEnqueueResp{}, fmt.Errorf("insert batch: %w", err)
	}

	for _, spec := range specs {
		_, err = tx.Exec(ctx, `
			INSERT INTO manage_scan_jobs
			  (tenant_id, host_id, profile, job_type, credentials_ref,
			   batch_id, max_cpu_pct, max_memory_mb, max_duration_s)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			req.TenantID, spec.HostID, string(req.Profile), string(spec.JobType),
			credRefArg(spec.CredentialsRef), batchID,
			req.MaxCPUPct, req.MaxMemoryMB, req.MaxDurationS,
		)
		if err != nil {
			return BatchEnqueueResp{}, fmt.Errorf("insert job for batch: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return BatchEnqueueResp{}, fmt.Errorf("commit batch tx: %w", err)
	}
	return BatchEnqueueResp{
		BatchID:     batchID,
		JobsCreated: len(specs),
		JobsSkipped: skipped,
	}, nil
}

// GetBatch returns a single batch by ID with an aggregated jobs_created count.
// Returns ErrNotFound when the batch does not exist.
func (s *PostgresStore) GetBatch(ctx context.Context, id uuid.UUID) (Batch, error) {
	var b Batch
	var jobTypes []string
	err := s.pool.QueryRow(ctx, `
		SELECT b.id, b.tenant_id, b.job_types, b.host_ids, b.profile,
		       b.max_cpu_pct, b.max_memory_mb, b.max_duration_s,
		       b.schedule_id, b.status, b.enqueued_at, b.finished_at,
		       COUNT(j.id) AS jobs_created
		FROM manage_scan_batches b
		LEFT JOIN manage_scan_jobs j ON j.batch_id = b.id
		WHERE b.id = $1
		GROUP BY b.id`, id,
	).Scan(
		&b.ID, &b.TenantID, &jobTypes, &b.HostIDs, &b.Profile,
		&b.MaxCPUPct, &b.MaxMemoryMB, &b.MaxDurationS,
		&b.ScheduleID, &b.Status, &b.EnqueuedAt, &b.FinishedAt,
		&b.JobsCreated,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Batch{}, ErrNotFound
	}
	if err != nil {
		return Batch{}, err
	}
	for _, jt := range jobTypes {
		b.JobTypes = append(b.JobTypes, JobType(jt))
	}
	return b, nil
}

// ListBatches returns the most recent batches for a tenant, newest first.
// limit <= 0 falls back to 50.
func (s *PostgresStore) ListBatches(ctx context.Context, tenantID uuid.UUID, limit int) ([]Batch, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT b.id, b.tenant_id, b.job_types, b.host_ids, b.profile,
		       b.max_cpu_pct, b.max_memory_mb, b.max_duration_s,
		       b.schedule_id, b.status, b.enqueued_at, b.finished_at,
		       COUNT(j.id) AS jobs_created
		FROM manage_scan_batches b
		LEFT JOIN manage_scan_jobs j ON j.batch_id = b.id
		WHERE b.tenant_id = $1
		GROUP BY b.id
		ORDER BY b.enqueued_at DESC
		LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Batch
	for rows.Next() {
		var b Batch
		var jobTypes []string
		if err := rows.Scan(
			&b.ID, &b.TenantID, &jobTypes, &b.HostIDs, &b.Profile,
			&b.MaxCPUPct, &b.MaxMemoryMB, &b.MaxDurationS,
			&b.ScheduleID, &b.Status, &b.EnqueuedAt, &b.FinishedAt,
			&b.JobsCreated,
		); err != nil {
			return nil, err
		}
		for _, jt := range jobTypes {
			b.JobTypes = append(b.JobTypes, JobType(jt))
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Compile-time assertion: PostgresStore must implement ScheduleStore.
var _ ScheduleStore = (*PostgresStore)(nil)

const schedSelectCols = `id, tenant_id, name, job_types, host_ids, profile, cron_expr,
	max_cpu_pct, max_memory_mb, max_duration_s, enabled, last_run_at, next_run_at, created_at`

func scanSchedule(row pgx.Row) (Schedule, error) {
	var s Schedule
	var jobTypes []string
	err := row.Scan(
		&s.ID, &s.TenantID, &s.Name, &jobTypes, &s.HostIDs, &s.Profile, &s.CronExpr,
		&s.MaxCPUPct, &s.MaxMemoryMB, &s.MaxDurationS,
		&s.Enabled, &s.LastRunAt, &s.NextRunAt, &s.CreatedAt,
	)
	for _, jt := range jobTypes {
		s.JobTypes = append(s.JobTypes, JobType(jt))
	}
	return s, err
}

// nextCronTick parses expr and returns the next fire time after now.
func nextCronTick(expr string) (time.Time, error) {
	sched, err := cron.ParseStandard(expr)
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(time.Now().UTC()), nil
}

func (s *PostgresStore) CreateSchedule(ctx context.Context, req ScheduleReq) (Schedule, error) {
	nextRun, err := nextCronTick(req.CronExpr)
	if err != nil {
		return Schedule{}, fmt.Errorf("invalid cron expression: %w", err)
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO manage_scan_schedules
		  (tenant_id, name, job_types, host_ids, profile, cron_expr,
		   max_cpu_pct, max_memory_mb, max_duration_s, next_run_at)
		VALUES ($1, $2, $3::text[], $4::uuid[], $5, $6, $7, $8, $9, $10)
		RETURNING `+schedSelectCols,
		req.TenantID, req.Name,
		jobTypesToStrings(req.JobTypes), req.HostIDs,
		string(req.Profile), req.CronExpr,
		req.MaxCPUPct, req.MaxMemoryMB, req.MaxDurationS,
		nextRun,
	)
	return scanSchedule(row)
}

func (s *PostgresStore) ListSchedules(ctx context.Context, tenantID uuid.UUID) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+schedSelectCols+`
		   FROM manage_scan_schedules
		  WHERE tenant_id = $1
		  ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Schedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *PostgresStore) PatchSchedule(ctx context.Context, tenantID, id uuid.UUID, req SchedulePatchReq) (Schedule, error) {
	set := []string{}
	args := []any{}
	pos := 1

	if req.Enabled != nil {
		set = append(set, fmt.Sprintf("enabled = $%d", pos))
		args = append(args, *req.Enabled)
		pos++
	}
	if req.Name != nil {
		set = append(set, fmt.Sprintf("name = $%d", pos))
		args = append(args, *req.Name)
		pos++
	}
	if req.CronExpr != nil {
		nextRun, err := nextCronTick(*req.CronExpr)
		if err != nil {
			return Schedule{}, fmt.Errorf("invalid cron expression: %w", err)
		}
		set = append(set, fmt.Sprintf("cron_expr = $%d", pos))
		args = append(args, *req.CronExpr)
		pos++
		set = append(set, fmt.Sprintf("next_run_at = $%d", pos))
		args = append(args, nextRun)
		pos++
	}
	if len(set) == 0 {
		return s.getSchedule(ctx, tenantID, id)
	}
	args = append(args, id, tenantID)
	row := s.pool.QueryRow(ctx,
		`UPDATE manage_scan_schedules SET `+
			strings.Join(set, ", ")+
			` WHERE id = $`+strconv.Itoa(pos)+
			` AND tenant_id = $`+strconv.Itoa(pos+1)+
			` RETURNING `+schedSelectCols,
		args...,
	)
	sc, err := scanSchedule(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Schedule{}, ErrNotFound
	}
	if err != nil {
		return Schedule{}, fmt.Errorf("patch schedule: %w", err)
	}
	return sc, nil
}

func (s *PostgresStore) getSchedule(ctx context.Context, tenantID, id uuid.UUID) (Schedule, error) {
	sc, err := scanSchedule(s.pool.QueryRow(ctx,
		`SELECT `+schedSelectCols+` FROM manage_scan_schedules WHERE id = $1 AND tenant_id = $2`, id, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Schedule{}, ErrNotFound
	}
	return sc, err
}

func (s *PostgresStore) DeleteSchedule(ctx context.Context, tenantID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM manage_scan_schedules WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return fmt.Errorf("delete schedule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimDueSchedules atomically advances next_run_at for all enabled schedules
// past their due time. FOR UPDATE SKIP LOCKED prevents double-fire under
// concurrent ticks.
func (s *PostgresStore) ClaimDueSchedules(ctx context.Context) ([]Schedule, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT `+schedSelectCols+`
		FROM manage_scan_schedules
		WHERE enabled = TRUE AND next_run_at <= NOW()
		FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return nil, err
	}
	var due []Schedule
	for rows.Next() {
		sc, err := scanSchedule(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		due = append(due, sc)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(due) == 0 {
		return []Schedule{}, tx.Commit(ctx)
	}

	now := time.Now().UTC()
	for i := range due {
		parser, err := cron.ParseStandard(due[i].CronExpr)
		if err != nil {
			return nil, fmt.Errorf("claim due schedules: invalid cron %q for schedule %s: %w", due[i].CronExpr, due[i].ID, err)
		}
		nextRun := parser.Next(now)
		if _, err = tx.Exec(ctx,
			`UPDATE manage_scan_schedules SET last_run_at = NOW(), next_run_at = $2 WHERE id = $1`,
			due[i].ID, nextRun,
		); err != nil {
			return nil, err
		}
		due[i].NextRunAt = nextRun
		due[i].LastRunAt = &now
	}
	return due, tx.Commit(ctx)
}
