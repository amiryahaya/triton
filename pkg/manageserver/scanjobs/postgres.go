package scanjobs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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
// worker_id / started_at.
func (s *PostgresStore) ClaimNext(ctx context.Context, workerID string) (Job, bool, error) {
	row := s.pool.QueryRow(ctx,
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
	return j, true, nil
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

// Complete transitions running→completed. The status guard makes the
// call idempotent: a second Complete after Cancel is a silent no-op
// (RowsAffected=0) but not an error — terminal-state collisions are
// expected in the orchestrator's cancel race.
func (s *PostgresStore) Complete(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE manage_scan_jobs
		    SET status = 'completed', finished_at = NOW()
		  WHERE id = $1 AND status = 'running'`,
		id,
	)
	if err != nil {
		return fmt.Errorf("complete scan job: %w", err)
	}
	return nil
}

// Fail transitions running→failed and stores errMsg for audit.
// Like Complete, the status guard makes it idempotent.
func (s *PostgresStore) Fail(ctx context.Context, id uuid.UUID, errMsg string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE manage_scan_jobs
		    SET status = 'failed', finished_at = NOW(), error_message = $2
		  WHERE id = $1 AND status = 'running'`,
		id, errMsg,
	)
	if err != nil {
		return fmt.Errorf("fail scan job: %w", err)
	}
	return nil
}

// Cancel transitions queued|running→cancelled. Guarded on the non-
// terminal states so terminal-state collisions (e.g. the orchestrator
// completed the scan a microsecond before the admin cancelled it) are
// silent no-ops rather than errors.
func (s *PostgresStore) Cancel(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE manage_scan_jobs
		    SET status = 'cancelled', finished_at = NOW()
		  WHERE id = $1 AND status IN ('queued','running')`,
		id,
	)
	if err != nil {
		return fmt.Errorf("cancel scan job: %w", err)
	}
	return nil
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
// prior cancel/complete).
func (s *PostgresStore) ClaimByID(ctx context.Context, id uuid.UUID, workerID string) (Job, error) {
	row := s.pool.QueryRow(ctx, `
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
		return j, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Job{}, fmt.Errorf("claim scan job by id: %w", err)
	}
	// ErrNoRows: distinguish job-not-found from job-already-claimed atomically.
	var total, queued int
	if qerr := s.pool.QueryRow(ctx,
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
		return BatchEnqueueResp{}, err
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
