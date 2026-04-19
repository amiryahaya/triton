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
const jobSelectCols = `id, tenant_id, zone_id, host_id, profile, credentials_ref, status, cancel_requested, COALESCE(worker_id,''), enqueued_at, started_at, finished_at, running_heartbeat_at, progress_text, error_message`

// defaultListLimit is the fallback page size for List when a non-positive
// limit is supplied. 100 keeps API responses bounded without operator
// configuration; admin UIs paginate explicitly when they need more.
const defaultListLimit = 100

// scanJob decodes a single row into a Job. ZoneID and HostID are
// nullable in DB (per migration v6 for audit preservation across
// zone/host deletes) but Job models them as non-pointer uuid.UUID —
// historical rows with NULL zone/host surface as uuid.Nil.
func scanJob(row pgx.Row) (Job, error) {
	var (
		j        Job
		credRef  *uuid.UUID
		zoneID   *uuid.UUID
		hostID   *uuid.UUID
		workerID string
	)
	if err := row.Scan(
		&j.ID, &j.TenantID, &zoneID, &hostID, &j.Profile, &credRef,
		&j.Status, &j.CancelRequested, &workerID, &j.EnqueuedAt,
		&j.StartedAt, &j.FinishedAt, &j.RunningHeartbeatAt,
		&j.ProgressText, &j.ErrorMessage,
	); err != nil {
		return Job{}, err
	}
	if zoneID != nil {
		j.ZoneID = *zoneID
	}
	if hostID != nil {
		j.HostID = *hostID
	}
	j.CredentialsRef = credRef
	j.WorkerID = workerID
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

// Enqueue expands (ZoneIDs, HostFilter) into Host rows then inserts
// one job per host in a single transaction. All-or-nothing semantics:
// any failure mid-batch rolls back the whole set.
//
// Saturation checking against the downstream result queue is
// intentionally NOT done here (see package doc for rationale) — it
// belongs in the scanresults package and is wired at the handler
// call-site.
func (s *PostgresStore) Enqueue(ctx context.Context, req EnqueueReq) ([]Job, error) {
	if len(req.ZoneIDs) == 0 {
		return []Job{}, nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin enqueue tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx,
		`SELECT id FROM manage_hosts WHERE zone_id = ANY($1) AND hostname LIKE $2`,
		req.ZoneIDs, sqlGlob(req.HostFilter),
	)
	if err != nil {
		return nil, fmt.Errorf("expand zones to hosts: %w", err)
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
			`INSERT INTO manage_scan_jobs (tenant_id, zone_id, host_id, profile, credentials_ref)
			 SELECT $1, h.zone_id, h.id, $2, $3 FROM manage_hosts h WHERE h.id = $4
			 RETURNING `+jobSelectCols,
			req.TenantID, string(req.Profile), credRefArg(req.CredentialsRef), hid,
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

// PlanEnqueueCount runs the same zone/host expansion query as
// Enqueue but returns only the count, without writing anything. The
// admin handler's soft-buffer scan-cap check calls this to know how
// many jobs a request would create before deciding whether to let
// the caller through.
//
// Returns 0 for an empty ZoneIDs list — matches Enqueue's short-
// circuit, which also inserts nothing in that case.
func (s *PostgresStore) PlanEnqueueCount(ctx context.Context, req EnqueueReq) (int64, error) {
	if len(req.ZoneIDs) == 0 {
		return 0, nil
	}
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_hosts WHERE zone_id = ANY($1) AND hostname LIKE $2`,
		req.ZoneIDs, sqlGlob(req.HostFilter),
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("plan enqueue count: %w", err)
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
