package scanresults

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/model"
)

// PostgresStore implements Store against a pgx pool. Caller owns the
// pool's lifetime; this package never Close()s it.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore wraps a pgxpool. The caller must have already run
// managestore.Migrate to version >= 4 so manage_scan_results_queue,
// manage_scan_results_dead_letter, manage_push_creds, and
// manage_license_state all exist.
func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// Compile-time interface satisfaction. PostgresStore must also satisfy
// the handler-side QueueDepther narrow interface in scanjobs; that
// check lives at the scanjobs wiring site.
var _ Store = (*PostgresStore)(nil)

// envelope is the JSON shape written into payload_json on Enqueue.
// Matches the Report Server's POST /api/v1/scans contract exactly:
//
//	{
//	  "scan":         { ...ScanResult... },
//	  "submitted_by": { "type": "manage", "id": "<uuid>" }
//	}
//
// Rationale: the Report Server's audit query filters on
// result_json->'submitted_by'->>'type' so the nested object layout is a
// load-bearing contract, not cosmetic. Queue-row bookkeeping (scan_job_id,
// enqueued_at) is captured by the `manage_scan_results_queue` columns
// and intentionally kept OUT of the envelope — the Report Server has no
// use for it and it would pollute result_json at the receiver.
type envelope struct {
	Scan        *model.ScanResult `json:"scan"`
	SubmittedBy submittedBy       `json:"submitted_by"`
}

// submittedBy is the nested provenance block of envelope. Type is the
// caller identity ("manage", "agent", etc.); ID is the Manage-instance
// UUID (or agent machine UUID) that produced the scan.
type submittedBy struct {
	Type string    `json:"type"`
	ID   uuid.UUID `json:"id"`
}

// Enqueue wraps the scan + provenance into an envelope and INSERTs one
// queue row. Returns the DB error verbatim for the orchestrator to
// surface via Store.Fail on the originating job.
//
// scan_job_id + enqueued_at are persisted as columns on the queue row,
// not inside payload_json — see the envelope doc comment. Agent-
// submitted scans pass uuid.Nil; the column is nullable (migration v7)
// and we translate to SQL NULL here so the FK stays intact.
func (s *PostgresStore) Enqueue(ctx context.Context, scanJobID uuid.UUID, sourceType string, sourceID uuid.UUID, scan *model.ScanResult) error {
	env := envelope{
		Scan: scan,
		SubmittedBy: submittedBy{
			Type: sourceType,
			ID:   sourceID,
		},
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal scan envelope: %w", err)
	}
	// uuid.Nil → NULL so the FK (ON DELETE SET NULL) doesn't trip.
	// Any non-zero UUID goes in verbatim.
	var jobArg any
	if scanJobID == uuid.Nil {
		jobArg = nil
	} else {
		jobArg = scanJobID
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO manage_scan_results_queue
		   (scan_job_id, source_type, source_id, payload_json)
		 VALUES ($1, $2, $3, $4)`,
		jobArg, sourceType, sourceID, payload,
	)
	if err != nil {
		return fmt.Errorf("enqueue scan result: %w", err)
	}
	return nil
}

// queueSelectCols keeps the SELECT list consistent across Claim + any
// future single-row lookups. Use string concat so pgx sees a literal.
const queueSelectCols = `id, scan_job_id, source_type, source_id, payload_json, enqueued_at, next_attempt_at, attempt_count, last_error`

// ClaimDue returns due-now rows ordered oldest-first. The WHERE clause
// mirrors the partial index `idx_manage_queue_due` on
// (next_attempt_at) WHERE attempt_count < 10 so the planner picks it
// up.
func (s *PostgresStore) ClaimDue(ctx context.Context, limit int) ([]QueueRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+queueSelectCols+`
		   FROM manage_scan_results_queue
		  WHERE next_attempt_at <= NOW()
		    AND attempt_count < 10
		  ORDER BY enqueued_at
		  LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("claim due queue rows: %w", err)
	}
	defer rows.Close()

	out := []QueueRow{}
	for rows.Next() {
		var r QueueRow
		if err := rows.Scan(
			&r.ID, &r.ScanJobID, &r.SourceType, &r.SourceID,
			&r.PayloadJSON, &r.EnqueuedAt, &r.NextAttemptAt,
			&r.AttemptCount, &r.LastError,
		); err != nil {
			return nil, fmt.Errorf("scan queue row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Delete removes the row after a successful push.
func (s *PostgresStore) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM manage_scan_results_queue WHERE id = $1`, id,
	)
	if err != nil {
		return fmt.Errorf("delete queue row: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Defer bumps attempt_count + 1, sets next_attempt_at, and stamps
// last_error. The count is incremented atomically inside the UPDATE
// so we can't race with another drain tick.
func (s *PostgresStore) Defer(ctx context.Context, id uuid.UUID, nextAttempt time.Time, errMsg string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_scan_results_queue
		    SET attempt_count = attempt_count + 1,
		        next_attempt_at = $2,
		        last_error = $3
		  WHERE id = $1`,
		id, nextAttempt, errMsg,
	)
	if err != nil {
		return fmt.Errorf("defer queue row: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeadLetter copies the row into manage_scan_results_dead_letter and
// DELETEs it from the queue, atomically. The dead-letter table has no
// FK to manage_scan_jobs (see migration v4) so the copy survives job
// deletion.
func (s *PostgresStore) DeadLetter(ctx context.Context, id uuid.UUID, reason string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin dead-letter tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx,
		`INSERT INTO manage_scan_results_dead_letter
		   (id, scan_job_id, source_type, source_id, payload_json,
		    enqueued_at, attempt_count, last_error, dead_letter_reason)
		 SELECT id, scan_job_id, source_type, source_id, payload_json,
		        enqueued_at, attempt_count, last_error, $2
		   FROM manage_scan_results_queue
		  WHERE id = $1`,
		id, reason,
	)
	if err != nil {
		return fmt.Errorf("copy to dead-letter: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	if _, err := tx.Exec(ctx,
		`DELETE FROM manage_scan_results_queue WHERE id = $1`, id,
	); err != nil {
		return fmt.Errorf("delete from queue: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit dead-letter tx: %w", err)
	}
	return nil
}

// QueueDepth is a plain COUNT(*) — cheap on the usual small-to-medium
// queue sizes. If the backpressure threshold turns out to be a hot
// path in production we can swap to an approximate pg_stat reader.
func (s *PostgresStore) QueueDepth(ctx context.Context) (int64, error) {
	var n int64
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_scan_results_queue`,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("queue depth: %w", err)
	}
	return n, nil
}

// OldestAge reports how long the oldest enqueued row has been sitting.
// Empty queue → 0 (the COALESCE below collapses the NULL case).
func (s *PostgresStore) OldestAge(ctx context.Context) (time.Duration, error) {
	var seconds float64
	if err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(enqueued_at))), 0)
		   FROM manage_scan_results_queue`,
	).Scan(&seconds); err != nil {
		return 0, fmt.Errorf("oldest queue row age: %w", err)
	}
	if seconds < 0 {
		seconds = 0
	}
	return time.Duration(seconds * float64(time.Second)), nil
}

// LoadPushCreds returns the singleton manage_push_creds row.
func (s *PostgresStore) LoadPushCreds(ctx context.Context) (PushCreds, error) {
	var c PushCreds
	err := s.pool.QueryRow(ctx,
		`SELECT client_cert_pem, client_key_pem, ca_cert_pem, report_url, tenant_id
		   FROM manage_push_creds WHERE id = 1`,
	).Scan(&c.ClientCertPEM, &c.ClientKeyPEM, &c.CACertPEM, &c.ReportURL, &c.TenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return PushCreds{}, ErrNotFound
	}
	if err != nil {
		return PushCreds{}, fmt.Errorf("load push creds: %w", err)
	}
	return c, nil
}

// SavePushCreds upserts the singleton row (id=1). Batch G calls this
// after the signed-token hand-off to persist the mTLS bundle before
// kicking the drain into action.
func (s *PostgresStore) SavePushCreds(ctx context.Context, creds PushCreds) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO manage_push_creds
		   (id, client_cert_pem, client_key_pem, ca_cert_pem, report_url, tenant_id, updated_at)
		 VALUES (1, $1, $2, $3, $4, $5, NOW())
		 ON CONFLICT (id) DO UPDATE
		   SET client_cert_pem = EXCLUDED.client_cert_pem,
		       client_key_pem  = EXCLUDED.client_key_pem,
		       ca_cert_pem     = EXCLUDED.ca_cert_pem,
		       report_url      = EXCLUDED.report_url,
		       tenant_id       = EXCLUDED.tenant_id,
		       updated_at      = NOW()`,
		creds.ClientCertPEM, creds.ClientKeyPEM, creds.CACertPEM,
		creds.ReportURL, creds.TenantID,
	)
	if err != nil {
		return fmt.Errorf("save push creds: %w", err)
	}
	return nil
}

// RecordPushSuccess stamps manage_license_state after a successful
// push. metricsJSON may be nil if the drain has no metrics body to
// attach (current default).
//
// A missing license_state row (migration v4 not applied, or the row
// was truncated) is treated as an error rather than a silent no-op —
// otherwise the drain would happily succeed with /push-status stuck
// at zero, hiding the misconfiguration.
func (s *PostgresStore) RecordPushSuccess(ctx context.Context, metricsJSON []byte) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_license_state
		    SET last_pushed_at = NOW(),
		        last_pushed_metrics = $1,
		        last_push_error = '',
		        consecutive_failures = 0,
		        updated_at = NOW()
		  WHERE id = 1`,
		metricsJSON,
	)
	if err != nil {
		return fmt.Errorf("record push success: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("record push success: %w: license_state row id=1 missing", ErrNotFound)
	}
	return nil
}

// RecordPushFailure increments consecutive_failures and stashes the
// error string. Called on both retryable (Defer) and non-retryable
// (DeadLetter) push failures so the /push-status endpoint surfaces
// sustained upstream outages even when rows are getting dead-lettered
// straight away.
//
// A missing license_state row is treated as an error — see the note
// on RecordPushSuccess for rationale.
func (s *PostgresStore) RecordPushFailure(ctx context.Context, errMsg string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE manage_license_state
		    SET last_push_error = $1,
		        consecutive_failures = consecutive_failures + 1,
		        updated_at = NOW()
		  WHERE id = 1`,
		errMsg,
	)
	if err != nil {
		return fmt.Errorf("record push failure: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("record push failure: %w: license_state row id=1 missing", ErrNotFound)
	}
	return nil
}

// LoadLicenseState merges queue diagnostics (depth, oldest age) with
// the license-state singleton into a single Status struct ready to
// serialise onto /api/v1/admin/push-status.
func (s *PostgresStore) LoadLicenseState(ctx context.Context) (Status, error) {
	depth, err := s.QueueDepth(ctx)
	if err != nil {
		return Status{}, err
	}
	age, err := s.OldestAge(ctx)
	if err != nil {
		return Status{}, err
	}

	var (
		st          Status
		lastPushed  *time.Time
		metricsRaw  []byte // unused at wire level; kept for future extension
		lastErr     string
		consecutive int
	)
	_ = metricsRaw
	err = s.pool.QueryRow(ctx,
		`SELECT last_pushed_at, last_pushed_metrics, last_push_error, consecutive_failures
		   FROM manage_license_state WHERE id = 1`,
	).Scan(&lastPushed, &metricsRaw, &lastErr, &consecutive)
	if errors.Is(err, pgx.ErrNoRows) {
		// Mirror LoadPushCreds: callers (the /push-status handler +
		// startScannerPipeline) use errors.Is(err, ErrNotFound) to tell
		// "not-yet-migrated / fresh install" from real DB faults.
		return Status{}, ErrNotFound
	}
	if err != nil {
		return Status{}, fmt.Errorf("load license state: %w", err)
	}

	st.QueueDepth = depth
	st.OldestRowAgeSeconds = int64(age / time.Second)
	st.LastPushError = lastErr
	st.ConsecutiveFailures = consecutive
	st.LastPushedAt = lastPushed
	return st, nil
}
