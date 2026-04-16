// Package jobqueue provides a generic engine-job-queue backed by a
// PostgreSQL table following the claim/ack/reclaim pattern used by
// discovery, credentials, and scanjobs bounded contexts.
//
// Each queue table is expected to follow a column convention:
//   - id UUID PRIMARY KEY
//   - org_id UUID (for cancel's org scope)
//   - engine_id / status / claimed_at / requested_at (configurable names)
//   - completed_at TIMESTAMPTZ (configurable name, set on finish)
//   - error TEXT (set on finish)
//
// The Queue struct pre-builds SQL at construction time so runtime
// methods execute a single parameterised query with no string
// interpolation on the hot path.
package jobqueue

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

// Sentinel errors returned by Queue methods. Consumers should wrap or
// translate these into their own domain sentinels if handler-layer
// contracts depend on specific error identities.
var (
	// ErrNotFound means the job ID does not exist (or is not visible
	// to the caller's org for Cancel).
	ErrNotFound = errors.New("jobqueue: not found")

	// ErrNotOwned means the Finish caller's engine ID does not match
	// the engine_id column on the row.
	ErrNotOwned = errors.New("jobqueue: not owned by this engine")

	// ErrAlreadyTerminal means the job is already in a terminal state
	// and cannot be finished again.
	ErrAlreadyTerminal = errors.New("jobqueue: already in terminal state")

	// ErrNotCancellable means the job exists but is not in the queued
	// state and therefore cannot be cancelled by an operator.
	ErrNotCancellable = errors.New("jobqueue: not cancellable")
)

// Config defines the table and column names for a specific queue.
// All fields are required except CompletedAtColumn which defaults to
// "completed_at".
type Config struct {
	Table             string   // e.g. "discovery_jobs", "scan_jobs"
	EngineIDColumn    string   // e.g. "engine_id"
	StatusColumn      string   // e.g. "status"
	ClaimedAtColumn   string   // e.g. "claimed_at"
	RequestedAtColumn string   // e.g. "requested_at"
	CompletedAtColumn string   // e.g. "completed_at" or "acked_at"
	QueuedStatus      string   // e.g. "queued"
	ClaimedStatus     string   // e.g. "claimed"
	TerminalStatuses  []string // e.g. ["completed", "failed", "cancelled"]
}

// Queue is a generic engine-job-queue backed by a single PostgreSQL
// table. It provides ID-only claim, finish, reclaim, and cancel — each
// consumer wraps these with type-safe enrichment. Use New to construct.
type Queue struct {
	pool *pgxpool.Pool
	cfg  Config

	// Pre-built SQL (computed once at construction).
	claimSelectSQL   string
	claimUpdateSQL   string
	finishSQL        string
	reclaimSQL       string
	cancelSQL        string
	disambiguateSQL  string
	cancelLookupSQL  string
}

// New constructs a Queue with pre-built SQL for the given config.
func New(pool *pgxpool.Pool, cfg Config) *Queue {
	if cfg.CompletedAtColumn == "" {
		cfg.CompletedAtColumn = "completed_at"
	}
	q := &Queue{pool: pool, cfg: cfg}
	q.buildSQL()
	return q
}

// Pool returns the underlying connection pool so consumers can run
// domain-specific enrichment queries without holding a second pool
// reference.
func (q *Queue) Pool() *pgxpool.Pool {
	return q.pool
}

func (q *Queue) buildSQL() {
	terminalList := buildTerminalList(q.cfg.TerminalStatuses)

	// ClaimNextID: select the oldest queued row for this engine, lock it.
	q.claimSelectSQL = fmt.Sprintf(
		`SELECT id FROM %s WHERE %s = $1 AND %s = '%s' ORDER BY %s ASC FOR UPDATE SKIP LOCKED LIMIT 1`,
		q.cfg.Table, q.cfg.EngineIDColumn, q.cfg.StatusColumn, q.cfg.QueuedStatus, q.cfg.RequestedAtColumn,
	)

	// ClaimNextID: flip the row to claimed.
	q.claimUpdateSQL = fmt.Sprintf(
		`UPDATE %s SET %s = '%s', %s = NOW() WHERE id = $1 AND %s = '%s'`,
		q.cfg.Table, q.cfg.StatusColumn, q.cfg.ClaimedStatus, q.cfg.ClaimedAtColumn,
		q.cfg.StatusColumn, q.cfg.QueuedStatus,
	)

	// Finish: set terminal status + error + completed_at. Guards on
	// engine ownership and non-terminal current status.
	q.finishSQL = fmt.Sprintf(
		`UPDATE %s SET %s = $1, error = NULLIF($2, ''), %s = NOW() WHERE id = $3 AND %s = $4 AND %s NOT IN (%s)`,
		q.cfg.Table, q.cfg.StatusColumn, q.cfg.CompletedAtColumn,
		q.cfg.EngineIDColumn, q.cfg.StatusColumn, terminalList,
	)

	// ReclaimStale: flip claimed/running rows older than cutoff back
	// to queued.
	q.reclaimSQL = fmt.Sprintf(
		`UPDATE %s SET %s = '%s', %s = NULL WHERE %s IN ('%s','running') AND %s IS NOT NULL AND %s < $1`,
		q.cfg.Table, q.cfg.StatusColumn, q.cfg.QueuedStatus, q.cfg.ClaimedAtColumn,
		q.cfg.StatusColumn, q.cfg.ClaimedStatus, q.cfg.ClaimedAtColumn, q.cfg.ClaimedAtColumn,
	)

	// Cancel: flip a queued row to cancelled.
	q.cancelSQL = fmt.Sprintf(
		`UPDATE %s SET %s = 'cancelled', %s = NOW() WHERE org_id = $1 AND id = $2 AND %s = '%s'`,
		q.cfg.Table, q.cfg.StatusColumn, q.cfg.CompletedAtColumn, q.cfg.StatusColumn, q.cfg.QueuedStatus,
	)

	// Disambiguate: on Finish 0-rows, figure out why.
	q.disambiguateSQL = fmt.Sprintf(
		`SELECT %s, %s FROM %s WHERE id = $1`,
		q.cfg.EngineIDColumn, q.cfg.StatusColumn, q.cfg.Table,
	)

	// Cancel lookup: on Cancel 0-rows, figure out why.
	q.cancelLookupSQL = fmt.Sprintf(
		`SELECT %s FROM %s WHERE org_id = $1 AND id = $2`,
		q.cfg.StatusColumn, q.cfg.Table,
	)
}

// buildTerminalList produces a SQL-safe comma-separated list of quoted
// terminal statuses for use in NOT IN (...) clauses.
func buildTerminalList(statuses []string) string {
	parts := make([]string, len(statuses))
	for i, s := range statuses {
		parts[i] = "'" + s + "'"
	}
	return strings.Join(parts, ",")
}

// ClaimNextID atomically picks the oldest queued job for this engine
// and flips it to claimed. Returns the job ID + true, or uuid.Nil +
// false when no queued work is available. Callers enrich the ID into
// a typed payload separately.
func (q *Queue) ClaimNextID(ctx context.Context, engineID uuid.UUID) (uuid.UUID, bool, error) {
	tx, err := q.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var id uuid.UUID
	err = tx.QueryRow(ctx, q.claimSelectSQL, engineID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, err
	}

	ct, err := tx.Exec(ctx, q.claimUpdateSQL, id)
	if err != nil {
		return uuid.Nil, false, err
	}
	if ct.RowsAffected() == 0 {
		return uuid.Nil, false, nil // lost race
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, false, err
	}
	return id, true, nil
}

// Finish transitions a job to a terminal state. Checks engine
// ownership and rejects if already terminal.
func (q *Queue) Finish(ctx context.Context, engineID, jobID uuid.UUID, status, errMsg string) error {
	ct, err := q.pool.Exec(ctx, q.finishSQL, status, errMsg, jobID, engineID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return q.disambiguate(ctx, engineID, jobID)
	}
	return nil
}

// ReclaimStale flips claimed/running jobs older than cutoff back to
// queued. Satisfies the Reclaimer interface for StaleReaper.
func (q *Queue) ReclaimStale(ctx context.Context, cutoff time.Time) error {
	_, err := q.pool.Exec(ctx, q.reclaimSQL, cutoff)
	return err
}

// Cancel transitions a queued job to cancelled. Returns
// ErrNotCancellable if the job is not in queued state, ErrNotFound if
// the (org, id) pair does not exist.
func (q *Queue) Cancel(ctx context.Context, orgID, jobID uuid.UUID) error {
	ct, err := q.pool.Exec(ctx, q.cancelSQL, orgID, jobID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		var status string
		err := q.pool.QueryRow(ctx, q.cancelLookupSQL, orgID, jobID).Scan(&status)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return ErrNotCancellable
	}
	return nil
}

func (q *Queue) disambiguate(ctx context.Context, engineID, jobID uuid.UUID) error {
	var curEngineID uuid.UUID
	var curStatus string
	err := q.pool.QueryRow(ctx, q.disambiguateSQL, jobID).Scan(&curEngineID, &curStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if curEngineID != engineID {
		return ErrNotOwned
	}
	return ErrAlreadyTerminal
}
