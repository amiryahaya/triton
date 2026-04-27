package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/model"
)

// PostgresStore implements Store using PostgreSQL via pgx v5.
type PostgresStore struct {
	pool      *pgxpool.Pool
	encryptor atomic.Pointer[Encryptor] // optional; nil load = no at-rest encryption

	// Backfill counters — read by the metrics handler, written by
	// BackfillFindings. Lock-free atomics so the metrics scrape path
	// costs nothing on every request. Analytics Phase 1 + polish
	// follow-ups (/pensive:full-review B6, Arch-3).
	backfillScansSucceeded   atomic.Uint64 // incremented on successful extraction
	backfillScansFailed      atomic.Uint64 // incremented when a blob fails to decode
	backfillScansInitial     atomic.Uint64 // snapshot of COUNT(*) awaiting backfill at start
	backfillLastProgressUnix atomic.Int64  // unix seconds of last batch-loop iteration
}

// BackfillScansSucceeded returns the running count of scans that were
// successfully processed by the findings backfill loop. Exposed as
// triton_backfill_scans_succeeded_total. Analytics Phase 1.
func (s *PostgresStore) BackfillScansSucceeded() uint64 {
	return s.backfillScansSucceeded.Load()
}

// BackfillScansFailed returns the running count of scans that failed
// extraction and were marked to skip (e.g. corrupt blobs). Exposed as
// triton_backfill_scans_failed_total. Analytics Phase 1.
func (s *PostgresStore) BackfillScansFailed() uint64 {
	return s.backfillScansFailed.Load()
}

// BackfillScansInitial returns the snapshot of unbackfilled scans
// taken once at the start of BackfillFindings. Zero if the goroutine
// has not yet started, or if the initial count query failed.
// Operators compute remaining work as:
//
//	remaining = initial - (succeeded + failed)
//
// /pensive:full-review action item Arch-3.
func (s *PostgresStore) BackfillScansInitial() uint64 {
	return s.backfillScansInitial.Load()
}

// BackfillLastProgress returns the most recent time a batch iteration
// advanced during BackfillFindings. Returns the zero time if the
// goroutine has not yet started or has finished. Operators use this
// to distinguish "backfill is progressing slowly through a large
// catalog" from "backfill is wedged on an uncancellable query".
// /pensive:full-review action item Arch-3.
func (s *PostgresStore) BackfillLastProgress() time.Time {
	unix := s.backfillLastProgressUnix.Load()
	if unix == 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0).UTC()
}

// SetEncryptor enables at-rest AES-256-GCM encryption for the scans
// result_json column. New writes are encrypted; existing plain-text
// rows remain readable via the envelope-detection logic in Encryptor.
// Disabling encryption after rows have been encrypted is a one-way
// door without the key — don't rotate keys without a migration.
//
// Thread-safe via atomic.Pointer — safe to call at any time, even
// while other goroutines are handling SaveScan/GetScan. (D4 fix from
// the Phase 2 review.)
func (s *PostgresStore) SetEncryptor(enc *Encryptor) {
	s.encryptor.Store(enc)
}

// loadEncryptor returns the current encryptor, or nil if unset.
// Callers use the nil-check pattern directly after this.
func (s *PostgresStore) loadEncryptor() *Encryptor {
	return s.encryptor.Load()
}

// Pool returns the underlying pgxpool.Pool. Exposed so integration
// tests can run ad-hoc SQL that the Store interface does not cover
// (e.g., Phase 2 tests that update organizations.executive_target_percent
// via direct UPDATE to exercise the per-org config path). Not part
// of the Store interface — prefer interface methods in production.
func (s *PostgresStore) Pool() *pgxpool.Pool {
	return s.pool
}

// QueryColumnTestOnly returns the data_type of (table, column) from
// information_schema.columns, or an empty string if the column does not
// exist. Used by integration tests to assert schema migrations. Not part
// of the Store interface — never call from production code.
func (s *PostgresStore) QueryColumnTestOnly(ctx context.Context, table, column string) (string, error) {
	var dt string
	err := s.pool.QueryRow(ctx, `
		SELECT data_type FROM information_schema.columns
		WHERE table_schema = current_schema()
		  AND table_name   = $1
		  AND column_name  = $2`, table, column).Scan(&dt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return dt, err
}

// NewPostgresStoreFromPool constructs a PostgresStore around an existing
// pgxpool.Pool. Introduced in B2.1 so Manage Server can share one pool
// between pkg/store and the scan-handler subpackages (scanjobs,
// credentials, discovery, agentpush) which take *pgxpool.Pool directly.
//
// **Pool ownership.** The caller owns the pool's lifecycle. Do NOT call
// Close() on the returned store when the pool is shared with other
// packages — PostgresStore.Close() unconditionally closes the underlying
// pool and would pull it out from under the other consumers. Close the
// pool yourself when the last user is done. This contrasts with
// NewPostgresStore below, which is the sole owner of its pool and whose
// Close() method IS the correct teardown path.
//
// The caller MUST have run Migrate(ctx, pool) (or gone through
// NewPostgresStore which does this) before using the returned store, or
// reads/writes will fail against a schema that doesn't exist.
func NewPostgresStoreFromPool(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// NewPostgresStore connects to PostgreSQL, runs any pending schema
// migrations, and returns a fully-initialised store. Convenience wrapper
// over pgxpool.New + Migrate + NewPostgresStoreFromPool — prefer this for
// new code that owns the full lifecycle. Use NewPostgresStoreFromPool when
// you need to share a pool with another package.
func NewPostgresStore(ctx context.Context, connStr string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgresql: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgresql: %w", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return NewPostgresStoreFromPool(pool), nil
}

// Migrate applies any unapplied schema migrations against the given pool.
// Safe to call from any caller that owns a pgxpool.Pool against the target
// database. Uses an advisory lock (id 7355693421) to serialise concurrent
// migrators on the same database; the lock is released before return.
// The advisory lock is per-database, so separate PostgreSQL databases
// (e.g. Manage Server's DB vs Report Server's DB) do not contend on this
// id even when both run Migrate concurrently. Idempotent — running twice
// against the same DB is a no-op for already-applied migrations.
//
// Introduced in B2.1 so Manage Server can run the same migration set against
// its own pool without going through NewPostgresStore. Report Server's
// NewPostgresStore now delegates here.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER NOT NULL UNIQUE,
		applied_at TIMESTAMPTZ NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creating schema_version table: %w", err)
	}

	// Acquire a dedicated connection for advisory lock to prevent concurrent migrations.
	// Advisory locks are session-level — we must hold the same connection for lock + migrations.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquiring connection for migration: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(7355693421)"); err != nil {
		return fmt.Errorf("acquiring migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock(7355693421)")
	}()

	var current int
	err = conn.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&current)
	if err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	for i := current; i < len(migrations); i++ {
		version := i + 1

		tx, err := conn.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin tx for migration %d: %w", version, err)
		}

		if _, err := tx.Exec(ctx, migrations[i]); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %d: %w", version, err)
		}

		if _, err := tx.Exec(ctx,
			"INSERT INTO schema_version (version, applied_at) VALUES ($1, NOW())",
			version,
		); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("recording migration %d: %w", version, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}

	return nil
}

// SaveScan persists a scan result to the database.
func (s *PostgresStore) SaveScan(ctx context.Context, result *model.ScanResult) error {
	if result == nil {
		return fmt.Errorf("cannot save nil scan result")
	}
	if result.ID == "" {
		return fmt.Errorf("scan result must have an ID")
	}

	blob, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshalling scan result: %w", err)
	}

	// At-rest encryption (Phase 2.7). The Encryptor wraps the JSON in
	// an AES-256-GCM envelope that's itself valid JSON, so the JSONB
	// column stores it transparently. No-op when encryptor is nil.
	if enc := s.loadEncryptor(); enc != nil {
		encrypted, encErr := enc.Encrypt(blob)
		if encErr != nil {
			return fmt.Errorf("encrypting scan result: %w", encErr)
		}
		blob = encrypted
	}

	// Use nil for empty org_id to store SQL NULL.
	var orgID *string
	if result.OrgID != "" {
		orgID = &result.OrgID
	}

	_, err = s.pool.Exec(ctx,
		`INSERT INTO scans
		 (id, hostname, timestamp, profile, total_findings, safe, transitional, deprecated, unsafe, result_json, org_id, scan_source)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		 ON CONFLICT (id) DO UPDATE SET
		   hostname = $2, timestamp = $3, profile = $4,
		   total_findings = $5, safe = $6, transitional = $7,
		   deprecated = $8, unsafe = $9, result_json = $10, org_id = $11, scan_source = $12`,
		result.ID,
		result.Metadata.Hostname,
		result.Metadata.Timestamp.UTC(),
		result.Metadata.ScanProfile,
		result.Summary.TotalFindings,
		result.Summary.Safe,
		result.Summary.Transitional,
		result.Summary.Deprecated,
		result.Summary.Unsafe,
		blob,
		orgID,
		string(result.Metadata.Source),
	)
	if err != nil {
		return fmt.Errorf("saving scan: %w", err)
	}
	return nil
}

// GetScan retrieves a scan result by ID.
// If orgID is non-empty, the scan must belong to that org (tenant isolation).
func (s *PostgresStore) GetScan(ctx context.Context, id, orgID string) (*model.ScanResult, error) {
	query := "SELECT result_json FROM scans WHERE id = $1"
	args := []any{id}
	if orgID != "" {
		query += " AND org_id = $2"
		args = append(args, orgID)
	}

	var blob []byte
	err := s.pool.QueryRow(ctx, query, args...).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "scan", ID: id}
	}
	if err != nil {
		return nil, fmt.Errorf("querying scan: %w", err)
	}

	// At-rest decryption (Phase 2.7). Decrypt is a no-op for rows
	// written before encryption was enabled (envelope detection falls
	// through to pass-through).
	if enc := s.loadEncryptor(); enc != nil {
		decrypted, decErr := enc.Decrypt(blob)
		if decErr != nil {
			return nil, fmt.Errorf("decrypting scan result: %w", decErr)
		}
		blob = decrypted
	}

	var result model.ScanResult
	if err := json.Unmarshal(blob, &result); err != nil {
		return nil, fmt.Errorf("unmarshalling scan result: %w", err)
	}
	return &result, nil
}

// ListScans returns scan summaries matching the given filter.
func (s *PostgresStore) ListScans(ctx context.Context, filter ScanFilter) ([]ScanSummary, error) {
	query := `SELECT id, hostname, timestamp, profile, scan_source,
	                 total_findings, safe, transitional, deprecated, unsafe
	          FROM scans WHERE 1=1`
	var args []any
	paramIdx := 0

	if filter.OrgID != "" {
		paramIdx++
		query += fmt.Sprintf(" AND org_id = $%d", paramIdx)
		args = append(args, filter.OrgID)
	}
	if filter.Hostname != "" {
		paramIdx++
		query += fmt.Sprintf(" AND hostname = $%d", paramIdx)
		args = append(args, filter.Hostname)
	}
	if filter.Profile != "" {
		paramIdx++
		query += fmt.Sprintf(" AND profile = $%d", paramIdx)
		args = append(args, filter.Profile)
	}
	if filter.Source != "" {
		paramIdx++
		query += fmt.Sprintf(" AND LOWER(scan_source) = LOWER($%d)", paramIdx)
		args = append(args, filter.Source)
	}
	if filter.After != nil {
		paramIdx++
		query += fmt.Sprintf(" AND timestamp >= $%d", paramIdx)
		args = append(args, filter.After.UTC())
	}
	if filter.Before != nil {
		paramIdx++
		query += fmt.Sprintf(" AND timestamp <= $%d", paramIdx)
		args = append(args, filter.Before.UTC())
	}

	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		paramIdx++
		query += fmt.Sprintf(" LIMIT $%d", paramIdx)
		args = append(args, filter.Limit)
	}

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing scans: %w", err)
	}
	defer rows.Close()

	summaries := make([]ScanSummary, 0)
	for rows.Next() {
		var ss ScanSummary
		var src string
		if err := rows.Scan(&ss.ID, &ss.Hostname, &ss.Timestamp, &ss.Profile, &src,
			&ss.TotalFindings, &ss.Safe, &ss.Transitional, &ss.Deprecated, &ss.Unsafe,
		); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		ss.Source = model.ScanSource(src)
		summaries = append(summaries, ss)
	}
	return summaries, rows.Err()
}

// DeleteScan removes a scan by ID.
// If orgID is non-empty, the scan must belong to that org (tenant isolation).
func (s *PostgresStore) DeleteScan(ctx context.Context, id, orgID string) error {
	query := "DELETE FROM scans WHERE id = $1"
	args := []any{id}
	if orgID != "" {
		query += " AND org_id = $2"
		args = append(args, orgID)
	}

	tag, err := s.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("deleting scan: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "scan", ID: id}
	}
	return nil
}

// GetFileHash retrieves the stored hash and last-scanned time for a file path.
func (s *PostgresStore) GetFileHash(ctx context.Context, path string) (string, time.Time, error) {
	var hash string
	var scannedAt time.Time
	err := s.pool.QueryRow(ctx,
		"SELECT hash, scanned_at FROM file_hashes WHERE path = $1", path,
	).Scan(&hash, &scannedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, &ErrNotFound{Resource: "file_hash", ID: path}
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("querying file hash: %w", err)
	}
	return hash, scannedAt, nil
}

// SetFileHash stores (or updates) the hash for a file path.
func (s *PostgresStore) SetFileHash(ctx context.Context, path, hash string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO file_hashes (path, hash, scanned_at)
		 VALUES ($1, $2, NOW())
		 ON CONFLICT (path) DO UPDATE SET hash = $2, scanned_at = NOW()`,
		path, hash,
	)
	if err != nil {
		return fmt.Errorf("setting file hash: %w", err)
	}
	return nil
}

// PruneStaleHashes removes file hash entries older than the given time.
func (s *PostgresStore) PruneStaleHashes(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx,
		"DELETE FROM file_hashes WHERE scanned_at < $1",
		before.UTC(),
	)
	if err != nil {
		return fmt.Errorf("pruning stale hashes: %w", err)
	}
	return nil
}

// TruncateAll deletes all data from all tables.
// Intended for test cleanup only.
func (s *PostgresStore) TruncateAll(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin truncate transaction: %w", err)
	}
	// Order matters for FK cascades. Sessions → users → organizations
	// is the safest topological order even though CASCADE would handle it.
	// audit_events has no FK dependencies; list it first for clarity.
	tables := []string{"audit_events", "sessions", "users", "organizations", "scans", "file_hashes"}
	for _, t := range tables {
		if _, err := tx.Exec(ctx, "DELETE FROM "+t); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
	}
	return tx.Commit(ctx)
}

// PruneScansBefore deletes scans whose timestamp is strictly before
// cutoff. Returns the number of rows deleted. Used by RetentionPruner
// in pkg/server to enforce per-deployment data-retention limits.
// Not on the Store interface because pruning is a Report-Server
// operational concern, not a core store abstraction.
func (s *PostgresStore) PruneScansBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM scans WHERE timestamp < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("pruning scans: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Close releases the connection pool.
func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// SchemaVersion returns the current schema version.
func (s *PostgresStore) SchemaVersion(ctx context.Context) (int, error) {
	var version int
	err := s.pool.QueryRow(ctx,
		"SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	return version, err
}

// FileHashStats returns summary statistics about the file hash cache.
func (s *PostgresStore) FileHashStats(ctx context.Context) (count int, oldest, newest time.Time, err error) {
	var oldestPtr, newestPtr *time.Time
	err = s.pool.QueryRow(ctx,
		`SELECT COUNT(*), MIN(scanned_at), MAX(scanned_at) FROM file_hashes`,
	).Scan(&count, &oldestPtr, &newestPtr)
	if err != nil {
		return 0, time.Time{}, time.Time{}, fmt.Errorf("querying file hash stats: %w", err)
	}
	if count > 0 && oldestPtr != nil && newestPtr != nil {
		oldest = *oldestPtr
		newest = *newestPtr
	}
	return count, oldest, newest, nil
}

// ---------------------------------------------------------------------------
// AgentStore implementation
// ---------------------------------------------------------------------------

// UpsertAgent creates the row on first-seen or updates
// hostname/os/arch + last_seen_at on subsequent polls.
func (s *PostgresStore) UpsertAgent(ctx context.Context, a *AgentRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (tenant_id, machine_id, hostname, os, arch)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, machine_id) DO UPDATE SET
			hostname     = EXCLUDED.hostname,
			os           = EXCLUDED.os,
			arch         = EXCLUDED.arch,
			last_seen_at = NOW()
	`, a.TenantID, a.MachineID, a.Hostname, a.OS, a.Arch)
	if err != nil {
		return fmt.Errorf("upserting agent: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetAgent(ctx context.Context, tenantID, machineID string) (*AgentRecord, error) {
	var a AgentRecord
	var paused pgtype.Timestamptz
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, machine_id, hostname, os, arch,
		       first_seen_at, last_seen_at, paused_until
		FROM agents
		WHERE tenant_id = $1 AND machine_id = $2`,
		tenantID, machineID,
	).Scan(&a.TenantID, &a.MachineID, &a.Hostname, &a.OS, &a.Arch,
		&a.FirstSeenAt, &a.LastSeenAt, &paused)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "agent", ID: machineID}
	}
	if err != nil {
		return nil, fmt.Errorf("getting agent: %w", err)
	}
	if paused.Valid {
		a.PausedUntil = paused.Time
	}
	return &a, nil
}

func (s *PostgresStore) ListAgentsByTenant(ctx context.Context, tenantID string, limit int) ([]AgentRecord, error) {
	q := `
		SELECT tenant_id, machine_id, hostname, os, arch,
		       first_seen_at, last_seen_at, paused_until
		FROM agents
		WHERE tenant_id = $1
		ORDER BY last_seen_at DESC`
	args := []any{tenantID}
	if limit > 0 {
		q += " LIMIT $2"
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing agents: %w", err)
	}
	defer rows.Close()
	out := []AgentRecord{}
	for rows.Next() {
		var a AgentRecord
		var paused pgtype.Timestamptz
		if err := rows.Scan(&a.TenantID, &a.MachineID, &a.Hostname, &a.OS, &a.Arch,
			&a.FirstSeenAt, &a.LastSeenAt, &paused); err != nil {
			return nil, fmt.Errorf("scanning agent: %w", err)
		}
		if paused.Valid {
			a.PausedUntil = paused.Time
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SetAgentPausedUntil(ctx context.Context, tenantID, machineID string, until time.Time) error {
	res, err := s.pool.Exec(ctx, `
		UPDATE agents SET paused_until = $3
		WHERE tenant_id = $1 AND machine_id = $2`,
		tenantID, machineID, until)
	if err != nil {
		return fmt.Errorf("setting paused_until: %w", err)
	}
	if res.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "agent", ID: machineID}
	}
	return nil
}

func (s *PostgresStore) ClearAgentPausedUntil(ctx context.Context, tenantID, machineID string) error {
	res, err := s.pool.Exec(ctx, `
		UPDATE agents SET paused_until = NULL
		WHERE tenant_id = $1 AND machine_id = $2`,
		tenantID, machineID)
	if err != nil {
		return fmt.Errorf("clearing paused_until: %w", err)
	}
	if res.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "agent", ID: machineID}
	}
	return nil
}

func (s *PostgresStore) EnqueueAgentCommand(ctx context.Context, cmd *AgentCommand) (*AgentCommand, error) {
	if cmd.ID == "" {
		cmd.ID = uuid.Must(uuid.NewV7()).String()
	}
	if len(cmd.Args) == 0 {
		cmd.Args = []byte(`{}`)
	}
	var out AgentCommand
	err := s.pool.QueryRow(ctx, `
		INSERT INTO agent_commands (id, tenant_id, machine_id, type, args, issued_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, tenant_id, machine_id, type, args, issued_by, issued_at, expires_at`,
		cmd.ID, cmd.TenantID, cmd.MachineID, string(cmd.Type), cmd.Args, cmd.IssuedBy, cmd.ExpiresAt,
	).Scan(&out.ID, &out.TenantID, &out.MachineID, &out.Type,
		&out.Args, &out.IssuedBy, &out.IssuedAt, &out.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("enqueuing agent command: %w", err)
	}
	return &out, nil
}

func (s *PostgresStore) ClaimPendingCommandsForAgent(ctx context.Context, tenantID, machineID string) ([]AgentCommand, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE agent_commands
		SET dispatched_at = NOW()
		WHERE id IN (
			SELECT id FROM agent_commands
			WHERE tenant_id = $1 AND machine_id = $2
			  AND dispatched_at IS NULL
			  AND expires_at > NOW()
			ORDER BY issued_at ASC
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, tenant_id, machine_id, type, args, issued_by,
		          issued_at, expires_at, dispatched_at`,
		tenantID, machineID)
	if err != nil {
		return nil, fmt.Errorf("claiming agent commands: %w", err)
	}
	defer rows.Close()
	out := []AgentCommand{}
	for rows.Next() {
		var c AgentCommand
		var dispatched pgtype.Timestamptz
		if err := rows.Scan(&c.ID, &c.TenantID, &c.MachineID, &c.Type,
			&c.Args, &c.IssuedBy, &c.IssuedAt, &c.ExpiresAt, &dispatched); err != nil {
			return nil, fmt.Errorf("scanning command: %w", err)
		}
		if dispatched.Valid {
			t := dispatched.Time
			c.DispatchedAt = &t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) SetAgentCommandResult(ctx context.Context, tenantID, machineID, commandID, status string, meta json.RawMessage) error {
	if len(meta) == 0 {
		meta = []byte(`{}`)
	}
	res, err := s.pool.Exec(ctx, `
		UPDATE agent_commands
		SET result_status = $4, result_meta = $5, resulted_at = NOW()
		WHERE id = $3 AND tenant_id = $1 AND machine_id = $2`,
		tenantID, machineID, commandID, status, meta)
	if err != nil {
		return fmt.Errorf("setting command result: %w", err)
	}
	if res.RowsAffected() == 0 {
		return &ErrNotFound{Resource: "agent_command", ID: commandID}
	}
	return nil
}

func (s *PostgresStore) ListAgentCommands(ctx context.Context, tenantID, machineID string, limit int) ([]AgentCommand, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, machine_id, type, args, issued_by,
		       issued_at, expires_at, dispatched_at, result_status, result_meta, resulted_at
		FROM agent_commands
		WHERE tenant_id = $1 AND machine_id = $2
		ORDER BY issued_at DESC
		LIMIT $3`, tenantID, machineID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing commands: %w", err)
	}
	defer rows.Close()
	out := []AgentCommand{}
	for rows.Next() {
		var c AgentCommand
		var dispatched, resulted pgtype.Timestamptz
		var status pgtype.Text
		var meta []byte
		if err := rows.Scan(&c.ID, &c.TenantID, &c.MachineID, &c.Type,
			&c.Args, &c.IssuedBy, &c.IssuedAt, &c.ExpiresAt,
			&dispatched, &status, &meta, &resulted); err != nil {
			return nil, fmt.Errorf("scanning command: %w", err)
		}
		if dispatched.Valid {
			t := dispatched.Time
			c.DispatchedAt = &t
		}
		if status.Valid {
			st := status.String
			c.ResultStatus = &st
		}
		if resulted.Valid {
			t := resulted.Time
			c.ResultedAt = &t
		}
		if len(meta) > 0 {
			c.ResultMeta = meta
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ExpireStaleAgentCommands(ctx context.Context) (int, error) {
	res, err := s.pool.Exec(ctx, `
		UPDATE agent_commands
		SET result_status = 'expired', resulted_at = NOW()
		WHERE dispatched_at IS NOT NULL
		  AND result_status IS NULL
		  AND expires_at < NOW()`)
	if err != nil {
		return 0, fmt.Errorf("expiring stale commands: %w", err)
	}
	return int(res.RowsAffected()), nil
}
