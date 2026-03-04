package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/model"
)

// PostgresStore implements Store using PostgreSQL via pgx v5.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects to PostgreSQL and runs any pending schema migrations.
func NewPostgresStore(ctx context.Context, connStr string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgresql: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging postgresql: %w", err)
	}

	s := &PostgresStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return s, nil
}

// migrate applies any unapplied schema migrations.
func (s *PostgresStore) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER NOT NULL UNIQUE,
		applied_at TIMESTAMPTZ NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creating schema_version table: %w", err)
	}

	// Acquire advisory lock to prevent concurrent migrations.
	if _, err := s.pool.Exec(ctx, "SELECT pg_advisory_lock(7355693421)"); err != nil {
		return fmt.Errorf("acquiring migration lock: %w", err)
	}
	defer func() {
		_, _ = s.pool.Exec(ctx, "SELECT pg_advisory_unlock(7355693421)")
	}()

	var current int
	err = s.pool.QueryRow(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&current)
	if err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	for i := current; i < len(migrations); i++ {
		version := i + 1

		tx, err := s.pool.Begin(ctx)
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

	_, err = s.pool.Exec(ctx,
		`INSERT INTO scans
		 (id, hostname, timestamp, profile, total_findings, safe, transitional, deprecated, unsafe, result_json)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (id) DO UPDATE SET
		   hostname = $2, timestamp = $3, profile = $4,
		   total_findings = $5, safe = $6, transitional = $7,
		   deprecated = $8, unsafe = $9, result_json = $10`,
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
	)
	if err != nil {
		return fmt.Errorf("saving scan: %w", err)
	}
	return nil
}

// GetScan retrieves a scan result by ID.
func (s *PostgresStore) GetScan(ctx context.Context, id string) (*model.ScanResult, error) {
	var blob []byte
	err := s.pool.QueryRow(ctx,
		"SELECT result_json FROM scans WHERE id = $1", id,
	).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "scan", ID: id}
	}
	if err != nil {
		return nil, fmt.Errorf("querying scan: %w", err)
	}

	var result model.ScanResult
	if err := json.Unmarshal(blob, &result); err != nil {
		return nil, fmt.Errorf("unmarshalling scan result: %w", err)
	}
	return &result, nil
}

// ListScans returns scan summaries matching the given filter.
func (s *PostgresStore) ListScans(ctx context.Context, filter ScanFilter) ([]ScanSummary, error) {
	query := `SELECT id, hostname, timestamp, profile,
	                 total_findings, safe, transitional, deprecated, unsafe
	          FROM scans WHERE 1=1`
	var args []any
	paramIdx := 0

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
		if err := rows.Scan(&ss.ID, &ss.Hostname, &ss.Timestamp, &ss.Profile,
			&ss.TotalFindings, &ss.Safe, &ss.Transitional, &ss.Deprecated, &ss.Unsafe,
		); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		summaries = append(summaries, ss)
	}
	return summaries, rows.Err()
}

// DeleteScan removes a scan by ID.
func (s *PostgresStore) DeleteScan(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM scans WHERE id = $1", id)
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

// TruncateAll deletes all data from scans and file_hashes tables.
// Intended for test cleanup only.
func (s *PostgresStore) TruncateAll(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin truncate transaction: %w", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM scans"); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM file_hashes"); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
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
