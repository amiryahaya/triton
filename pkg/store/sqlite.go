package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/amiryahaya/triton/pkg/model"

	_ "modernc.org/sqlite"
)

// SQLiteStore implements Store using a local SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (or creates) a SQLite database at the given path and
// runs any pending schema migrations.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	// Ensure parent directory exists.
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	// Single connection for write safety; reads still concurrent via WAL.
	db.SetMaxOpenConns(1)

	s := &SQLiteStore{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return s, nil
}

// migrate applies any unapplied schema migrations.
func (s *SQLiteStore) migrate() error {
	// Ensure the schema_version table exists.
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version INTEGER NOT NULL,
		applied_at TEXT NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creating schema_version table: %w", err)
	}

	// Determine current version.
	var current int
	row := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version")
	if err := row.Scan(&current); err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	// Apply pending migrations.
	for i := current; i < len(migrations); i++ {
		version := i + 1

		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin tx for migration %d: %w", version, err)
		}

		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", version, err)
		}

		if _, err := tx.Exec(
			"INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
			version, time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("recording migration %d: %w", version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}

	return nil
}

// SaveScan persists a scan result to the database.
func (s *SQLiteStore) SaveScan(ctx context.Context, result *model.ScanResult) error {
	blob, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshalling scan result: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO scans
		 (id, hostname, timestamp, profile, total_findings, safe, transitional, deprecated, unsafe, result_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.ID,
		result.Metadata.Hostname,
		result.Metadata.Timestamp.UTC().Format(time.RFC3339),
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
func (s *SQLiteStore) GetScan(ctx context.Context, id string) (*model.ScanResult, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx,
		"SELECT result_json FROM scans WHERE id = ?", id,
	).Scan(&blob)
	if err == sql.ErrNoRows {
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
func (s *SQLiteStore) ListScans(ctx context.Context, filter ScanFilter) ([]ScanSummary, error) {
	query := `SELECT id, hostname, timestamp, profile,
	                 total_findings, safe, transitional, deprecated, unsafe
	          FROM scans WHERE 1=1`
	var args []any

	if filter.Hostname != "" {
		query += " AND hostname = ?"
		args = append(args, filter.Hostname)
	}
	if filter.Profile != "" {
		query += " AND profile = ?"
		args = append(args, filter.Profile)
	}
	if filter.After != nil {
		query += " AND timestamp >= ?"
		args = append(args, filter.After.UTC().Format(time.RFC3339))
	}
	if filter.Before != nil {
		query += " AND timestamp <= ?"
		args = append(args, filter.Before.UTC().Format(time.RFC3339))
	}

	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing scans: %w", err)
	}
	defer rows.Close()

	var summaries []ScanSummary
	for rows.Next() {
		var ss ScanSummary
		var ts string
		if err := rows.Scan(&ss.ID, &ss.Hostname, &ts, &ss.Profile,
			&ss.TotalFindings, &ss.Safe, &ss.Transitional, &ss.Deprecated, &ss.Unsafe,
		); err != nil {
			return nil, fmt.Errorf("scanning row: %w", err)
		}
		ss.Timestamp, _ = time.Parse(time.RFC3339, ts)
		summaries = append(summaries, ss)
	}
	return summaries, rows.Err()
}

// DeleteScan removes a scan by ID.
func (s *SQLiteStore) DeleteScan(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, "DELETE FROM scans WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting scan: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return &ErrNotFound{Resource: "scan", ID: id}
	}
	return nil
}

// GetFileHash retrieves the stored hash and last-scanned time for a file path.
func (s *SQLiteStore) GetFileHash(ctx context.Context, path string) (string, time.Time, error) {
	var hash, ts string
	err := s.db.QueryRowContext(ctx,
		"SELECT hash, scanned_at FROM file_hashes WHERE path = ?", path,
	).Scan(&hash, &ts)
	if err == sql.ErrNoRows {
		return "", time.Time{}, &ErrNotFound{Resource: "file_hash", ID: path}
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("querying file hash: %w", err)
	}
	scannedAt, _ := time.Parse(time.RFC3339, ts)
	return hash, scannedAt, nil
}

// SetFileHash stores (or updates) the hash for a file path.
func (s *SQLiteStore) SetFileHash(ctx context.Context, path, hash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO file_hashes (path, hash, scanned_at)
		 VALUES (?, ?, ?)`,
		path, hash, time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("setting file hash: %w", err)
	}
	return nil
}

// PruneStaleHashes removes file hash entries older than the given time.
func (s *SQLiteStore) PruneStaleHashes(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM file_hashes WHERE scanned_at < ?",
		before.UTC().Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("pruning stale hashes: %w", err)
	}
	return nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// SchemaVersion returns the current schema version.
func (s *SQLiteStore) SchemaVersion() (int, error) {
	var version int
	err := s.db.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version)
	return version, err
}

// FileHashStats returns summary statistics about the file hash cache.
func (s *SQLiteStore) FileHashStats(ctx context.Context) (count int, oldest, newest time.Time, err error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MIN(scanned_at), ''), COALESCE(MAX(scanned_at), '')
		 FROM file_hashes`)
	var oldestStr, newestStr string
	if err = row.Scan(&count, &oldestStr, &newestStr); err != nil {
		return 0, time.Time{}, time.Time{}, fmt.Errorf("querying file hash stats: %w", err)
	}
	if count > 0 {
		oldest, _ = time.Parse(time.RFC3339, oldestStr)
		newest, _ = time.Parse(time.RFC3339, newestStr)
	}
	return count, oldest, newest, nil
}
