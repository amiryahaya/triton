package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
)

// ComputeFindingKey produces a stable identifier for a crypto finding
// across scans. The key is a hex-encoded SHA-256 hash of the fields
// separated by null bytes to prevent boundary collisions (e.g.,
// hostname="webRSA" + algorithm="" vs hostname="web" + algorithm="RSA").
//
// Note: file_path is intentionally excluded — findings with the same
// algorithm on the same host from the same module are grouped together.
// Marking one as resolved marks all of them. This is the desired
// behavior for migration tracking (you migrate the algorithm, not
// individual files).
func ComputeFindingKey(orgID, hostname, algorithm string, keySize int, module string) string {
	data := orgID + "\x00" + hostname + "\x00" + algorithm + "\x00" + strconv.Itoa(keySize) + "\x00" + module
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

func (s *PostgresStore) SetFindingStatus(ctx context.Context, entry *FindingStatusEntry) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO finding_status (finding_key, org_id, status, reason, changed_by, changed_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.FindingKey, entry.OrgID, entry.Status, entry.Reason, entry.ChangedBy, entry.ChangedAt, entry.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("SetFindingStatus: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetFindingHistory(ctx context.Context, findingKey, orgID string) ([]FindingStatusEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, finding_key, org_id, status, reason, changed_by, changed_at, expires_at
		 FROM finding_status
		 WHERE finding_key = $1 AND org_id = $2
		 ORDER BY changed_at DESC`,
		findingKey, orgID,
	)
	if err != nil {
		return nil, fmt.Errorf("GetFindingHistory: %w", err)
	}
	defer rows.Close()
	result := []FindingStatusEntry{}
	for rows.Next() {
		var e FindingStatusEntry
		if err := rows.Scan(&e.ID, &e.FindingKey, &e.OrgID, &e.Status, &e.Reason, &e.ChangedBy, &e.ChangedAt, &e.ExpiresAt); err != nil {
			return nil, fmt.Errorf("GetFindingHistory scan: %w", err)
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

func (s *PostgresStore) GetRemediationSummary(ctx context.Context, orgID string) (*RemediationSummary, error) {
	var summary RemediationSummary
	err := s.pool.QueryRow(ctx,
		`WITH latest_scans AS (
			SELECT DISTINCT ON (hostname) id FROM scans
			WHERE org_id = $1 ORDER BY hostname, timestamp DESC
		),
		latest_status AS (
			SELECT DISTINCT ON (finding_key) finding_key, status, expires_at
			FROM finding_status WHERE org_id = $1
			ORDER BY finding_key, changed_at DESC
		)
		SELECT
			COUNT(*) FILTER (WHERE
				COALESCE(ls.status, 'open') = 'open'
				OR (ls.status = 'accepted' AND ls.expires_at IS NOT NULL AND ls.expires_at < NOW())
			) AS open_count,
			COUNT(*) FILTER (WHERE ls.status = 'in_progress') AS in_progress,
			COUNT(*) FILTER (WHERE ls.status = 'resolved') AS resolved,
			COUNT(*) FILTER (WHERE ls.status = 'accepted'
				AND (ls.expires_at IS NULL OR ls.expires_at >= NOW())) AS accepted,
			COUNT(*) AS total
		FROM findings f
		JOIN latest_scans lsc ON f.scan_id = lsc.id
		LEFT JOIN latest_status ls ON ls.finding_key =
			encode(sha256((f.org_id::text || chr(0) || f.hostname || chr(0) || f.algorithm || chr(0) || f.key_size::text || chr(0) || f.module)::bytea), 'hex')`,
		orgID,
	).Scan(&summary.Open, &summary.InProgress, &summary.Resolved, &summary.Accepted, &summary.Total)
	if err != nil {
		return nil, fmt.Errorf("GetRemediationSummary: %w", err)
	}
	return &summary, nil
}

func (s *PostgresStore) ListRemediationFindings(ctx context.Context, orgID, statusFilter, hostnameFilter, pqcFilter string) ([]RemediationRow, error) {
	query := `WITH latest_scans AS (
		SELECT DISTINCT ON (hostname) id FROM scans
		WHERE org_id = $1 ORDER BY hostname, timestamp DESC
	),
	latest_status AS (
		SELECT DISTINCT ON (finding_key) finding_key, status, changed_at, changed_by, expires_at
		FROM finding_status WHERE org_id = $1
		ORDER BY finding_key, changed_at DESC
	)
	SELECT f.id, f.hostname, f.algorithm, f.key_size, f.pqc_status, f.module,
		f.migration_priority,
		COALESCE(ls.status, 'open') AS current_status,
		ls.changed_at, COALESCE(ls.changed_by, ''),
		encode(sha256((f.org_id::text || chr(0) || f.hostname || chr(0) || f.algorithm || chr(0) || f.key_size::text || chr(0) || f.module)::bytea), 'hex') AS finding_key
	FROM findings f
	JOIN latest_scans lsc ON f.scan_id = lsc.id
	LEFT JOIN latest_status ls ON ls.finding_key =
		encode(sha256((f.org_id::text || chr(0) || f.hostname || chr(0) || f.algorithm || chr(0) || f.key_size::text || chr(0) || f.module)::bytea), 'hex')
	WHERE 1=1`

	args := []any{orgID}
	argIdx := 2

	if statusFilter != "" {
		switch statusFilter {
		case "open":
			query += ` AND (COALESCE(ls.status, 'open') = 'open' OR (ls.status = 'accepted' AND ls.expires_at IS NOT NULL AND ls.expires_at < NOW()))`
		case "accepted":
			query += ` AND ls.status = 'accepted' AND (ls.expires_at IS NULL OR ls.expires_at >= NOW())`
		default:
			query += fmt.Sprintf(` AND ls.status = $%d`, argIdx)
			args = append(args, statusFilter)
			argIdx++
		}
	}
	if hostnameFilter != "" {
		query += fmt.Sprintf(` AND f.hostname = $%d`, argIdx)
		args = append(args, hostnameFilter)
		argIdx++
	}
	if pqcFilter != "" {
		query += fmt.Sprintf(` AND f.pqc_status = $%d`, argIdx)
		args = append(args, pqcFilter)
		argIdx++
	}
	_ = argIdx // suppress unused

	query += ` ORDER BY f.migration_priority DESC`

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ListRemediationFindings: %w", err)
	}
	defer rows.Close()

	result := []RemediationRow{}
	for rows.Next() {
		var r RemediationRow
		if err := rows.Scan(&r.FindingID, &r.Hostname, &r.Algorithm, &r.KeySize,
			&r.PQCStatus, &r.Module, &r.Priority, &r.Status,
			&r.ChangedAt, &r.ChangedBy, &r.FindingKey); err != nil {
			return nil, fmt.Errorf("ListRemediationFindings scan: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *PostgresStore) GetFindingByID(ctx context.Context, findingID, orgID string) (*Finding, error) {
	var f Finding
	err := s.pool.QueryRow(ctx,
		`SELECT id, scan_id, org_id, hostname, finding_index, module, file_path,
			algorithm, key_size, pqc_status, migration_priority, not_after,
			subject, issuer, reachability, created_at, image_ref, image_digest
		 FROM findings
		 WHERE id = $1 AND org_id = $2`,
		findingID, orgID,
	).Scan(&f.ID, &f.ScanID, &f.OrgID, &f.Hostname, &f.FindingIndex, &f.Module, &f.FilePath,
		&f.Algorithm, &f.KeySize, &f.PQCStatus, &f.MigrationPriority, &f.NotAfter,
		&f.Subject, &f.Issuer, &f.Reachability, &f.CreatedAt, &f.ImageRef, &f.ImageDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &ErrNotFound{Resource: "finding", ID: findingID}
	}
	if err != nil {
		return nil, fmt.Errorf("GetFindingByID: %w", err)
	}
	return &f, nil
}
