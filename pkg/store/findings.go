package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/amiryahaya/triton/pkg/model"
)

// SaveScanWithFindings atomically creates a scan row and inserts the
// extracted crypto findings into the findings table. Marks the scan as
// backfilled on success so the background goroutine skips it.
//
// Replaces SaveScan on the hot-path write; SaveScan remains for legacy
// call sites and for backfill-test fixtures that need to seed unmarked
// scans. See docs/plans/2026-04-09-analytics-phase-1-design.md §6 and
// the plan's Appendix A.5.
func (s *PostgresStore) SaveScanWithFindings(ctx context.Context, scan *model.ScanResult, findings []Finding) error {
	if scan == nil {
		return fmt.Errorf("cannot save nil scan result")
	}
	if scan.ID == "" {
		return fmt.Errorf("scan result must have an ID")
	}

	// Marshal + encrypt the blob using the same pattern as SaveScan.
	blob, err := json.Marshal(scan)
	if err != nil {
		return fmt.Errorf("marshalling scan result: %w", err)
	}
	if enc := s.loadEncryptor(); enc != nil {
		encrypted, encErr := enc.Encrypt(blob)
		if encErr != nil {
			return fmt.Errorf("encrypting scan result: %w", encErr)
		}
		blob = encrypted
	}

	var orgID *string
	if scan.OrgID != "" {
		orgID = &scan.OrgID
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// (1) Upsert the scan row. Column list matches SaveScan's insert
	// plus the new findings_extracted_at marker (set to NOW() so the
	// backfill goroutine skips this row).
	_, err = tx.Exec(ctx, `
		INSERT INTO scans
		  (id, hostname, timestamp, profile,
		   total_findings, safe, transitional, deprecated, unsafe,
		   result_json, org_id, findings_extracted_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
		ON CONFLICT (id) DO UPDATE SET
		  hostname = EXCLUDED.hostname,
		  timestamp = EXCLUDED.timestamp,
		  profile = EXCLUDED.profile,
		  total_findings = EXCLUDED.total_findings,
		  safe = EXCLUDED.safe,
		  transitional = EXCLUDED.transitional,
		  deprecated = EXCLUDED.deprecated,
		  unsafe = EXCLUDED.unsafe,
		  result_json = EXCLUDED.result_json,
		  org_id = EXCLUDED.org_id,
		  findings_extracted_at = EXCLUDED.findings_extracted_at
	`,
		scan.ID,
		scan.Metadata.Hostname,
		scan.Metadata.Timestamp.UTC(),
		scan.Metadata.ScanProfile,
		scan.Summary.TotalFindings,
		scan.Summary.Safe,
		scan.Summary.Transitional,
		scan.Summary.Deprecated,
		scan.Summary.Unsafe,
		blob,
		orgID,
	)
	if err != nil {
		return fmt.Errorf("upsert scan: %w", err)
	}

	// (2) Bulk-insert the findings. Idempotent via ON CONFLICT so
	// retries or re-runs of the backfill are safe.
	//
	// Single-tenant safety net: in deployments with no Guard and no
	// JWT, handleSubmitScan stamps scan.OrgID = "" (via
	// TenantFromContext returning the empty zero-value). The scan row
	// itself is fine — the column is nullable and we pass *string —
	// but every finding row has org_id UUID NOT NULL, so passing ""
	// would fail the insert with `invalid input syntax for type
	// uuid`, rolling back the scan too. Skip findings insertion for
	// no-org scans; analytics views have no data for single-tenant
	// dev deployments anyway, which is the intended scope.
	// See /pensive:full-review action item B1 (2026-04-09).
	if scan.OrgID == "" {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit tx: %w", err)
		}
		return nil
	}
	if err := insertFindingsInTx(ctx, tx, findings); err != nil {
		return fmt.Errorf("insert findings: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// insertFindingsInTx bulk-inserts findings using chunked VALUES lists
// to avoid the pgx parameter limit (65535). 1000 rows × 18 cols = 18000
// params per chunk keeps us well under the limit.
func insertFindingsInTx(ctx context.Context, tx pgx.Tx, findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	const chunkSize = 1000
	for start := 0; start < len(findings); start += chunkSize {
		end := start + chunkSize
		if end > len(findings) {
			end = len(findings)
		}
		if err := insertFindingsChunk(ctx, tx, findings[start:end]); err != nil {
			return err
		}
	}
	return nil
}

// insertFindingsChunk inserts up to 1000 finding rows in a single
// statement. Column count: 18 (no category, no line_number).
//
// The loop indexes directly into chunk (rather than `for i, f := range
// chunk`) to avoid copying each 232-byte Finding struct per iteration —
// gocritic rangeValCopy fix.
func insertFindingsChunk(ctx context.Context, tx pgx.Tx, chunk []Finding) error {
	const cols = 18
	args := make([]any, 0, len(chunk)*cols)
	valueStrs := make([]string, 0, len(chunk))
	for i := range chunk {
		f := &chunk[i]
		base := i * cols
		valueStrs = append(valueStrs, fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8,
			base+9, base+10, base+11, base+12, base+13, base+14, base+15, base+16,
			base+17, base+18,
		))
		args = append(args,
			f.ID, f.ScanID, f.OrgID, f.Hostname, f.FindingIndex,
			f.Module, f.FilePath,
			f.Algorithm, f.KeySize, f.PQCStatus, f.MigrationPriority,
			f.NotAfter, f.Subject, f.Issuer, f.Reachability, f.CreatedAt,
			f.ImageRef, f.ImageDigest,
		)
	}

	sql := `INSERT INTO findings (
		id, scan_id, org_id, hostname, finding_index,
		module, file_path,
		algorithm, key_size, pqc_status, migration_priority,
		not_after, subject, issuer, reachability, created_at,
		image_ref, image_digest
	) VALUES ` + strings.Join(valueStrs, ",") + `
	ON CONFLICT (scan_id, finding_index) DO NOTHING`

	_, err := tx.Exec(ctx, sql, args...)
	return err
}

// ListInventory aggregates findings by (algorithm, key_size) for the
// given org, filtered to the latest scan per hostname. Sorted by worst
// PQC status first, then instances descending. Returns an empty slice
// (not nil) when there are no findings.
func (s *PostgresStore) ListInventory(ctx context.Context, orgID string) ([]InventoryRow, error) {
	const q = `
WITH latest_scans AS (
    SELECT DISTINCT ON (hostname) id, org_id
    FROM scans
    WHERE org_id = $1
    ORDER BY hostname, timestamp DESC
)
SELECT
    f.algorithm,
    f.key_size,
    MIN(
        CASE f.pqc_status
            WHEN 'UNSAFE'       THEN 1
            WHEN 'DEPRECATED'   THEN 2
            WHEN 'TRANSITIONAL' THEN 3
            WHEN 'SAFE'         THEN 4
            ELSE 5
        END
    ) AS status_rank,
    COUNT(*)                               AS instances,
    COUNT(DISTINCT f.hostname)             AS machines,
    COALESCE(MAX(f.migration_priority), 0) AS max_priority
FROM findings f
WHERE f.org_id = $1
  AND (f.scan_id, f.org_id) IN (SELECT id, org_id FROM latest_scans)
GROUP BY f.algorithm, f.key_size
ORDER BY status_rank ASC, instances DESC
`
	rows, err := s.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("ListInventory query: %w", err)
	}
	defer rows.Close()

	out := make([]InventoryRow, 0)
	for rows.Next() {
		var r InventoryRow
		var rank int
		if err := rows.Scan(&r.Algorithm, &r.KeySize, &rank, &r.Instances, &r.Machines, &r.MaxPriority); err != nil {
			return nil, fmt.Errorf("ListInventory scan: %w", err)
		}
		r.PQCStatus = pqcStatusFromRank(rank)
		out = append(out, r)
	}
	return out, rows.Err()
}

// pqcStatusFromRank converts the SQL CASE rank back to its string form.
// Must stay in sync with the CASE expression in ListInventory.
func pqcStatusFromRank(rank int) string {
	switch rank {
	case 1:
		return "UNSAFE"
	case 2:
		return "DEPRECATED"
	case 3:
		return "TRANSITIONAL"
	case 4:
		return "SAFE"
	default:
		return ""
	}
}

// ListExpiringCertificates returns findings with not_after IS NOT NULL,
// filtered to the latest scan per hostname, expiring within the given
// duration from now. Already-expired certs are ALWAYS included.
func (s *PostgresStore) ListExpiringCertificates(ctx context.Context, orgID string, within time.Duration) ([]ExpiringCertRow, error) {
	const q = `
WITH latest_scans AS (
    SELECT DISTINCT ON (hostname) id, org_id
    FROM scans
    WHERE org_id = $1
    ORDER BY hostname, timestamp DESC
)
SELECT f.id, f.subject, f.issuer, f.hostname, f.algorithm, f.key_size, f.not_after
FROM findings f
WHERE f.org_id = $1
  AND (f.scan_id, f.org_id) IN (SELECT id, org_id FROM latest_scans)
  AND f.not_after IS NOT NULL
  AND (f.not_after <= NOW() + $2::interval OR f.not_after < NOW())
ORDER BY f.not_after ASC
`
	interval := fmt.Sprintf("%d seconds", int64(within.Seconds()))
	rows, err := s.pool.Query(ctx, q, orgID, interval)
	if err != nil {
		return nil, fmt.Errorf("ListExpiringCertificates query: %w", err)
	}
	defer rows.Close()

	now := time.Now().UTC()
	out := make([]ExpiringCertRow, 0)
	for rows.Next() {
		var r ExpiringCertRow
		var notAfter time.Time
		if err := rows.Scan(&r.FindingID, &r.Subject, &r.Issuer, &r.Hostname, &r.Algorithm, &r.KeySize, &notAfter); err != nil {
			return nil, fmt.Errorf("ListExpiringCertificates scan: %w", err)
		}
		r.NotAfter = notAfter
		r.DaysRemaining = int(notAfter.Sub(now).Hours() / 24)
		r.Status = certStatusFromDays(r.DaysRemaining)
		out = append(out, r)
	}
	return out, rows.Err()
}

// certStatusFromDays maps days-remaining to a status badge label.
// Matches the UI colour scheme: red ≤0 expired, orange 1-30 urgent,
// yellow 31-90 warning, green >90 ok.
func certStatusFromDays(days int) string {
	switch {
	case days < 0:
		return "expired"
	case days <= 30:
		return "urgent"
	case days <= 90:
		return "warning"
	default:
		return "ok"
	}
}

// ListTopPriorityFindings returns the top N findings by
// migration_priority descending, filtered to the latest scan per
// hostname. limit=0 is treated as limit=20. Findings with priority 0
// are excluded.
func (s *PostgresStore) ListTopPriorityFindings(ctx context.Context, orgID string, limit int) ([]PriorityRow, error) {
	if limit <= 0 {
		limit = 20
	}
	const q = `
WITH latest_scans AS (
    SELECT DISTINCT ON (hostname) id, org_id
    FROM scans
    WHERE org_id = $1
    ORDER BY hostname, timestamp DESC
)
SELECT f.id, f.migration_priority, f.algorithm, f.key_size, f.pqc_status,
       f.module, f.hostname, f.file_path
FROM findings f
WHERE f.org_id = $1
  AND (f.scan_id, f.org_id) IN (SELECT id, org_id FROM latest_scans)
  AND f.migration_priority > 0
ORDER BY f.migration_priority DESC
LIMIT $2
`
	rows, err := s.pool.Query(ctx, q, orgID, limit)
	if err != nil {
		return nil, fmt.Errorf("ListTopPriorityFindings query: %w", err)
	}
	defer rows.Close()

	out := make([]PriorityRow, 0)
	for rows.Next() {
		var r PriorityRow
		if err := rows.Scan(&r.FindingID, &r.Priority, &r.Algorithm, &r.KeySize, &r.PQCStatus,
			&r.Module, &r.Hostname, &r.FilePath); err != nil {
			return nil, fmt.Errorf("ListTopPriorityFindings scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListScansOrderedByTime returns ALL scan summaries for the given
// org, sorted by timestamp ASCENDING. Full history is intentional:
// the projection math in pkg/analytics uses first-to-last pace over
// the entire org lifetime. If a time window is needed in the future,
// add an optional parameter rather than changing this method.
// See the interface doc comment in store.go for rationale.
// Analytics Phase 2.
func (s *PostgresStore) ListScansOrderedByTime(ctx context.Context, orgID string) ([]ScanSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, timestamp, profile,
		       total_findings, safe, transitional, deprecated, unsafe
		FROM scans
		WHERE org_id = $1
		ORDER BY timestamp ASC
	`, orgID)
	if err != nil {
		return nil, fmt.Errorf("ListScansOrderedByTime: %w", err)
	}
	defer rows.Close()

	out := make([]ScanSummary, 0)
	for rows.Next() {
		var r ScanSummary
		if err := rows.Scan(&r.ID, &r.Hostname, &r.Timestamp, &r.Profile,
			&r.TotalFindings, &r.Safe, &r.Transitional, &r.Deprecated, &r.Unsafe); err != nil {
			return nil, fmt.Errorf("ListScansOrderedByTime scan: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
