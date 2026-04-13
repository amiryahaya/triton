package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// RefreshHostSummary recomputes the host_summary row for one (org, hostname)
// pair from the latest scan's findings. This is the T2 pipeline transform.
// Analytics Phase 4A.
func (s *PostgresStore) RefreshHostSummary(ctx context.Context, orgID, hostname string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	// Step 1: find the latest scan for this hostname.
	var scanID string
	var scannedAt time.Time
	err = tx.QueryRow(ctx,
		`SELECT id, timestamp FROM scans
		 WHERE org_id = $1 AND hostname = $2
		 ORDER BY timestamp DESC LIMIT 1`,
		orgID, hostname,
	).Scan(&scanID, &scannedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// No scan for this host — nothing to summarise.
		return nil
	}
	if err != nil {
		return fmt.Errorf("RefreshHostSummary latest scan: %w", err)
	}

	// Step 1b: auto-reopen resolved findings that reappeared in the latest scan.
	// This runs BEFORE the status counts (Step 2) so that the counts reflect
	// the post-reopen state. Accepted findings are NOT reopened.
	_, err = tx.Exec(ctx,
		`WITH scan_keys AS (
		   SELECT DISTINCT encode(sha256(
		     (f.org_id::text || chr(0) || f.hostname || chr(0) || f.algorithm || chr(0) || f.key_size::text || chr(0) || f.module)::bytea
		   ), 'hex') AS fkey
		   FROM findings f WHERE f.scan_id = $1
		 ),
		 resolved_keys AS (
		   SELECT DISTINCT ON (finding_key) finding_key, status
		   FROM finding_status WHERE org_id = $2
		   ORDER BY finding_key, changed_at DESC
		 )
		 INSERT INTO finding_status (finding_key, org_id, status, reason, changed_by, changed_at)
		 SELECT rk.finding_key, $2, 'open', 'finding reappeared in scan', 'system', NOW()
		 FROM resolved_keys rk
		 JOIN scan_keys sk ON rk.finding_key = sk.fkey
		 WHERE rk.status = 'resolved'`,
		scanID, orgID,
	)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary auto-reopen: %w", err)
	}

	// Step 2: count findings by pqc_status, excluding resolved and non-expired accepted findings.
	counts := map[string]int{}
	rows, err := tx.Query(ctx,
		`WITH latest_status AS (
		   SELECT DISTINCT ON (finding_key) finding_key, status, expires_at
		   FROM finding_status
		   WHERE org_id = $1
		   ORDER BY finding_key, changed_at DESC
		 )
		 SELECT f.pqc_status, COUNT(*)
		 FROM findings f
		 LEFT JOIN latest_status ls ON ls.finding_key =
		   encode(sha256((f.org_id::text || chr(0) || f.hostname || chr(0) || f.algorithm || chr(0) || f.key_size::text || chr(0) || f.module)::bytea), 'hex')
		 WHERE f.scan_id = $2
		   AND (ls.status IS NULL
		        OR ls.status IN ('open', 'in_progress')
		        OR (ls.status = 'accepted' AND ls.expires_at IS NOT NULL AND ls.expires_at < NOW()))
		 GROUP BY f.pqc_status`,
		orgID, scanID,
	)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary status counts: %w", err)
	}
	for rows.Next() {
		var status string
		var cnt int
		if err := rows.Scan(&status, &cnt); err != nil {
			rows.Close()
			return fmt.Errorf("RefreshHostSummary status counts scan: %w", err)
		}
		counts[status] = cnt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("RefreshHostSummary status counts rows: %w", err)
	}

	safeFindings := counts["SAFE"]
	transitionalFindings := counts["TRANSITIONAL"]
	deprecatedFindings := counts["DEPRECATED"]
	unsafeFindings := counts["UNSAFE"]
	totalFindings := safeFindings + transitionalFindings + deprecatedFindings + unsafeFindings

	// Step 3: count expiring / expired certs.
	var certsExpired, certsExpiring30d, certsExpiring90d int

	err = tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM findings
		 WHERE scan_id = $1 AND not_after IS NOT NULL AND not_after < NOW()`,
		scanID,
	).Scan(&certsExpired)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary certs_expired: %w", err)
	}

	err = tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM findings
		 WHERE scan_id = $1 AND not_after IS NOT NULL
		   AND not_after BETWEEN NOW() AND NOW() + interval '30 days'`,
		scanID,
	).Scan(&certsExpiring30d)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary certs_expiring_30d: %w", err)
	}

	err = tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM findings
		 WHERE scan_id = $1 AND not_after IS NOT NULL
		   AND not_after BETWEEN NOW() AND NOW() + interval '90 days'`,
		scanID,
	).Scan(&certsExpiring90d)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary certs_expiring_90d: %w", err)
	}

	// Step 4: max migration priority.
	var maxPriority int
	err = tx.QueryRow(ctx,
		`SELECT COALESCE(MAX(migration_priority), 0) FROM findings WHERE scan_id = $1`,
		scanID,
	).Scan(&maxPriority)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary max_priority: %w", err)
	}

	// Step 4b: count resolved and accepted findings.
	var resolvedCount, acceptedCount int
	err = tx.QueryRow(ctx,
		`WITH latest_status AS (
		   SELECT DISTINCT ON (finding_key) finding_key, status, expires_at
		   FROM finding_status
		   WHERE org_id = $1
		   ORDER BY finding_key, changed_at DESC
		 )
		 SELECT
		   COUNT(*) FILTER (WHERE ls.status = 'resolved'),
		   COUNT(*) FILTER (WHERE ls.status = 'accepted' AND (ls.expires_at IS NULL OR ls.expires_at >= NOW()))
		 FROM findings f
		 JOIN latest_status ls ON ls.finding_key =
		   encode(sha256((f.org_id::text || chr(0) || f.hostname || chr(0) || f.algorithm || chr(0) || f.key_size::text || chr(0) || f.module)::bytea), 'hex')
		 WHERE f.scan_id = $2`,
		orgID, scanID,
	).Scan(&resolvedCount, &acceptedCount)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary resolved/accepted counts: %w", err)
	}

	// Step 5: readiness percentage.
	var readinessPct float64
	if totalFindings > 0 {
		readinessPct = float64(safeFindings) / float64(totalFindings) * 100
	}

	// Step 6: sparkline — last 12 months.
	sparkRows, err := tx.Query(ctx,
		`WITH monthly_scans AS (
		   SELECT DISTINCT ON (date_trunc('month', s.timestamp))
		     s.id AS scan_id, date_trunc('month', s.timestamp) AS month
		   FROM scans s
		   WHERE s.org_id = $1 AND s.hostname = $2
		     AND s.timestamp >= NOW() - interval '12 months'
		   ORDER BY date_trunc('month', s.timestamp), s.timestamp DESC
		 )
		 SELECT to_char(ms.month, 'YYYY-MM') AS month,
		   COUNT(*) FILTER (WHERE f.pqc_status = 'SAFE') AS safe,
		   COUNT(*) AS total
		 FROM monthly_scans ms
		 JOIN findings f ON f.scan_id = ms.scan_id
		 GROUP BY ms.month
		 ORDER BY ms.month`,
		orgID, hostname,
	)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary sparkline: %w", err)
	}

	var sparkline []SparklinePoint
	for sparkRows.Next() {
		var month string
		var safe, total int
		if err := sparkRows.Scan(&month, &safe, &total); err != nil {
			sparkRows.Close()
			return fmt.Errorf("RefreshHostSummary sparkline scan: %w", err)
		}
		var r float64
		if total > 0 {
			r = float64(safe) / float64(total) * 100
		}
		sparkline = append(sparkline, SparklinePoint{Month: month, Readiness: r})
	}
	sparkRows.Close()
	if err := sparkRows.Err(); err != nil {
		return fmt.Errorf("RefreshHostSummary sparkline rows: %w", err)
	}

	// Step 7: trend direction.
	trendDirection := "insufficient"
	var trendDeltaPct float64
	if len(sparkline) >= 2 {
		last := sparkline[len(sparkline)-1].Readiness
		prev := sparkline[len(sparkline)-2].Readiness
		delta := last - prev
		trendDeltaPct = delta
		switch {
		case delta > 1:
			trendDirection = "improving"
		case delta < -1:
			trendDirection = "declining"
		default:
			trendDirection = "stable"
		}
	}

	// Step 8: marshal sparkline for JSONB column.
	sparklineJSON, err := json.Marshal(sparkline)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary sparkline marshal: %w", err)
	}

	// UPSERT into host_summary.
	_, err = tx.Exec(ctx,
		`INSERT INTO host_summary (
		   org_id, hostname, scan_id, scanned_at,
		   total_findings, safe_findings, transitional_findings, deprecated_findings, unsafe_findings,
		   readiness_pct, certs_expiring_30d, certs_expiring_90d, certs_expired,
		   max_priority, trend_direction, trend_delta_pct, sparkline,
		   resolved_count, accepted_count, refreshed_at
		 ) VALUES (
		   $1, $2, $3, $4,
		   $5, $6, $7, $8, $9,
		   $10, $11, $12, $13,
		   $14, $15, $16, $17,
		   $18, $19, NOW()
		 )
		 ON CONFLICT (org_id, hostname) DO UPDATE SET
		   scan_id               = EXCLUDED.scan_id,
		   scanned_at            = EXCLUDED.scanned_at,
		   total_findings        = EXCLUDED.total_findings,
		   safe_findings         = EXCLUDED.safe_findings,
		   transitional_findings = EXCLUDED.transitional_findings,
		   deprecated_findings   = EXCLUDED.deprecated_findings,
		   unsafe_findings       = EXCLUDED.unsafe_findings,
		   readiness_pct         = EXCLUDED.readiness_pct,
		   certs_expiring_30d    = EXCLUDED.certs_expiring_30d,
		   certs_expiring_90d    = EXCLUDED.certs_expiring_90d,
		   certs_expired         = EXCLUDED.certs_expired,
		   max_priority          = EXCLUDED.max_priority,
		   trend_direction       = EXCLUDED.trend_direction,
		   trend_delta_pct       = EXCLUDED.trend_delta_pct,
		   sparkline             = EXCLUDED.sparkline,
		   resolved_count        = EXCLUDED.resolved_count,
		   accepted_count        = EXCLUDED.accepted_count,
		   refreshed_at          = NOW()`,
		orgID, hostname, scanID, scannedAt,
		totalFindings, safeFindings, transitionalFindings, deprecatedFindings, unsafeFindings,
		readinessPct, certsExpiring30d, certsExpiring90d, certsExpired,
		maxPriority, trendDirection, trendDeltaPct, sparklineJSON,
		resolvedCount, acceptedCount,
	)
	if err != nil {
		return fmt.Errorf("RefreshHostSummary upsert: %w", err)
	}

	return tx.Commit(ctx)
}

// ListHostSummaries returns host_summary rows for the given org,
// optionally filtered by pqc_status. Analytics Phase 4A.
func (s *PostgresStore) ListHostSummaries(ctx context.Context, orgID, pqcStatusFilter string) ([]HostSummary, error) {
	baseQuery := `SELECT
		org_id, hostname, scan_id, scanned_at,
		total_findings, safe_findings, transitional_findings, deprecated_findings, unsafe_findings,
		readiness_pct, certs_expiring_30d, certs_expiring_90d, certs_expired,
		max_priority, trend_direction, trend_delta_pct, sparkline, refreshed_at
	  FROM host_summary
	  WHERE org_id = $1`

	switch pqcStatusFilter {
	case "UNSAFE":
		baseQuery += ` AND unsafe_findings > 0`
	case "DEPRECATED":
		baseQuery += ` AND deprecated_findings > 0`
	case "TRANSITIONAL":
		baseQuery += ` AND transitional_findings > 0`
	case "SAFE":
		baseQuery += ` AND unsafe_findings = 0 AND deprecated_findings = 0`
	}
	baseQuery += ` ORDER BY readiness_pct ASC, hostname ASC`

	rows, err := s.pool.Query(ctx, baseQuery, orgID)
	if err != nil {
		return nil, fmt.Errorf("ListHostSummaries query: %w", err)
	}
	defer rows.Close()

	result := []HostSummary{}
	for rows.Next() {
		var hs HostSummary
		var sparklineRaw []byte
		if err := rows.Scan(
			&hs.OrgID, &hs.Hostname, &hs.ScanID, &hs.ScannedAt,
			&hs.TotalFindings, &hs.SafeFindings, &hs.TransitionalFindings, &hs.DeprecatedFindings, &hs.UnsafeFindings,
			&hs.ReadinessPct, &hs.CertsExpiring30d, &hs.CertsExpiring90d, &hs.CertsExpired,
			&hs.MaxPriority, &hs.TrendDirection, &hs.TrendDeltaPct, &sparklineRaw, &hs.RefreshedAt,
		); err != nil {
			return nil, fmt.Errorf("ListHostSummaries scan: %w", err)
		}
		if len(sparklineRaw) > 0 {
			if err := json.Unmarshal(sparklineRaw, &hs.Sparkline); err != nil {
				return nil, fmt.Errorf("ListHostSummaries sparkline unmarshal: %w", err)
			}
		}
		result = append(result, hs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListHostSummaries rows: %w", err)
	}
	return result, nil
}

// ListStaleHosts returns all (org_id, hostname) pairs whose host_summary
// is missing or older than the newest scan for that host.
// This drives the T2 pipeline catch-up sweep. Analytics Phase 4A.
func (s *PostgresStore) ListStaleHosts(ctx context.Context) ([]PipelineJob, error) {
	// Find hosts with no summary or whose summary is older than the
	// latest scan. Uses a CTE to compute MAX(timestamp) per host so
	// the comparison is against the newest scan only (not every scan).
	// Unscoped across all orgs — runs at cold start only.
	rows, err := s.pool.Query(ctx,
		`WITH latest_scan AS (
			SELECT f.org_id, f.hostname, MAX(s.timestamp) AS max_ts
			FROM findings f
			JOIN scans s ON f.scan_id = s.id
			GROUP BY f.org_id, f.hostname
		)
		SELECT ls.org_id, ls.hostname
		FROM latest_scan ls
		LEFT JOIN host_summary hs ON ls.org_id = hs.org_id AND ls.hostname = hs.hostname
		WHERE hs.org_id IS NULL
		   OR hs.refreshed_at < ls.max_ts`,
	)
	if err != nil {
		return nil, fmt.Errorf("ListStaleHosts query: %w", err)
	}
	defer rows.Close()

	result := []PipelineJob{}
	for rows.Next() {
		var job PipelineJob
		if err := rows.Scan(&job.OrgID, &job.Hostname); err != nil {
			return nil, fmt.Errorf("ListStaleHosts scan: %w", err)
		}
		result = append(result, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListStaleHosts rows: %w", err)
	}
	return result, nil
}
