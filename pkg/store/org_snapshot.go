package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// RefreshOrgSnapshot recomputes the org_snapshot row for an org from all
// host_summary rows. This is the T3 pipeline transform. Analytics Phase 4A.
func (s *PostgresStore) RefreshOrgSnapshot(ctx context.Context, orgID string) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("RefreshOrgSnapshot begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback is a no-op after commit

	// Step 1: query all host_summary rows for this org.
	rows, err := tx.Query(ctx,
		`SELECT hostname, total_findings, safe_findings, transitional_findings,
		        deprecated_findings, unsafe_findings, readiness_pct,
		        certs_expiring_30d, certs_expiring_90d, certs_expired,
		        sparkline
		 FROM host_summary WHERE org_id = $1`,
		orgID,
	)
	if err != nil {
		return fmt.Errorf("RefreshOrgSnapshot host_summary query: %w", err)
	}
	defer rows.Close()

	type hostRow struct {
		hostname             string
		totalFindings        int
		safeFindings         int
		transitionalFindings int
		deprecatedFindings   int
		unsafeFindings       int
		readinessPct         float64
		certsExpiring30d     int
		certsExpiring90d     int
		certsExpired         int
		sparkline            []SparklinePoint
	}

	var hosts []hostRow
	for rows.Next() {
		var h hostRow
		var sparklineRaw []byte
		if err := rows.Scan(
			&h.hostname,
			&h.totalFindings, &h.safeFindings, &h.transitionalFindings,
			&h.deprecatedFindings, &h.unsafeFindings, &h.readinessPct,
			&h.certsExpiring30d, &h.certsExpiring90d, &h.certsExpired,
			&sparklineRaw,
		); err != nil {
			return fmt.Errorf("RefreshOrgSnapshot host_summary scan: %w", err)
		}
		if len(sparklineRaw) > 0 {
			if err := json.Unmarshal(sparklineRaw, &h.sparkline); err != nil {
				return fmt.Errorf("RefreshOrgSnapshot sparkline unmarshal: %w", err)
			}
		}
		hosts = append(hosts, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("RefreshOrgSnapshot host_summary rows: %w", err)
	}

	// Step 2: no hosts = delete any existing snapshot and return.
	if len(hosts) == 0 {
		_, err := tx.Exec(ctx, `DELETE FROM org_snapshot WHERE org_id = $1`, orgID)
		if err != nil {
			return fmt.Errorf("RefreshOrgSnapshot delete empty snapshot: %w", err)
		}
		return nil
	}

	// Step 3: aggregate across all hosts.
	var totalFindings, safeFindings int
	for _, h := range hosts {
		totalFindings += h.totalFindings
		safeFindings += h.safeFindings
	}
	var readinessPct float64
	if totalFindings > 0 {
		readinessPct = float64(safeFindings) / float64(totalFindings) * 100
	}

	// Step 4: machine health tiers.
	machinesTotal := len(hosts)
	var machinesRed, machinesYellow, machinesGreen int
	for _, h := range hosts {
		switch {
		case h.unsafeFindings > 0:
			machinesRed++
		case h.deprecatedFindings > 0:
			machinesYellow++
		default:
			machinesGreen++
		}
	}

	// Step 5: monthly trend — merge all hosts' sparklines by month.
	// For each month, accumulate safe and total across hosts.
	type monthAccum struct {
		safe  int
		total int
	}
	monthMap := map[string]*monthAccum{}
	for _, h := range hosts {
		for _, pt := range h.sparkline {
			if _, ok := monthMap[pt.Month]; !ok {
				monthMap[pt.Month] = &monthAccum{}
			}
			// Reconstruct safe and total from readiness for this host's point.
			// We don't have per-month safe/total stored in sparkline — only readiness.
			// Use host total_findings as a proxy weight: safe = readiness/100 * total.
			// Actually we need to sum safe+total across hosts per month correctly.
			// Since SparklinePoint only stores readiness, we need to store safe/total
			// separately. We use total_findings of the host as the denominator estimate.
			// Better: approximate safe = round(readiness/100 * h.totalFindings),
			// total = h.totalFindings. This is approximate for merged trend.
			//
			// Note: host_summary sparkline stores readiness percent (0-100) per month.
			// We approximate per-month host weight using h.totalFindings as stable weight.
			// This gives a weighted average across hosts per month.
			accum := monthMap[pt.Month]
			hostTotal := h.totalFindings
			if hostTotal == 0 {
				hostTotal = 1 // avoid zero weight
			}
			hostSafe := int(pt.Readiness / 100.0 * float64(hostTotal))
			accum.safe += hostSafe
			accum.total += hostTotal
		}
	}

	// Sort months chronologically.
	months := make([]string, 0, len(monthMap))
	for m := range monthMap {
		months = append(months, m)
	}
	sort.Strings(months)

	monthlyTrend := make([]SparklinePoint, 0, len(months))
	for _, m := range months {
		acc := monthMap[m]
		var r float64
		if acc.total > 0 {
			r = float64(acc.safe) / float64(acc.total) * 100
		}
		monthlyTrend = append(monthlyTrend, SparklinePoint{Month: m, Readiness: r})
	}

	// Step 6: trend direction — compare last two monthly trend points.
	trendDirection := "insufficient"
	var trendDeltaPct float64
	if len(monthlyTrend) >= 2 {
		last := monthlyTrend[len(monthlyTrend)-1].Readiness
		prev := monthlyTrend[len(monthlyTrend)-2].Readiness
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

	// Step 7: get org config from organizations table.
	var targetPct float64
	var deadlineYear int
	err = tx.QueryRow(ctx,
		`SELECT COALESCE(executive_target_percent, 80.0), COALESCE(executive_deadline_year, 2030)
		 FROM organizations WHERE id = $1`,
		orgID,
	).Scan(&targetPct, &deadlineYear)
	if errors.Is(err, pgx.ErrNoRows) {
		targetPct = 80.0
		deadlineYear = 2030
	} else if err != nil {
		return fmt.Errorf("RefreshOrgSnapshot org config: %w", err)
	}

	// Step 8: projection — pace-based.
	projectionStatus := "insufficient-history"
	var projectedYear int
	if len(monthlyTrend) >= 2 {
		first := monthlyTrend[0].Readiness
		last := monthlyTrend[len(monthlyTrend)-1].Readiness
		numMonths := len(monthlyTrend) - 1
		pace := (last - first) / float64(numMonths)

		switch {
		case last >= targetPct:
			projectionStatus = "already-complete"
		case pace <= 0:
			projectionStatus = "regressing"
		case pace < 0.1:
			projectionStatus = "insufficient-movement"
		default:
			monthsNeeded := (targetPct - last) / pace
			currentYear := time.Now().Year()
			pyFloat := float64(currentYear) + monthsNeeded/12.0
			projectedYear = int(pyFloat)
			if pyFloat > float64(deadlineYear) {
				projectionStatus = "behind-schedule"
			} else {
				projectionStatus = "on-track"
			}
		}
	}

	// Step 9: top 5 blockers from findings table (latest scan per host).
	blockerRows, err := tx.Query(ctx,
		`WITH latest_scans AS (
		   SELECT DISTINCT ON (hostname) id FROM scans
		   WHERE org_id = $1 ORDER BY hostname, timestamp DESC
		 )
		 SELECT f.id, f.migration_priority, f.algorithm, f.key_size,
		        f.pqc_status, f.module, f.hostname, f.file_path
		 FROM findings f
		 JOIN latest_scans ls ON f.scan_id = ls.id
		 WHERE f.migration_priority > 0
		 ORDER BY f.migration_priority DESC
		 LIMIT 5`,
		orgID,
	)
	if err != nil {
		return fmt.Errorf("RefreshOrgSnapshot top blockers query: %w", err)
	}
	defer blockerRows.Close()

	topBlockers := []PriorityRow{}
	for blockerRows.Next() {
		var pr PriorityRow
		if err := blockerRows.Scan(
			&pr.FindingID, &pr.Priority, &pr.Algorithm, &pr.KeySize,
			&pr.PQCStatus, &pr.Module, &pr.Hostname, &pr.FilePath,
		); err != nil {
			return fmt.Errorf("RefreshOrgSnapshot top blockers scan: %w", err)
		}
		topBlockers = append(topBlockers, pr)
	}
	blockerRows.Close()
	if err := blockerRows.Err(); err != nil {
		return fmt.Errorf("RefreshOrgSnapshot top blockers rows: %w", err)
	}

	// Step 10: certificate rollup — sum from host_summary rows.
	var certsExpiring30d, certsExpiring90d, certsExpired int
	for _, h := range hosts {
		certsExpiring30d += h.certsExpiring30d
		certsExpiring90d += h.certsExpiring90d
		certsExpired += h.certsExpired
	}

	// Step 11: policy verdicts — empty for Phase 4A.
	policyVerdicts := []PolicyVerdictSummary{}

	// Marshal JSONB columns.
	monthlyTrendJSON, err := json.Marshal(monthlyTrend)
	if err != nil {
		return fmt.Errorf("RefreshOrgSnapshot monthly_trend marshal: %w", err)
	}
	policyVerdictsJSON, err := json.Marshal(policyVerdicts)
	if err != nil {
		return fmt.Errorf("RefreshOrgSnapshot policy_verdicts marshal: %w", err)
	}
	topBlockersJSON, err := json.Marshal(topBlockers)
	if err != nil {
		return fmt.Errorf("RefreshOrgSnapshot top_blockers marshal: %w", err)
	}

	// Step 12: UPSERT into org_snapshot.
	_, err = tx.Exec(ctx,
		`INSERT INTO org_snapshot (
		   org_id, readiness_pct, total_findings, safe_findings,
		   machines_total, machines_red, machines_yellow, machines_green,
		   trend_direction, trend_delta_pct, monthly_trend, projection_status,
		   projected_year, target_pct, deadline_year, policy_verdicts,
		   top_blockers, certs_expiring_30d, certs_expiring_90d, certs_expired,
		   refreshed_at
		 ) VALUES (
		   $1, $2, $3, $4,
		   $5, $6, $7, $8,
		   $9, $10, $11, $12,
		   $13, $14, $15, $16,
		   $17, $18, $19, $20,
		   NOW()
		 )
		 ON CONFLICT (org_id) DO UPDATE SET
		   readiness_pct         = EXCLUDED.readiness_pct,
		   total_findings        = EXCLUDED.total_findings,
		   safe_findings         = EXCLUDED.safe_findings,
		   machines_total        = EXCLUDED.machines_total,
		   machines_red          = EXCLUDED.machines_red,
		   machines_yellow       = EXCLUDED.machines_yellow,
		   machines_green        = EXCLUDED.machines_green,
		   trend_direction       = EXCLUDED.trend_direction,
		   trend_delta_pct       = EXCLUDED.trend_delta_pct,
		   monthly_trend         = EXCLUDED.monthly_trend,
		   projection_status     = EXCLUDED.projection_status,
		   projected_year        = EXCLUDED.projected_year,
		   target_pct            = EXCLUDED.target_pct,
		   deadline_year         = EXCLUDED.deadline_year,
		   policy_verdicts       = EXCLUDED.policy_verdicts,
		   top_blockers          = EXCLUDED.top_blockers,
		   certs_expiring_30d    = EXCLUDED.certs_expiring_30d,
		   certs_expiring_90d    = EXCLUDED.certs_expiring_90d,
		   certs_expired         = EXCLUDED.certs_expired,
		   refreshed_at          = NOW()`,
		orgID, readinessPct, totalFindings, safeFindings,
		machinesTotal, machinesRed, machinesYellow, machinesGreen,
		trendDirection, trendDeltaPct, monthlyTrendJSON, projectionStatus,
		projectedYear, targetPct, deadlineYear, policyVerdictsJSON,
		topBlockersJSON, certsExpiring30d, certsExpiring90d, certsExpired,
	)
	if err != nil {
		return fmt.Errorf("RefreshOrgSnapshot upsert: %w", err)
	}

	return tx.Commit(ctx)
}

// GetOrgSnapshot returns the pre-computed org snapshot for the given org,
// or nil if the pipeline hasn't run yet. Analytics Phase 4A.
func (s *PostgresStore) GetOrgSnapshot(ctx context.Context, orgID string) (*OrgSnapshot, error) {
	var snap OrgSnapshot
	var monthlyTrendRaw, policyVerdictsRaw, topBlockersRaw []byte

	err := s.pool.QueryRow(ctx,
		`SELECT org_id, readiness_pct, total_findings, safe_findings,
		        machines_total, machines_red, machines_yellow, machines_green,
		        trend_direction, trend_delta_pct, monthly_trend, projection_status,
		        projected_year, target_pct, deadline_year, policy_verdicts,
		        top_blockers, certs_expiring_30d, certs_expiring_90d, certs_expired,
		        refreshed_at
		 FROM org_snapshot WHERE org_id = $1`,
		orgID,
	).Scan(
		&snap.OrgID, &snap.ReadinessPct, &snap.TotalFindings, &snap.SafeFindings,
		&snap.MachinesTotal, &snap.MachinesRed, &snap.MachinesYellow, &snap.MachinesGreen,
		&snap.TrendDirection, &snap.TrendDeltaPct, &monthlyTrendRaw, &snap.ProjectionStatus,
		&snap.ProjectedYear, &snap.TargetPct, &snap.DeadlineYear, &policyVerdictsRaw,
		&topBlockersRaw, &snap.CertsExpiring30d, &snap.CertsExpiring90d, &snap.CertsExpired,
		&snap.RefreshedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetOrgSnapshot query: %w", err)
	}

	if len(monthlyTrendRaw) > 0 {
		if err := json.Unmarshal(monthlyTrendRaw, &snap.MonthlyTrend); err != nil {
			return nil, fmt.Errorf("GetOrgSnapshot monthly_trend unmarshal: %w", err)
		}
	}
	if len(policyVerdictsRaw) > 0 {
		if err := json.Unmarshal(policyVerdictsRaw, &snap.PolicyVerdicts); err != nil {
			return nil, fmt.Errorf("GetOrgSnapshot policy_verdicts unmarshal: %w", err)
		}
	}
	if len(topBlockersRaw) > 0 {
		if err := json.Unmarshal(topBlockersRaw, &snap.TopBlockers); err != nil {
			return nil, fmt.Errorf("GetOrgSnapshot top_blockers unmarshal: %w", err)
		}
	}

	return &snap, nil
}
