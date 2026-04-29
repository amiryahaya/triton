package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// NacsaSummary is the response for GET /api/v1/nacsa/summary.
type NacsaSummary struct {
	ReadinessPct    float64        `json:"readiness_pct"`
	TargetPct       float64        `json:"target_pct"`
	TargetYear      int            `json:"target_year"`
	Compliant       int64          `json:"compliant"`
	Transitional    int64          `json:"transitional"`
	NonCompliant    int64          `json:"non_compliant"`
	Safe            int64          `json:"safe"`
	TotalAssets     int64          `json:"total_assets"`
	TopBlockers     []NacsaBlocker `json:"top_blockers"`
	MigrationPhases []NacsaPhase   `json:"migration_phases"`
}

// NacsaBlocker is one top-blocker entry in NacsaSummary.
type NacsaBlocker struct {
	Algorithm  string `json:"algorithm"`
	Hostname   string `json:"hostname"`
	Severity   string `json:"severity"`
	AssetCount int64  `json:"asset_count"`
}

// NacsaPhase is migration-phase progress in NacsaSummary.
type NacsaPhase struct {
	Phase       int    `json:"phase"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	ProgressPct int    `json:"progress_pct"`
}

// NacsaServerRow is one row for GET /api/v1/nacsa/servers.
type NacsaServerRow struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	HostCount    int64      `json:"host_count"`
	ReadinessPct float64    `json:"readiness_pct"`
	LastScanAt   *time.Time `json:"last_scan_at,omitempty"`
}

// NacsaHostRow is one row for GET /api/v1/nacsa/servers/{id}/hosts.
type NacsaHostRow struct {
	Hostname     string     `json:"hostname"`
	ScanProfile  string     `json:"scan_profile,omitempty"`
	ReadinessPct float64    `json:"readiness_pct"`
	LastScanAt   *time.Time `json:"last_scan_at,omitempty"`
	ModuleCount  int64      `json:"module_count"`
}

// NacsaCBOMRow is one algorithm row for GET /api/v1/nacsa/hosts/{hostname}/cbom.
type NacsaCBOMRow struct {
	Algorithm  string `json:"algorithm"`
	KeySize    int    `json:"key_size,omitempty"`
	PQCStatus  string `json:"pqc_status"`
	AssetCount int64  `json:"asset_count"`
	Module     string `json:"module"`
}

// NacsaRiskRow is one risk entry for GET /api/v1/nacsa/hosts/{hostname}/risk.
type NacsaRiskRow struct {
	Algorithm  string `json:"algorithm"`
	Hostname   string `json:"hostname"`
	Impact     int    `json:"impact"`
	Likelihood int    `json:"likelihood"`
	Score      int    `json:"score"`
	RiskBand   string `json:"risk_band"`
	AssetCount int64  `json:"asset_count"`
}

// NacsaMigResponse is the response for GET /api/v1/nacsa/migration.
type NacsaMigResponse struct {
	Phases []NacsaMigPhase `json:"phases"`
}

// NacsaMigPhase is one migration phase in NacsaMigResponse.
type NacsaMigPhase struct {
	Phase         int                `json:"phase"`
	Name          string             `json:"name"`
	Status        string             `json:"status"`
	ProgressPct   int                `json:"progress_pct"`
	Period        string             `json:"period"`
	Activities    []NacsaMigActivity `json:"activities"`
	BudgetTotalRM int64              `json:"budget_total_rm"`
	BudgetSpentRM int64              `json:"budget_spent_rm"`
}

// NacsaMigActivity is one activity row in NacsaMigPhase.
type NacsaMigActivity struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	BudgetRM int64  `json:"budget_rm"`
}

// NacsaScopeFilter restricts NACSA queries to a specific manage server
// and/or hostname. Zero values mean "show all".
type NacsaScopeFilter struct {
	ManageServerID string
	Hostname       string
}

// nacsaReadinessPct computes NACSA readiness % from safe/total.
func nacsaReadinessPct(safe, total int64) float64 {
	if total == 0 {
		return 0
	}
	return float64(safe) / float64(total) * 100
}

// nacsaRiskBand converts a score to a risk band label.
func nacsaRiskBand(score int) string {
	switch {
	case score >= 20:
		return "CRITICAL"
	case score >= 10:
		return "HIGH"
	case score >= 5:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// nacsaImpactLikelihood returns default impact and likelihood for a pqc_status.
func nacsaImpactLikelihood(pqcStatus string, migrationPriority int) (impact, likelihood int) {
	switch pqcStatus {
	case "UNSAFE":
		impact, likelihood = 5, 4
	case "DEPRECATED":
		impact, likelihood = 4, 2
	case "TRANSITIONAL":
		impact, likelihood = 3, 3
	default:
		impact, likelihood = 1, 1
	}
	if migrationPriority > 0 && migrationPriority < 5 {
		likelihood = migrationPriority
	}
	return
}

// latestScansCTE returns a WITH clause fragment filtering to latest scan
// per hostname within the given org.
func latestScansCTE(orgID string, scope NacsaScopeFilter) (cte string, args []any) {
	args = []any{orgID}
	where := "WHERE org_id = $1"
	if scope.ManageServerID != "" {
		args = append(args, scope.ManageServerID)
		where += fmt.Sprintf(" AND manage_server_id = $%d", len(args))
	}
	if scope.Hostname != "" {
		args = append(args, scope.Hostname)
		where += fmt.Sprintf(" AND hostname = $%d", len(args))
	}
	cte = fmt.Sprintf(`latest_scans AS (
        SELECT DISTINCT ON (hostname) id, org_id, manage_server_id, manage_server_name
        FROM scans
        %s
        ORDER BY hostname, timestamp DESC
    )`, where)
	return cte, args
}

// GetNacsaSummary returns the tenant-level NACSA summary.
func (s *PostgresStore) GetNacsaSummary(ctx context.Context, orgID string, scope NacsaScopeFilter) (NacsaSummary, error) {
	cte, args := latestScansCTE(orgID, scope)

	q := fmt.Sprintf(`
WITH %s
SELECT
    COALESCE(SUM(CASE WHEN f.pqc_status = 'SAFE'         THEN 1 ELSE 0 END), 0) AS safe_count,
    COALESCE(SUM(CASE WHEN f.pqc_status = 'TRANSITIONAL' THEN 1 ELSE 0 END), 0) AS trans_count,
    COALESCE(SUM(CASE WHEN f.pqc_status IN ('DEPRECATED','UNSAFE') THEN 1 ELSE 0 END), 0) AS noncompliant_count,
    COUNT(*) AS total_count
FROM findings f
JOIN latest_scans ls ON f.scan_id = ls.id
WHERE f.org_id = $1`, cte)

	var safe, trans, noncompliant, total int64
	err := s.pool.QueryRow(ctx, q, args...).Scan(&safe, &trans, &noncompliant, &total)
	if err != nil {
		return NacsaSummary{}, fmt.Errorf("nacsa summary counts: %w", err)
	}

	// Top blockers: UNSAFE findings grouped by algorithm+hostname.
	cte2, args2 := latestScansCTE(orgID, scope)
	bq := fmt.Sprintf(`
WITH %s
SELECT f.algorithm, f.hostname, COUNT(*) AS cnt
FROM findings f
JOIN latest_scans ls ON f.scan_id = ls.id
WHERE f.org_id = $1 AND f.pqc_status = 'UNSAFE'
GROUP BY f.algorithm, f.hostname
ORDER BY cnt DESC
LIMIT 5`, cte2)

	rows, err := s.pool.Query(ctx, bq, args2...)
	if err != nil {
		return NacsaSummary{}, fmt.Errorf("nacsa top blockers: %w", err)
	}
	defer rows.Close()
	var blockers []NacsaBlocker
	for rows.Next() {
		var b NacsaBlocker
		if err := rows.Scan(&b.Algorithm, &b.Hostname, &b.AssetCount); err != nil {
			return NacsaSummary{}, err
		}
		b.Severity = "CRITICAL"
		blockers = append(blockers, b)
	}
	if err := rows.Err(); err != nil {
		return NacsaSummary{}, err
	}

	phases, err := s.listNacsaPhasesSummary(ctx, orgID)
	if err != nil {
		return NacsaSummary{}, err
	}

	if blockers == nil {
		blockers = []NacsaBlocker{}
	}

	return NacsaSummary{
		ReadinessPct:    nacsaReadinessPct(safe, total),
		TargetPct:       80,
		TargetYear:      2030,
		Compliant:       safe,
		Transitional:    trans,
		NonCompliant:    noncompliant,
		Safe:            safe,
		TotalAssets:     total,
		TopBlockers:     blockers,
		MigrationPhases: phases,
	}, nil
}

// listNacsaPhasesSummary returns the migration phases for a summary card.
func (s *PostgresStore) listNacsaPhasesSummary(ctx context.Context, orgID string) ([]NacsaPhase, error) {
	rows, err := s.pool.Query(ctx, `
        SELECT phase, name, status, progress_pct
        FROM nacsa_migration_phases
        WHERE org_id = $1
        ORDER BY phase`, orgID)
	if err != nil {
		return nil, fmt.Errorf("nacsa phases: %w", err)
	}
	defer rows.Close()
	var phases []NacsaPhase
	for rows.Next() {
		var p NacsaPhase
		if err := rows.Scan(&p.Phase, &p.Name, &p.Status, &p.ProgressPct); err != nil {
			return nil, err
		}
		phases = append(phases, p)
	}
	if phases == nil {
		phases = []NacsaPhase{}
	}
	return phases, rows.Err()
}

// ListNacsaServers groups scans by manage_server_id and returns readiness per server.
func (s *PostgresStore) ListNacsaServers(ctx context.Context, orgID string) ([]NacsaServerRow, error) {
	rows, err := s.pool.Query(ctx, `
WITH latest AS (
    SELECT DISTINCT ON (hostname)
        manage_server_id, manage_server_name, timestamp,
        safe, unsafe, deprecated, transitional,
        (safe + unsafe + deprecated + transitional) AS total
    FROM scans
    WHERE org_id = $1 AND manage_server_id IS NOT NULL
    ORDER BY hostname, timestamp DESC
)
SELECT
    manage_server_id,
    MAX(manage_server_name)   AS name,
    COUNT(*)                  AS host_count,
    CASE WHEN SUM(total) = 0 THEN 0
         ELSE ROUND(SUM(safe)::numeric / SUM(total)::numeric * 100, 1)
    END                       AS readiness_pct,
    MAX(timestamp)            AS last_scan_at
FROM latest
GROUP BY manage_server_id
ORDER BY readiness_pct DESC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("nacsa servers: %w", err)
	}
	defer rows.Close()
	var result []NacsaServerRow
	for rows.Next() {
		var r NacsaServerRow
		if err := rows.Scan(&r.ID, &r.Name, &r.HostCount, &r.ReadinessPct, &r.LastScanAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	if result == nil {
		result = []NacsaServerRow{}
	}
	return result, rows.Err()
}

// ListNacsaHosts returns hosts for a specific manage server.
func (s *PostgresStore) ListNacsaHosts(ctx context.Context, orgID, manageServerID string) ([]NacsaHostRow, error) {
	rows, err := s.pool.Query(ctx, `
SELECT DISTINCT ON (hostname)
    hostname,
    profile,
    CASE WHEN (safe + unsafe + deprecated + transitional) = 0 THEN 0
         ELSE ROUND(safe::numeric / (safe + unsafe + deprecated + transitional)::numeric * 100, 1)
    END AS readiness_pct,
    timestamp,
    0 AS module_count
FROM scans
WHERE org_id = $1 AND manage_server_id = $2
ORDER BY hostname, timestamp DESC`, orgID, manageServerID)
	if err != nil {
		return nil, fmt.Errorf("nacsa hosts: %w", err)
	}
	defer rows.Close()
	var result []NacsaHostRow
	for rows.Next() {
		var r NacsaHostRow
		if err := rows.Scan(&r.Hostname, &r.ScanProfile, &r.ReadinessPct, &r.LastScanAt, &r.ModuleCount); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	if result == nil {
		result = []NacsaHostRow{}
	}
	return result, rows.Err()
}

// ListNacsaCBOM returns crypto algorithm inventory for a hostname.
func (s *PostgresStore) ListNacsaCBOM(ctx context.Context, orgID, hostname string, statuses []string) ([]NacsaCBOMRow, error) {
	q := `
WITH latest AS (
    SELECT DISTINCT ON (hostname) id
    FROM scans
    WHERE org_id = $1 AND hostname = $2
    ORDER BY hostname, timestamp DESC
)
SELECT f.algorithm, f.key_size, f.pqc_status, COUNT(*) AS cnt, f.module
FROM findings f
JOIN latest l ON f.scan_id = l.id
WHERE f.org_id = $1`

	args := []any{orgID, hostname}
	if len(statuses) > 0 {
		placeholders := make([]string, len(statuses))
		for i, st := range statuses {
			args = append(args, st)
			placeholders[i] = fmt.Sprintf("$%d", len(args))
		}
		q += fmt.Sprintf(" AND f.pqc_status IN (%s)", strings.Join(placeholders, ","))
	}
	q += `
GROUP BY f.algorithm, f.key_size, f.pqc_status, f.module
ORDER BY
    CASE f.pqc_status WHEN 'UNSAFE' THEN 1 WHEN 'DEPRECATED' THEN 2 WHEN 'TRANSITIONAL' THEN 3 ELSE 4 END,
    cnt DESC`

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("nacsa cbom: %w", err)
	}
	defer rows.Close()
	var result []NacsaCBOMRow
	for rows.Next() {
		var r NacsaCBOMRow
		if err := rows.Scan(&r.Algorithm, &r.KeySize, &r.PQCStatus, &r.AssetCount, &r.Module); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	if result == nil {
		result = []NacsaCBOMRow{}
	}
	return result, rows.Err()
}

// ListNacsaRisk returns risk register rows derived from findings.
func (s *PostgresStore) ListNacsaRisk(ctx context.Context, orgID, hostname, sortBy string) ([]NacsaRiskRow, error) {
	whereExtra := ""
	args := []any{orgID}
	if hostname != "" {
		args = append(args, hostname)
		whereExtra = fmt.Sprintf(" AND f.hostname = $%d", len(args))
	}

	q := fmt.Sprintf(`
WITH latest AS (
    SELECT DISTINCT ON (hostname) id
    FROM scans
    WHERE org_id = $1
    ORDER BY hostname, timestamp DESC
)
SELECT
    f.algorithm,
    f.hostname,
    f.pqc_status,
    MAX(COALESCE(f.migration_priority, 0)) AS max_priority,
    COUNT(*) AS asset_count
FROM findings f
JOIN latest l ON f.scan_id = l.id
WHERE f.org_id = $1
  AND f.pqc_status IN ('UNSAFE','DEPRECATED','TRANSITIONAL')
  %s
GROUP BY f.algorithm, f.hostname, f.pqc_status
`, whereExtra)

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("nacsa risk: %w", err)
	}
	defer rows.Close()
	var result []NacsaRiskRow
	for rows.Next() {
		var algo, host, status string
		var maxPriority int
		var cnt int64
		if err := rows.Scan(&algo, &host, &status, &maxPriority, &cnt); err != nil {
			return nil, err
		}
		impact, likelihood := nacsaImpactLikelihood(status, maxPriority)
		score := impact * likelihood
		result = append(result, NacsaRiskRow{
			Algorithm:  algo,
			Hostname:   host,
			Impact:     impact,
			Likelihood: likelihood,
			Score:      score,
			RiskBand:   nacsaRiskBand(score),
			AssetCount: cnt,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool {
		switch sortBy {
		case "impact":
			if result[i].Impact != result[j].Impact {
				return result[i].Impact > result[j].Impact
			}
			return result[i].Score > result[j].Score
		case "hostname":
			if result[i].Hostname != result[j].Hostname {
				return result[i].Hostname < result[j].Hostname
			}
			return result[i].Score > result[j].Score
		default:
			return result[i].Score > result[j].Score
		}
	})
	if result == nil {
		result = []NacsaRiskRow{}
	}
	return result, nil
}

// GetNacsaMigration returns phase + activity data.
func (s *PostgresStore) GetNacsaMigration(ctx context.Context, orgID string) (NacsaMigResponse, error) {
	rows, err := s.pool.Query(ctx, `
        SELECT phase, name, period, status, progress_pct
        FROM nacsa_migration_phases
        WHERE org_id = $1
        ORDER BY phase`, orgID)
	if err != nil {
		return NacsaMigResponse{}, fmt.Errorf("nacsa migration phases: %w", err)
	}
	defer rows.Close()
	phaseMap := map[int]*NacsaMigPhase{}
	var phases []NacsaMigPhase
	for rows.Next() {
		var p NacsaMigPhase
		if err := rows.Scan(&p.Phase, &p.Name, &p.Period, &p.Status, &p.ProgressPct); err != nil {
			return NacsaMigResponse{}, err
		}
		phases = append(phases, p)
		phaseMap[p.Phase] = &phases[len(phases)-1]
	}
	if err := rows.Err(); err != nil {
		return NacsaMigResponse{}, err
	}

	aRows, err := s.pool.Query(ctx, `
        SELECT phase, name, status, budget_rm
        FROM nacsa_migration_activities
        WHERE org_id = $1
        ORDER BY phase, sort_order`, orgID)
	if err != nil {
		return NacsaMigResponse{}, fmt.Errorf("nacsa migration activities: %w", err)
	}
	defer aRows.Close()
	for aRows.Next() {
		var phaseNum int
		var a NacsaMigActivity
		if err := aRows.Scan(&phaseNum, &a.Name, &a.Status, &a.BudgetRM); err != nil {
			return NacsaMigResponse{}, err
		}
		if p, ok := phaseMap[phaseNum]; ok {
			p.Activities = append(p.Activities, a)
			p.BudgetTotalRM += a.BudgetRM
			if a.Status == "done" {
				p.BudgetSpentRM += a.BudgetRM
			}
		}
	}
	if err := aRows.Err(); err != nil {
		return NacsaMigResponse{}, err
	}

	if phases == nil {
		phases = []NacsaMigPhase{}
	}

	return NacsaMigResponse{Phases: phases}, nil
}
