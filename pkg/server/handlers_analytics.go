package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/analytics"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/policy"
	"github.com/amiryahaya/triton/pkg/store"
)

// Analytics Phase 1 handlers — see
// docs/plans/2026-04-09-analytics-phase-1-plan.md Appendix A.
//
// The three analytics endpoints share two invariants:
//
//  1. The X-Backfill-In-Progress header is set whenever the server's
//     backfillInProgress atomic flag is true, so the UI can render an
//     inline banner warning that historical data is still loading.
//
//  2. An empty result is returned as `[]` (a JSON array) and status
//     200, never a 404 — "no findings yet" is a normal state for a
//     fresh org, not an error.

// GET /api/v1/inventory
//
// Returns the crypto inventory aggregated by (algorithm, key_size)
// for the authenticated tenant, filtered to the latest scan per host.
// No query parameters. Empty array if no findings yet.
// GET /api/v1/filters
//
// Returns distinct hostnames, algorithms, and PQC statuses for the
// org's latest scans. Used to populate filter dropdowns in the UI.
func (s *Server) handleFilterOptions(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	opts, err := s.store.ListFilterOptions(r.Context(), orgID)
	if err != nil {
		log.Printf("filters: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	if s.backfillInProgress.Load() {
		w.Header().Set("X-Backfill-In-Progress", "true")
	}
	orgID := TenantFromContext(r.Context())
	fp := store.FilterParams{
		Hostname:  r.URL.Query().Get("hostname"),
		PQCStatus: r.URL.Query().Get("pqc_status"),
	}
	rows, err := s.store.ListInventory(r.Context(), orgID, fp)
	if err != nil {
		log.Printf("inventory: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rows == nil {
		rows = []store.InventoryRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/certificates/expiring?within=<days>|all
//
// Returns certificates (findings with a non-null NotAfter) sorted
// ascending by expiry. Already-expired certs are ALWAYS included
// regardless of the within window.
//
//	within=<N>   certs expiring within N days from now (N must be 0-3650)
//	within=all   certs with any future expiry (handler passes a
//	             100-year interval internally)
//	(missing)    default 90 days
func (s *Server) handleExpiringCertificates(w http.ResponseWriter, r *http.Request) {
	if s.backfillInProgress.Load() {
		w.Header().Set("X-Backfill-In-Progress", "true")
	}
	orgID := TenantFromContext(r.Context())

	withinParam := strings.TrimSpace(r.URL.Query().Get("within"))
	var within time.Duration
	switch withinParam {
	case "":
		within = 90 * 24 * time.Hour
	case "all":
		within = 100 * 365 * 24 * time.Hour
	default:
		days, err := strconv.Atoi(withinParam)
		if err != nil || days < 0 || days > 3650 {
			writeError(w, http.StatusBadRequest,
				"within must be a non-negative integer (days, 0-3650) or 'all'")
			return
		}
		within = time.Duration(days) * 24 * time.Hour
	}

	certFP := store.FilterParams{
		Hostname:  r.URL.Query().Get("hostname"),
		Algorithm: r.URL.Query().Get("algorithm"),
	}
	rows, err := s.store.ListExpiringCertificates(r.Context(), orgID, within, certFP)
	if err != nil {
		log.Printf("expiring certs: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rows == nil {
		rows = []store.ExpiringCertRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/priority?limit=<N>
//
// Returns the top N findings by migration_priority descending,
// filtered to the latest scan per hostname. Findings with priority 0
// are excluded by the store query. limit missing → 20 (the UI
// default), otherwise must be in [1, 1000] — the upper bound is a
// DoS guard, not a hard product constraint.
func (s *Server) handlePriorityFindings(w http.ResponseWriter, r *http.Request) {
	if s.backfillInProgress.Load() {
		w.Header().Set("X-Backfill-In-Progress", "true")
	}
	orgID := TenantFromContext(r.Context())

	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, "limit must be between 1 and 1000")
			return
		}
		limit = n
	}

	prioFP := store.FilterParams{
		Hostname:  r.URL.Query().Get("hostname"),
		PQCStatus: r.URL.Query().Get("pqc_status"),
	}
	rows, err := s.store.ListTopPriorityFindings(r.Context(), orgID, limit, prioFP)
	if err != nil {
		log.Printf("priority: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rows == nil {
		rows = []store.PriorityRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// GET /api/v1/executive
//
// Returns a single-round-trip ExecutiveSummary for the authenticated
// tenant, driven by the org's per-org executive_target_percent and
// executive_deadline_year settings. See
// docs/plans/2026-04-10-analytics-phase-2-design.md §4 for the full
// response contract.
func (s *Server) handleExecutiveSummary(w http.ResponseWriter, r *http.Request) {
	if s.backfillInProgress.Load() {
		w.Header().Set("X-Backfill-In-Progress", "true")
	}
	orgID := TenantFromContext(r.Context())

	// Fetch per-org settings for the projection math. Empty orgID
	// (single-tenant mode) skips the lookup and uses defaults.
	targetPercent := 80.0
	deadlineYear := 2030
	if orgID != "" {
		org, err := s.store.GetOrg(r.Context(), orgID)
		if err != nil {
			var nf *store.ErrNotFound
			if !errors.As(err, &nf) {
				log.Printf("executive: get org: %v", err)
				writeError(w, http.StatusInternalServerError, "internal server error")
				return
			}
			// Org not found — fall through with defaults.
		} else {
			targetPercent = org.ExecutiveTargetPercent
			deadlineYear = org.ExecutiveDeadlineYear
		}
	}

	// Fetch all scan summaries in chronological order for the trend.
	summaries, err := s.store.ListScansOrderedByTime(r.Context(), orgID)
	if err != nil {
		log.Printf("executive: list scans: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	latestPerHost := analytics.LatestByHostname(summaries)

	// Compute the pure-math parts.
	trend := analytics.ComputeOrgTrend(summaries)
	projection := analytics.ComputeProjection(trend, targetPercent, deadlineYear)
	machineHealth := analytics.ComputeMachineHealth(latestPerHost)

	// Compute readiness from the latest-per-host summaries.
	readiness := analytics.ComputeReadiness(latestPerHost)

	// Top-5 blockers from Phase 1 store method.
	topBlockers, err := s.store.ListTopPriorityFindings(r.Context(), orgID, 5, store.FilterParams{})
	if err != nil {
		log.Printf("executive: top blockers: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if topBlockers == nil {
		topBlockers = []store.PriorityRow{}
	}

	// Evaluate both built-in policies against each latest scan and
	// aggregate the verdicts.
	policyVerdicts, err := s.computePolicyVerdicts(r.Context(), orgID, latestPerHost)
	if err != nil {
		log.Printf("executive: policy verdicts: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	out := store.ExecutiveSummary{
		Readiness:      readiness,
		Trend:          trend,
		Projection:     projection,
		PolicyVerdicts: policyVerdicts,
		TopBlockers:    topBlockers,
		MachineHealth:  machineHealth,
	}
	writeJSON(w, http.StatusOK, out)
}

// computePolicyVerdicts evaluates both built-in policies against
// each latest scan in the org and aggregates the results.
// Scans are fetched once and reused across all policies to avoid
// N×M DB round-trips (/pensive:full-review B-D2).
// Verdict aggregation: worst wins (FAIL > WARN > PASS). Counts sum.
func (s *Server) computePolicyVerdicts(ctx context.Context, orgID string, latestPerHost []store.ScanSummary) ([]store.PolicyVerdictSummary, error) {
	type policyDef struct {
		name  string
		label string
	}
	builtins := []policyDef{
		{name: "nacsa-2030", label: "NACSA-2030"},
		{name: "cnsa-2.0", label: "CNSA-2.0"},
	}

	if len(latestPerHost) == 0 {
		out := make([]store.PolicyVerdictSummary, 0, len(builtins))
		for _, def := range builtins {
			out = append(out, store.PolicyVerdictSummary{
				PolicyName:  def.name,
				PolicyLabel: def.label,
				Verdict:     "PASS",
			})
		}
		return out, nil
	}

	// Fetch all scan results ONCE, reuse across all policies.
	scanResults := make(map[string]*model.ScanResult, len(latestPerHost))
	for _, summary := range latestPerHost {
		scan, err := s.store.GetScan(ctx, summary.ID, orgID)
		if err != nil {
			return nil, fmt.Errorf("get scan %s: %w", summary.ID, err)
		}
		scanResults[summary.ID] = scan
	}

	out := make([]store.PolicyVerdictSummary, 0, len(builtins))
	for _, def := range builtins {
		pol, err := policy.LoadBuiltin(def.name)
		if err != nil {
			return nil, fmt.Errorf("load builtin %q: %w", def.name, err)
		}

		verdict := "PASS"
		var totalViolations, totalFindings int
		for _, summary := range latestPerHost {
			result := policy.Evaluate(pol, scanResults[summary.ID])
			totalViolations += len(result.Violations)
			totalFindings += result.FindingsChecked
			verdict = worstVerdict(verdict, string(result.Verdict))
		}

		out = append(out, store.PolicyVerdictSummary{
			PolicyName:      def.name,
			PolicyLabel:     def.label,
			Verdict:         verdict,
			ViolationCount:  totalViolations,
			FindingsChecked: totalFindings,
		})
	}
	return out, nil
}

// GET /api/v1/systems?pqc_status=X
//
// Returns per-host summary rows from the pre-computed host_summary table.
// Sorted by readiness_pct ASC (worst first). Includes staleness metadata.
func (s *Server) handleSystems(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	pqcFilter := r.URL.Query().Get("pqc_status")

	rows, err := s.store.ListHostSummaries(r.Context(), orgID, pqcFilter)
	if err != nil {
		log.Printf("systems: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rows == nil {
		rows = []store.HostSummary{}
	}

	// Staleness: oldest refreshed_at across all rows
	var dataAsOf time.Time
	if len(rows) > 0 {
		dataAsOf = rows[0].RefreshedAt
		for i := 1; i < len(rows); i++ {
			if rows[i].RefreshedAt.Before(dataAsOf) {
				dataAsOf = rows[i].RefreshedAt
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"data":        rows,
		"dataAsOf":    dataAsOf,
		"pipelineLag": int(time.Since(dataAsOf).Seconds()),
	})
}

// GET /api/v1/trends?hostname=X
//
// Returns monthly trend data. Without hostname: org-wide from org_snapshot.
// With hostname: per-host from host_summary sparkline.
func (s *Server) handleTrends(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	hostname := r.URL.Query().Get("hostname")

	if hostname != "" {
		// Per-host trend: find the host in host_summary
		rows, err := s.store.ListHostSummaries(r.Context(), orgID, "")
		if err != nil {
			log.Printf("trends: %v", err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		for i := range rows {
			if rows[i].Hostname == hostname {
				row := &rows[i]
				writeJSON(w, http.StatusOK, map[string]any{
					"monthlyPoints": row.Sparkline,
					"direction":     row.TrendDirection,
					"deltaPct":      row.TrendDeltaPct,
					"dataAsOf":      row.RefreshedAt,
					"pipelineLag":   int(time.Since(row.RefreshedAt).Seconds()),
				})
				return
			}
		}
		// Host not found — return empty
		writeJSON(w, http.StatusOK, map[string]any{
			"monthlyPoints": []store.SparklinePoint{},
			"direction":     "insufficient",
			"deltaPct":      0,
		})
		return
	}

	// Org-wide trend from org_snapshot
	snap, err := s.store.GetOrgSnapshot(r.Context(), orgID)
	if err != nil {
		log.Printf("trends: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if snap == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"monthlyPoints": []store.SparklinePoint{},
			"direction":     "insufficient",
			"deltaPct":      0,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"monthlyPoints": snap.MonthlyTrend,
		"direction":     snap.TrendDirection,
		"deltaPct":      snap.TrendDeltaPct,
		"dataAsOf":      snap.RefreshedAt,
		"pipelineLag":   int(time.Since(snap.RefreshedAt).Seconds()),
	})
}

// GET /api/v1/pipeline/status
//
// Returns the current pipeline processing state. Used by the UI's
// staleness bar to show "Processing..." when jobs are queued.
func (s *Server) handlePipelineStatus(w http.ResponseWriter, r *http.Request) {
	if s.pipeline == nil {
		writeJSON(w, http.StatusOK, store.PipelineStatus{Status: "idle"})
		return
	}
	writeJSON(w, http.StatusOK, s.pipeline.Status())
}

// worstVerdict returns the more severe of two policy verdicts.
// Severity order: FAIL > WARN > PASS. Unknown strings fail-safe
// to FAIL (/pensive:full-review B-D4).
func worstVerdict(a, b string) string {
	rank := map[string]int{"PASS": 0, "WARN": 1, "FAIL": 2}
	ra, aok := rank[a]
	rb, bok := rank[b]
	if !aok || !bok {
		return "FAIL"
	}
	if rb > ra {
		return b
	}
	return a
}
