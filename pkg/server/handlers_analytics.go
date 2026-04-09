package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amiryahaya/triton/pkg/analytics"
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
func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	if s.backfillInProgress.Load() {
		w.Header().Set("X-Backfill-In-Progress", "true")
	}
	orgID := TenantFromContext(r.Context())
	rows, err := s.store.ListInventory(r.Context(), orgID)
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

	rows, err := s.store.ListExpiringCertificates(r.Context(), orgID, within)
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

	rows, err := s.store.ListTopPriorityFindings(r.Context(), orgID, limit)
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
	readiness := computeReadiness(latestPerHost)

	// Top-5 blockers from Phase 1 store method.
	topBlockers, err := s.store.ListTopPriorityFindings(r.Context(), orgID, 5)
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

// computeReadiness sums safe and total findings across the latest
// scan per host and returns the ReadinessSummary.
func computeReadiness(latestPerHost []store.ScanSummary) store.ReadinessSummary {
	var safe, total int
	for _, s := range latestPerHost {
		safe += s.Safe
		total += s.Safe + s.Transitional + s.Deprecated + s.Unsafe
	}
	percent := 0.0
	if total > 0 {
		percent = math.Round(float64(safe)/float64(total)*1000) / 10 // 1 decimal
	}
	return store.ReadinessSummary{
		Percent:       percent,
		TotalFindings: total,
		SafeFindings:  safe,
	}
}

// computePolicyVerdicts evaluates both built-in policies against
// each latest scan in the org and aggregates the results.
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

	out := make([]store.PolicyVerdictSummary, 0, len(builtins))
	for _, def := range builtins {
		pol, err := policy.LoadBuiltin(def.name)
		if err != nil {
			return nil, fmt.Errorf("load builtin %q: %w", def.name, err)
		}

		verdict := "PASS"
		var totalViolations, totalFindings int
		for _, summary := range latestPerHost {
			// Fetch the full scan with findings for policy evaluation.
			scan, err := s.store.GetScan(ctx, summary.ID, orgID)
			if err != nil {
				return nil, fmt.Errorf("get scan %s: %w", summary.ID, err)
			}
			result := policy.Evaluate(pol, scan)
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

// worstVerdict returns the more severe of two policy verdicts.
// Severity order: FAIL > WARN > PASS. Used to aggregate per-scan
// verdicts into a single org-wide verdict.
func worstVerdict(a, b string) string {
	rank := map[string]int{"PASS": 0, "WARN": 1, "FAIL": 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}
