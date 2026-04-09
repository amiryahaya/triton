package server

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	switch {
	case withinParam == "":
		within = 90 * 24 * time.Hour
	case withinParam == "all":
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
