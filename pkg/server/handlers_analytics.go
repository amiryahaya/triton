package server

import (
	"log"
	"net/http"

	"github.com/amiryahaya/triton/pkg/store"
)

// Analytics Phase 1 handlers — see
// docs/plans/2026-04-09-analytics-phase-1-design.md §7.
//
// All three analytics endpoints live here. They share two invariants:
//
//  1. The X-Backfill-In-Progress header is set whenever the server's
//     backfillInProgress atomic flag is true, so the UI can render an
//     inline banner warning that the historical data is still loading.
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
