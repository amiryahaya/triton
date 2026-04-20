package scanresults

import (
	"encoding/json"
	"log"
	"net/http"
)

// AdminHandlers serves the /api/v1/admin/push-status diagnostics API.
// Single handler, single route: GET / returns the current Status.
type AdminHandlers struct {
	Store Store
}

// NewAdminHandlers wires an AdminHandlers with the given Store.
func NewAdminHandlers(s Store) *AdminHandlers {
	return &AdminHandlers{Store: s}
}

// Status returns the current push-queue diagnostics.
//
// Body shape (see types.Status for field pins):
//
//	{
//	  "queue_depth": 42,
//	  "oldest_row_age_seconds": 123,
//	  "last_push_error": "...",
//	  "consecutive_failures": 0,
//	  "last_pushed_at": "2026-04-19T14:22:00Z"  // omitted when null
//	}
//
// LoadLicenseState merges all four read paths (queue depth, oldest
// age, license-state singleton) so this handler is a straight
// pass-through.
func (h *AdminHandlers) Status(w http.ResponseWriter, r *http.Request) {
	st, err := h.Store.LoadLicenseState(r.Context())
	if err != nil {
		// Method + path logged alongside op to match the
		// zones/hosts/scanjobs/agents internalErr convention, so a
		// single grep surfaces server-side errors by handler without
		// needing a request-ID correlation step.
		log.Printf("manageserver/scanresults: load license state: %s %s: %v",
			r.Method, r.URL.Path, err)
		writeErr(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// writeJSON writes a JSON response with the given status code. Mirrors
// the helpers in the sibling scanjobs package; duplicated here rather
// than imported to keep scanjobs free of a scanresults dep (and
// vice-versa).
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
