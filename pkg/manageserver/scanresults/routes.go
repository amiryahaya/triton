package scanresults

import "github.com/go-chi/chi/v5"

// MountAdminRoutes wires the push-status admin API onto r. Callers
// must mount this under an already-authenticated, instance-scoped
// subtree (/api/v1/admin).
//
// Route table:
//
//	GET / — return the current Status
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.Status)
}
