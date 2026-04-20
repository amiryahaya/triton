package agents

import "github.com/go-chi/chi/v5"

// MountAdminRoutes wires the agents CRUD + revoke endpoints onto r.
// Callers must mount this under an already-authenticated, tenancy-
// scoped subtree (typically /api/v1/admin/agents).
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.List)
	r.Get("/{id}", h.Get)
	r.Delete("/{id}", h.Revoke)
}

// MountEnrolRoutes wires the agent-enrol endpoint onto r. Lives on a
// sibling path to the CRUD subtree (/api/v1/admin/enrol/agent) so the
// URL shape reads "POST /admin/enrol/<kind>" rather than mixing verbs
// into the CRUD namespace.
func MountEnrolRoutes(r chi.Router, h *AdminHandlers) {
	r.Post("/agent", h.Enrol)
}
