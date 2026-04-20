package hosts

import "github.com/go-chi/chi/v5"

// MountAdminRoutes wires the hosts admin CRUD onto r. Callers must
// mount this under an already-authenticated subtree.
//
// Static routes (/bulk) are registered before the {id} catch-all to
// keep the routing intent unambiguous even though chi would match
// literals before wildcards regardless of declaration order.
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Post("/bulk", h.BulkCreate)
	r.Get("/{id}", h.Get)
	r.Patch("/{id}", h.Update)
	r.Delete("/{id}", h.Delete)
}
