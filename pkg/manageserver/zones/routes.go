package zones

import "github.com/go-chi/chi/v5"

// MountAdminRoutes wires the zones admin CRUD onto r. Callers must
// mount this under an already-authenticated subtree.
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Get("/{id}", h.Get)
	r.Patch("/{id}", h.Update)
	r.Delete("/{id}", h.Delete)
}
