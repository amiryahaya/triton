package credentials

import "github.com/go-chi/chi/v5"

// MountAdminRoutes wires credential admin routes. r must be authenticated + tenant-scoped.
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Delete("/{id}", h.Delete)
}

// MountWorkerRoutes wires the worker GetSecret route.
func MountWorkerRoutes(r chi.Router, h *WorkerHandler) {
	r.Get("/credentials/{id}", h.GetSecret)
}
