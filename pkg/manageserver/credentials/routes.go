package credentials

import "github.com/go-chi/chi/v5"

// MountAdminRoutes wires credential admin routes. r must be authenticated + tenant-scoped.
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.List)
	r.Post("/", h.Create)
	r.Delete("/{id}", h.Delete)
}

// MountWorkerRoutes wires the worker GetSecret route.
// key is the shared X-Worker-Key secret; WorkerKeyAuth is applied here so
// the outer /api/v1/worker group does not need to duplicate the middleware.
func MountWorkerRoutes(r chi.Router, h *WorkerHandler, key string) {
	r.Group(func(r chi.Router) {
		r.Use(workerKeyAuth(key))
		r.Get("/credentials/{id}", h.GetSecret)
	})
}
