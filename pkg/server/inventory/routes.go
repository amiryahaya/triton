package inventory

import (
	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/server"
)

// MountRoutes wires inventory CRUD onto the given router. Read endpoints
// are open to any authenticated role (Officer+); mutations require
// Engineer or higher. Callers must mount this under an already-
// authenticated subtree (JWTAuth or equivalent).
func MountRoutes(r chi.Router, h *Handlers) {
	r.Get("/groups", h.ListGroups)
	r.Get("/groups/{id}", h.GetGroup)
	r.Get("/hosts", h.ListHosts)
	r.Get("/hosts/{id}", h.GetHost)

	r.Group(func(r chi.Router) {
		r.Use(server.RequireRole(server.RoleEngineer))
		r.Post("/groups", h.CreateGroup)
		r.Put("/groups/{id}", h.UpdateGroup)
		r.Delete("/groups/{id}", h.DeleteGroup)
		r.Post("/hosts", h.CreateHost)
		r.Put("/hosts/{id}", h.UpdateHost)
		r.Delete("/hosts/{id}", h.DeleteHost)
	})
}
