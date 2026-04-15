package discovery

import (
	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/server"
)

// MountAdminRoutes wires the operator-facing discovery endpoints onto
// r. Read endpoints (GET) are open to any authenticated role; write
// endpoints (create/promote/cancel) require Engineer+. Callers must
// mount this under an already-authenticated subtree (JWTAuth).
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.ListDiscoveries)
	r.Get("/{id}", h.GetDiscovery)

	r.Group(func(r chi.Router) {
		r.Use(server.RequireRole(server.RoleEngineer))
		r.Post("/", h.CreateDiscovery)
		r.Post("/{id}/promote", h.PromoteCandidates)
		r.Post("/{id}/cancel", h.CancelDiscovery)
	})
}

