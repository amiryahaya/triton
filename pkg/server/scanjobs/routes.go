package scanjobs

import (
	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/server"
)

// MountAdminRoutes wires /api/v1/manage/scan-jobs/* onto r. Read
// endpoints (GET) admit any authenticated role; mutations (create +
// cancel) require Engineer+. Caller must have already applied JWTAuth.
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.ListJobs)
	r.Get("/{id}", h.GetJob)

	r.Group(func(r chi.Router) {
		r.Use(server.RequireRole(server.RoleEngineer))
		r.Post("/", h.CreateJob)
		r.Post("/{id}/cancel", h.CancelJob)
	})
}

// MountGatewayRoutes wires /api/v1/engine/scans/* onto r. Caller MUST
// have applied engine.MTLSMiddleware upstream so handlers can resolve
// the authenticated engine from context.
func MountGatewayRoutes(r chi.Router, h *GatewayHandlers) {
	r.Get("/poll", h.Poll)
	r.Post("/{id}/progress", h.Progress)
	r.Post("/{id}/submit", h.Submit)
	r.Post("/{id}/finish", h.Finish)
}
