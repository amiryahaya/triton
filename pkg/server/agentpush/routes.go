package agentpush

import (
	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/server"
)

// MountAdminRoutes wires /api/v1/manage/agent-push/* onto r. Read
// endpoints (GET) admit any authenticated role; mutations require
// Engineer+. Caller must have already applied JWTAuth.
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.ListPushJobs)
	r.Get("/{id}", h.GetPushJob)
	r.Get("/agents", h.ListAgents)

	r.Group(func(r chi.Router) {
		r.Use(server.RequireRole(server.RoleEngineer))
		r.Post("/", h.CreatePushJob)
		r.Post("/{id}/cancel", h.CancelPushJob)
		r.Post("/agents/{hostID}/uninstall", h.UninstallAgent)
	})
}

// MountGatewayRoutes wires /api/v1/engine/agent-push/* onto r. Caller
// MUST have applied engine.MTLSMiddleware upstream.
func MountGatewayRoutes(r chi.Router, h *GatewayHandlers) {
	r.Get("/poll", h.Poll)
	r.Post("/{id}/progress", h.Progress)
	r.Post("/{id}/finish", h.Finish)
	r.Post("/agents/register", h.RegisterAgent)
	r.Post("/agents/heartbeat", h.AgentHeartbeat)
}
