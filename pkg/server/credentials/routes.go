package credentials

import (
	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/server"
)

// MountAdminRoutes wires /api/v1/manage/credentials/* onto r. Read
// endpoints (GET) admit any authenticated role; mutations require
// Engineer+ (the matcher CRUD + test triggers are dangerous). Caller
// must have already applied JWTAuth.
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.ListProfiles)
	r.Get("/tests/{id}", h.GetTestJob)
	r.Get("/{id}", h.GetProfile)

	r.Group(func(r chi.Router) {
		r.Use(server.RequireRole(server.RoleEngineer))
		r.Post("/", h.CreateProfile)
		r.Delete("/{id}", h.DeleteProfile)
		r.Post("/{id}/test", h.StartTest)
	})
}

// MountGatewayRoutes wires /api/v1/engine/credentials/* onto r. Caller
// MUST have applied the engine mTLS middleware upstream.
func MountGatewayRoutes(r chi.Router, h *GatewayHandlers) {
	r.Get("/deliveries/poll", h.PollDelivery)
	r.Post("/deliveries/{id}/ack", h.AckDelivery)
	r.Get("/tests/poll", h.PollTest)
	r.Post("/tests/{id}/submit", h.SubmitTest)
}
