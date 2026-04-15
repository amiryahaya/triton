package engine

import (
	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/server"
)

// MountAdminRoutes wires /api/v1/manage/engines/* onto r. Read
// endpoints (GET) are open to any authenticated role; CreateEngine
// requires Engineer-or-higher; RevokeEngine is Owner-only. Callers
// must mount this under an already-authenticated subtree (JWTAuth).
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Get("/", h.ListEngines)
	r.Get("/{id}", h.GetEngine)
	r.Get("/{id}/encryption-pubkey", h.GetEngineEncryptionPubkey)

	r.Group(func(r chi.Router) {
		r.Use(server.RequireRole(server.RoleEngineer))
		r.Post("/", h.CreateEngine)
	})

	r.Group(func(r chi.Router) {
		r.Use(server.RequireRole(server.RoleOwner))
		r.Post("/{id}/revoke", h.RevokeEngine)
	})
}

// MountGatewayRoutes wires /api/v1/engine/* onto r. The caller MUST
// have already applied MTLSMiddleware to r; these handlers pull the
// authenticated engine from context and assume it is non-nil.
func MountGatewayRoutes(r chi.Router, h *GatewayHandlers) {
	r.Post("/enroll", h.Enroll)
	r.Post("/heartbeat", h.Heartbeat)
	r.Post("/encryption-pubkey", h.SubmitEncryptionPubkey)
}
