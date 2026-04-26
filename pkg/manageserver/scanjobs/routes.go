package scanjobs

import "github.com/go-chi/chi/v5"

// MountAdminRoutes wires the scan-jobs admin API onto r. Callers must
// mount this under an already-authenticated, instance-scoped subtree
// (the Manage server's /api/v1/admin group, which runs jwtAuth +
// injectInstanceOrg).
//
// Route table:
//
//	POST   /             - enqueue scan jobs (body: EnqueueReq)
//	GET    /             - list scan jobs for the tenant (?limit=N)
//	GET    /{id}         - get a single scan job
//	POST   /{id}/cancel  - request cancel on a scan job
//
// The /{id}/cancel path is declared before {id} isn't strictly needed
// because chi matches exact literals ahead of path params regardless
// of declaration order, but we keep the order readable for future
// maintainers.
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Post("/", h.Enqueue)
	r.Post("/port-survey", h.EnqueuePortSurvey)
	r.Get("/", h.List)
	r.Get("/{id}", h.Get)
	r.Post("/{id}/cancel", h.RequestCancel)
}
