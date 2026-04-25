package discovery

import "github.com/go-chi/chi/v5"

// MountAdminRoutes wires the discovery admin API onto r. Callers must
// mount this under an already-authenticated, instance-scoped subtree
// (the Manage server's /api/v1/admin group, which runs jwtAuth +
// injectInstanceOrg).
//
// Route table:
//
//	POST   /        - start a discovery scan
//	GET    /        - get current job + candidates so far
//	POST   /cancel  - cancel the running scan
//	POST   /import  - import selected candidates into host inventory
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
	r.Post("/", h.HandleStart)
	r.Get("/", h.HandleGet)
	r.Post("/cancel", h.HandleCancel)
	r.Post("/import", h.HandleImport)
}
