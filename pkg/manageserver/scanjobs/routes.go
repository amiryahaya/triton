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

// MountWorkerRoutes wires the Worker API onto r under whatever parent path it's
// mounted on (Manage server uses /api/v1/worker).
// key is the shared X-Worker-Key secret.
//
// Route table:
//
//	POST   /jobs/{id}/claim     - claim a queued job → 200 ClaimWorkerResp | 404 | 409
//	PATCH  /jobs/{id}/heartbeat - renew running_heartbeat_at → 204
//	POST   /jobs/{id}/submit    - submit scan result + mark complete → 204
//	POST   /jobs/{id}/complete  - mark job completed (no result) → 204
//	POST   /jobs/{id}/fail      - mark job failed (body: {"error":"…"}) → 204
//	GET    /hosts/{id}          - get host info for a job → 200 WorkerHostResp
func MountWorkerRoutes(r chi.Router, h *WorkerHandlers, key string) {
	r.Group(func(r chi.Router) {
		r.Use(WorkerKeyAuth(key))
		r.Post("/jobs/{id}/claim", h.Claim)
		r.Patch("/jobs/{id}/heartbeat", h.Heartbeat)
		r.Post("/jobs/{id}/submit", h.Submit)
		r.Post("/jobs/{id}/complete", h.Complete)
		r.Post("/jobs/{id}/fail", h.Fail)
		r.Get("/hosts/{id}", h.GetHost)
	})
}
