package scanjobs

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
)

// hostsGetter is the narrow interface BatchHandlers needs from the hosts store.
type hostsGetter interface {
	GetByIDs(ctx context.Context, ids []uuid.UUID) ([]hosts.Host, error)
}

// BatchHandlers serves POST/GET /api/v1/admin/scan-batches.
type BatchHandlers struct {
	store      BatchStore
	hostsStore hostsGetter
}

// NewBatchHandlers wires a BatchHandlers with the given BatchStore and hosts
// store. Both arguments are required.
func NewBatchHandlers(store BatchStore, hs hostsGetter) *BatchHandlers {
	return &BatchHandlers{store: store, hostsStore: hs}
}

// EnqueueBatch handles POST /api/v1/admin/scan-batches.
// It resolves the supplied host IDs, fans out to per-host job specs via
// ResolveJobs, and delegates persistence to BatchStore.EnqueueBatch.
func (h *BatchHandlers) EnqueueBatch(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "instance not initialised")
		return
	}

	var req BatchEnqueueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.TenantID = tenantID

	if len(req.JobTypes) == 0 {
		writeErr(w, http.StatusBadRequest, "job_types must not be empty")
		return
	}
	if len(req.HostIDs) == 0 {
		writeErr(w, http.StatusBadRequest, "host_ids must not be empty")
		return
	}
	if req.Profile == "" {
		req.Profile = ProfileStandard
	}
	switch req.Profile {
	case ProfileQuick, ProfileStandard, ProfileComprehensive:
		// valid
	default:
		writeErr(w, http.StatusBadRequest, "profile must be one of quick|standard|comprehensive")
		return
	}
	if req.MaxCPUPct != nil && (*req.MaxCPUPct < 0 || *req.MaxCPUPct > 100) {
		writeErr(w, http.StatusBadRequest, "max_cpu_pct must be 0-100")
		return
	}
	if req.MaxMemoryMB != nil && *req.MaxMemoryMB < 0 {
		writeErr(w, http.StatusBadRequest, "max_memory_mb must be >= 0")
		return
	}

	const maxPending = 10_000
	pending, err := h.store.CountPendingJobs(r.Context())
	if err != nil {
		internalErr(w, r, err, "check queue capacity")
		return
	}
	if pending >= maxPending {
		writeErr(w, http.StatusServiceUnavailable, "queue is saturated; try again later")
		return
	}

	rawHosts, err := h.hostsStore.GetByIDs(r.Context(), req.HostIDs)
	if err != nil {
		internalErr(w, r, err, "resolve hosts for batch")
		return
	}

	infos := make([]ResolveHostInfo, len(rawHosts))
	for i, rh := range rawHosts {
		infos[i] = ResolveHostInfo{
			ID:             rh.ID,
			ConnectionType: rh.ConnectionType,
			CredentialsRef: rh.CredentialsRef,
			SSHPort:        rh.SSHPort,
		}
	}

	specs, skipped := ResolveJobs(infos, req.JobTypes)

	resp, err := h.store.EnqueueBatch(r.Context(), req, specs, skipped)
	if err != nil {
		internalErr(w, r, err, "enqueue batch")
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// ListBatches handles GET /api/v1/admin/scan-batches.
// Optional ?limit=<N> caps the response; invalid values fall back to the
// store default (50).
func (h *BatchHandlers) ListBatches(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "instance not initialised")
		return
	}

	limit := 0
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}

	batches, err := h.store.ListBatches(r.Context(), tenantID, limit)
	if err != nil {
		internalErr(w, r, err, "list batches")
		return
	}
	writeJSON(w, http.StatusOK, batches)
}
