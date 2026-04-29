package scanjobs

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	cron "github.com/robfig/cron/v3"

	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
)

// ScheduleHandlers serves CRUD for /api/v1/admin/scan-schedules.
type ScheduleHandlers struct {
	store ScheduleStore
}

// NewScheduleHandlers wires a ScheduleHandlers with the given ScheduleStore.
func NewScheduleHandlers(store ScheduleStore) *ScheduleHandlers {
	return &ScheduleHandlers{store: store}
}

// CreateSchedule handles POST /api/v1/admin/scan-schedules.
// Body: {name, job_types, host_ids, profile, cron_expr, max_cpu_pct?, max_memory_mb?, max_duration_s?}
func (h *ScheduleHandlers) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)
	var req ScheduleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.TenantID = tenantID

	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.JobTypes) == 0 {
		writeErr(w, http.StatusBadRequest, "job_types must not be empty")
		return
	}
	if len(req.HostIDs) == 0 {
		writeErr(w, http.StatusBadRequest, "host_ids must not be empty")
		return
	}
	if req.CronExpr == "" {
		writeErr(w, http.StatusBadRequest, "cron_expr is required")
		return
	}
	if _, err := cron.ParseStandard(req.CronExpr); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid cron_expr: "+err.Error())
		return
	}

	sched, err := h.store.CreateSchedule(r.Context(), req)
	if err != nil {
		internalErr(w, r, err, "create schedule")
		return
	}
	writeJSON(w, http.StatusCreated, sched)
}

// ListSchedules handles GET /api/v1/admin/scan-schedules.
func (h *ScheduleHandlers) ListSchedules(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing tenant")
		return
	}
	list, err := h.store.ListSchedules(r.Context(), tenantID)
	if err != nil {
		internalErr(w, r, err, "list schedules")
		return
	}
	if list == nil {
		list = []Schedule{}
	}
	writeJSON(w, http.StatusOK, list)
}

// PatchSchedule handles PATCH /api/v1/admin/scan-schedules/{id}.
// Only non-nil fields in the body are applied.
func (h *ScheduleHandlers) PatchSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid schedule id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)
	var req SchedulePatchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.CronExpr != nil {
		if _, err := cron.ParseStandard(*req.CronExpr); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid cron_expr: "+err.Error())
			return
		}
	}
	sched, err := h.store.PatchSchedule(r.Context(), id, req)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "schedule not found")
		return
	}
	if err != nil {
		internalErr(w, r, err, "patch schedule")
		return
	}
	writeJSON(w, http.StatusOK, sched)
}

// DeleteSchedule handles DELETE /api/v1/admin/scan-schedules/{id}.
func (h *ScheduleHandlers) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid schedule id")
		return
	}
	if err := h.store.DeleteSchedule(r.Context(), id); errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "schedule not found")
		return
	} else if err != nil {
		internalErr(w, r, err, "delete schedule")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
