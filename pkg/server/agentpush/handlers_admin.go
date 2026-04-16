package agentpush

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/server/inventory"
)

// AuditRecorder captures operator actions for the audit log. Nil is
// tolerated (test + embedded deployments).
type AuditRecorder interface {
	Record(ctx context.Context, event, subject string, fields map[string]any)
}

// InventoryQuerier is the narrow slice of inventory.Store the admin
// handler needs.
type InventoryQuerier interface {
	ListHosts(ctx context.Context, orgID uuid.UUID, f inventory.HostFilters) ([]inventory.Host, error)
	GetEnginesForHosts(ctx context.Context, orgID uuid.UUID, hostIDs []uuid.UUID) (map[uuid.UUID]struct{}, error)
}

// AdminHandlers implements /api/v1/manage/agent-push/*.
type AdminHandlers struct {
	Store          Store
	InventoryStore InventoryQuerier
	Audit          AuditRecorder
}

// NewAdminHandlers wires an AdminHandlers.
func NewAdminHandlers(s Store, inv InventoryQuerier, a AuditRecorder) *AdminHandlers {
	return &AdminHandlers{Store: s, InventoryStore: inv, Audit: a}
}

func (h *AdminHandlers) audit(ctx context.Context, event, subject string, fields map[string]any) {
	if h.Audit == nil {
		return
	}
	h.Audit.Record(ctx, event, subject, fields)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (h *AdminHandlers) claims(r *http.Request) (orgID, userID uuid.UUID, ok bool) {
	c := server.ClaimsFromContext(r.Context())
	if c == nil {
		return uuid.Nil, uuid.Nil, false
	}
	var err error
	orgID, err = uuid.Parse(c.Org)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	userID, err = uuid.Parse(c.Sub)
	if err != nil {
		return uuid.Nil, uuid.Nil, false
	}
	return orgID, userID, true
}

type createPushJobPayload struct {
	GroupID             *uuid.UUID  `json:"group_id,omitempty"`
	HostIDs             []uuid.UUID `json:"host_ids,omitempty"`
	CredentialProfileID uuid.UUID   `json:"credential_profile_id"`
}

// CreatePushJob queues a new agent push job. Requires exactly one of
// group_id or host_ids. Enforces one-engine-per-job.
func (h *AdminHandlers) CreatePushJob(w http.ResponseWriter, r *http.Request) {
	var body createPushJobPayload
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// XOR: exactly one of group_id or host_ids must be supplied.
	if (body.GroupID == nil) == (len(body.HostIDs) == 0) {
		writeErr(w, http.StatusBadRequest, "exactly one of group_id or host_ids required")
		return
	}
	if body.CredentialProfileID == uuid.Nil {
		writeErr(w, http.StatusBadRequest, "credential_profile_id is required")
		return
	}

	orgID, userID, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}

	// Resolve host list from group, or trust the caller's explicit list.
	var hostIDs []uuid.UUID
	if body.GroupID != nil {
		hosts, err := h.InventoryStore.ListHosts(r.Context(), orgID, inventory.HostFilters{GroupID: body.GroupID})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "list hosts: "+err.Error())
			return
		}
		for i := range hosts {
			hostIDs = append(hostIDs, hosts[i].ID)
		}
	} else {
		hostIDs = body.HostIDs
	}
	if len(hostIDs) == 0 {
		writeErr(w, http.StatusBadRequest, "no hosts resolved from group or list")
		return
	}

	// Enforce one-engine-per-job.
	engineSet, err := h.InventoryStore.GetEnginesForHosts(r.Context(), orgID, hostIDs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "resolve engines: "+err.Error())
		return
	}
	if len(engineSet) == 0 {
		writeErr(w, http.StatusBadRequest, "hosts have no engine assigned; register an engine for these hosts first")
		return
	}
	if len(engineSet) > 1 {
		writeErr(w, http.StatusBadRequest, "hosts span multiple engines; split into separate push jobs per engine")
		return
	}
	var engineID uuid.UUID
	for k := range engineSet {
		engineID = k
	}

	j := PushJob{
		ID:                  uuid.Must(uuid.NewV7()),
		OrgID:               orgID,
		EngineID:            engineID,
		GroupID:             body.GroupID,
		HostIDs:             hostIDs,
		CredentialProfileID: body.CredentialProfileID,
		RequestedBy:         userID,
		ProgressTotal:       len(hostIDs),
	}
	j, err = h.Store.CreatePushJob(r.Context(), j)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create job: "+err.Error())
		return
	}

	h.audit(r.Context(), "agentpush.job.create", j.ID.String(), map[string]any{
		"engine_id":  engineID.String(),
		"host_count": len(hostIDs),
	})
	writeJSON(w, http.StatusCreated, j)
}

// ListPushJobs returns push jobs for the caller's org.
func (h *AdminHandlers) ListPushJobs(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}
	limit := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 500 {
		limit = 500
	}
	jobs, err := h.Store.ListPushJobs(r.Context(), orgID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list jobs: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, jobs)
}

// GetPushJob returns a single push job by id.
func (h *AdminHandlers) GetPushJob(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid job id")
		return
	}
	j, err := h.Store.GetPushJob(r.Context(), orgID, id)
	if err != nil {
		if errors.Is(err, ErrJobNotFound) {
			writeErr(w, http.StatusNotFound, "job not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "get job: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, j)
}

// CancelPushJob flips a queued push job to cancelled.
func (h *AdminHandlers) CancelPushJob(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid job id")
		return
	}
	err = h.Store.CancelPushJob(r.Context(), orgID, id)
	switch {
	case err == nil:
		h.audit(r.Context(), "agentpush.job.cancel", id.String(), nil)
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, ErrJobNotFound):
		writeErr(w, http.StatusNotFound, "job not found")
	case errors.Is(err, ErrJobNotCancellable):
		writeErr(w, http.StatusConflict, "job not cancellable (must be queued)")
	default:
		writeErr(w, http.StatusInternalServerError, "cancel job: "+err.Error())
	}
}

// ListAgents returns fleet agents for the caller's org.
func (h *AdminHandlers) ListAgents(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}
	agents, err := h.Store.ListAgents(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list agents: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

// UninstallAgent marks an agent as uninstalled and flips the host
// mode back to agentless.
func (h *AdminHandlers) UninstallAgent(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid auth claim")
		return
	}
	hostID, err := uuid.Parse(chi.URLParam(r, "hostID"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid host id")
		return
	}

	// Find agent by host ID in this org.
	agents, err := h.Store.ListAgents(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list agents: "+err.Error())
		return
	}
	var agentID uuid.UUID
	found := false
	for i := range agents {
		if agents[i].HostID == hostID {
			agentID = agents[i].ID
			found = true
			break
		}
	}
	if !found {
		writeErr(w, http.StatusNotFound, "no agent found for host")
		return
	}

	if err := h.Store.SetAgentStatus(r.Context(), agentID, "uninstalled"); err != nil {
		writeErr(w, http.StatusInternalServerError, "set agent status: "+err.Error())
		return
	}

	h.audit(r.Context(), "agentpush.agent.uninstall", hostID.String(), map[string]any{
		"agent_id": agentID.String(),
	})
	w.WriteHeader(http.StatusNoContent)
}
