package agentpush

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server/engine"
)

// GatewayHandlers implements /api/v1/engine/agent-push/*. The mTLS
// middleware runs upstream; these handlers read the authenticated
// engine via engine.EngineFromContext.
type GatewayHandlers struct {
	Store        Store
	Audit        AuditRecorder
	PollTimeout  time.Duration
	PollInterval time.Duration
}

// NewGatewayHandlers wires a GatewayHandlers with sensible defaults.
func NewGatewayHandlers(s Store) *GatewayHandlers {
	return &GatewayHandlers{
		Store:        s,
		PollTimeout:  30 * time.Second,
		PollInterval: 1 * time.Second,
	}
}

func (h *GatewayHandlers) audit(r *http.Request, event, subject string, fields map[string]any) {
	if h.Audit == nil {
		return
	}
	h.Audit.Record(r.Context(), event, subject, fields)
}

// Poll long-polls for the next queued push job for the authenticated
// engine. Returns 200 + PushJobPayload when a job is claimed, 204 on
// timeout, 500 if the engine context is missing.
func (h *GatewayHandlers) Poll(w http.ResponseWriter, r *http.Request) {
	eng := engine.EngineFromContext(r.Context())
	if eng == nil {
		writeErr(w, http.StatusInternalServerError, "missing engine context")
		return
	}
	timeout := h.PollTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	interval := h.PollInterval
	if interval == 0 {
		interval = 1 * time.Second
	}

	deadline := time.Now().Add(timeout)
	for {
		payload, found, err := h.Store.ClaimNext(r.Context(), eng.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if found {
			writeJSON(w, http.StatusOK, payload)
			return
		}
		if time.Now().After(deadline) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(interval):
		}
	}
}

// Progress ingests a batch of per-host progress updates.
func (h *GatewayHandlers) Progress(w http.ResponseWriter, r *http.Request) {
	eng := engine.EngineFromContext(r.Context())
	if eng == nil {
		writeErr(w, http.StatusInternalServerError, "missing engine context")
		return
	}
	jobID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid job id")
		return
	}
	var updates []ProgressUpdate
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	done, failed := 0, 0
	for _, u := range updates {
		switch u.Status {
		case "completed":
			done++
		case "failed":
			failed++
		}
	}
	if err := h.Store.UpdateProgress(r.Context(), jobID, done, failed); err != nil {
		writeErr(w, http.StatusInternalServerError, "update progress: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type finishRequest struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Finish transitions the push job to its terminal state.
func (h *GatewayHandlers) Finish(w http.ResponseWriter, r *http.Request) {
	eng := engine.EngineFromContext(r.Context())
	if eng == nil {
		writeErr(w, http.StatusInternalServerError, "missing engine context")
		return
	}
	jobID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid job id")
		return
	}
	var body finishRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	switch body.Status {
	case "completed", "failed", "cancelled":
	default:
		writeErr(w, http.StatusBadRequest, "invalid status")
		return
	}
	if err := h.Store.FinishJob(r.Context(), eng.ID, jobID, JobStatus(body.Status), body.Error); err != nil {
		switch {
		case errors.Is(err, ErrJobAlreadyTerminal):
			writeErr(w, http.StatusConflict, "job already terminal")
		case errors.Is(err, ErrJobNotOwned):
			writeErr(w, http.StatusForbidden, "job not owned by this engine")
		case errors.Is(err, ErrJobNotFound):
			writeErr(w, http.StatusNotFound, "job not found")
		default:
			writeErr(w, http.StatusInternalServerError, "finish job: "+err.Error())
		}
		return
	}
	h.audit(r, "agentpush.job.finished", jobID.String(), map[string]any{
		"engine_id": eng.ID.String(),
		"status":    body.Status,
	})
	w.WriteHeader(http.StatusNoContent)
}

// AgentHeartbeat records an agent heartbeat relayed from the engine.
// Atomically flips 'installing' → 'healthy' on first heartbeat and
// updates last_heartbeat on every subsequent one.
func (h *GatewayHandlers) AgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	eng := engine.EngineFromContext(r.Context())
	if eng == nil {
		writeErr(w, http.StatusInternalServerError, "missing engine context")
		return
	}
	var body struct {
		HostID          string `json:"host_id"`
		CertFingerprint string `json:"cert_fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hostID, err := uuid.Parse(body.HostID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad host_id")
		return
	}
	if err := h.Store.RecordAgentHeartbeat(r.Context(), hostID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type registerAgentRequest struct {
	HostID          uuid.UUID `json:"host_id"`
	CertFingerprint string    `json:"cert_fingerprint"`
	Version         string    `json:"version"`
}

// RegisterAgent records a successful agent installation. The engine
// calls this after each host push succeeds. Inserts into fleet_agents
// and flips inventory_hosts.mode to 'agent'.
func (h *GatewayHandlers) RegisterAgent(w http.ResponseWriter, r *http.Request) {
	eng := engine.EngineFromContext(r.Context())
	if eng == nil {
		writeErr(w, http.StatusInternalServerError, "missing engine context")
		return
	}
	var body registerAgentRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.HostID == uuid.Nil {
		writeErr(w, http.StatusBadRequest, "host_id is required")
		return
	}
	if body.CertFingerprint == "" {
		writeErr(w, http.StatusBadRequest, "cert_fingerprint is required")
		return
	}

	agent := FleetAgent{
		ID:              uuid.Must(uuid.NewV7()),
		OrgID:           eng.OrgID,
		HostID:          body.HostID,
		EngineID:        eng.ID,
		CertFingerprint: body.CertFingerprint,
		Version:         body.Version,
		Status:          "installing",
	}
	if err := h.Store.RegisterAgent(r.Context(), agent); err != nil {
		writeErr(w, http.StatusInternalServerError, "register agent: "+err.Error())
		return
	}

	h.audit(r, "agentpush.agent.registered", body.HostID.String(), map[string]any{
		"engine_id":        eng.ID.String(),
		"cert_fingerprint": body.CertFingerprint,
	})
	w.WriteHeader(http.StatusNoContent)
}
