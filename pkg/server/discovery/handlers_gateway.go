package discovery

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server/engine"
)

// GatewayHandlers are the engine-facing discovery endpoints. They are
// mounted under engine.MTLSMiddleware so every request has a resolved
// *engine.Engine in context. PollTimeout / PollInterval tune the HTTP
// long-poll loop; zero values use the defaults below.
type GatewayHandlers struct {
	Store        Store
	Audit        AuditRecorder // may be nil — audit events are best-effort
	PollTimeout  time.Duration
	PollInterval time.Duration
}

// NewGatewayHandlers constructs a GatewayHandlers with production
// defaults (30s long-poll, 1s check interval). Tests override the
// fields directly for fast turnaround.
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

// Poll implements GET /engine/discovery/poll. It long-polls for the
// next queued job assigned to the calling engine. If a job is
// available, it is atomically claimed and returned. Otherwise, the
// handler sleeps up to PollTimeout (checking every PollInterval) and
// returns 204 No Content on timeout so the engine can immediately
// re-connect without burning CPU.
func (h *GatewayHandlers) Poll(w http.ResponseWriter, r *http.Request) {
	eng := engine.EngineFromContext(r.Context())
	if eng == nil {
		http.Error(w, "missing engine context", http.StatusInternalServerError)
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
		job, found, err := h.Store.ClaimNext(r.Context(), eng.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if found {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(job)
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

// submitRequest is the engine's POST body for /engine/discovery/{id}/submit.
// On success the engine posts a list of candidates; on failure it posts
// an "error" field instead. The two are mutually exclusive — if Error
// is non-empty, Candidates is ignored and the job is marked failed.
type submitRequest struct {
	Candidates []submittedCandidate `json:"candidates"`
	Error      string               `json:"error,omitempty"`
}

type submittedCandidate struct {
	Address   string `json:"address"`
	Hostname  string `json:"hostname,omitempty"`
	OpenPorts []int  `json:"open_ports"`
}

// Submit implements POST /engine/discovery/{id}/submit. On success it
// bulk-inserts candidates and flips the job to 'completed'. On a
// reported engine-side failure (body.Error set) it flips the job to
// 'failed' and discards candidates.
func (h *GatewayHandlers) Submit(w http.ResponseWriter, r *http.Request) {
	eng := engine.EngineFromContext(r.Context())
	if eng == nil {
		http.Error(w, "missing engine context", http.StatusInternalServerError)
		return
	}
	jobID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid job id", http.StatusBadRequest)
		return
	}

	var body submitRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if body.Error != "" {
		if err := h.Store.FinishJob(r.Context(), jobID, StatusFailed, body.Error, 0); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.audit(r, "discovery.job.failed", jobID.String(), map[string]any{
			"engine_id": eng.ID.String(),
		})
		w.WriteHeader(http.StatusNoContent)
		return
	}

	cs := make([]Candidate, 0, len(body.Candidates))
	for _, sc := range body.Candidates {
		ip := net.ParseIP(sc.Address)
		if ip == nil {
			// Silently skip malformed addresses — engines may forward
			// partial results from agents with broken DNS/rDNS.
			continue
		}
		cs = append(cs, Candidate{
			ID:        uuid.Must(uuid.NewV7()),
			JobID:     jobID,
			Address:   ip,
			Hostname:  sc.Hostname,
			OpenPorts: sc.OpenPorts,
		})
	}
	if err := h.Store.InsertCandidates(r.Context(), jobID, cs); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := h.Store.FinishJob(r.Context(), jobID, StatusCompleted, "", len(cs)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.audit(r, "discovery.candidates.submitted", jobID.String(), map[string]any{
		"engine_id":       eng.ID.String(),
		"candidate_count": len(cs),
	})
	w.WriteHeader(http.StatusNoContent)
}
