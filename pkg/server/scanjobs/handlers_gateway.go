package scanjobs

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server/engine"
)

// GatewayHandlers implements /api/v1/engine/scans/*. The mTLS
// middleware runs upstream; these handlers read the authenticated
// engine via engine.EngineFromContext and reject requests that lack it
// with 500 (defensive — indicates a mis-wired route).
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

// Poll long-polls for the next queued scan job for the authenticated
// engine. Returns 200 + JobPayload when a job is claimed, 204 on
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

// Progress ingests a batch of per-host progress updates. Only the
// aggregate done/failed counts are persisted today — per-host status
// remains opaque to the server until Submit lands the scan result.
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
	if err := h.Store.UpdateProgress(r.Context(), eng.ID, jobID, done, failed); err != nil {
		switch {
		case errors.Is(err, ErrJobNotFound):
			writeErr(w, http.StatusNotFound, "job not found")
		case errors.Is(err, ErrJobNotOwnedByEngine):
			writeErr(w, http.StatusForbidden, "job belongs to a different engine")
		default:
			writeErr(w, http.StatusInternalServerError, "update progress: "+err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type submitRequest struct {
	HostID        uuid.UUID       `json:"host_id"`
	FindingsCount int             `json:"findings_count"`
	ScanResult    json.RawMessage `json:"scan_result"`
}

// maxSubmitBodyBytes caps the scan-result POST body. Comprehensive scans
// on a single host with 10k findings produce ~5–10 MB; 32 MB gives
// comfortable headroom while bounding the portal's OOM exposure to a
// malicious or buggy engine.
const maxSubmitBodyBytes = 32 << 20

// Submit persists a per-host scan result. The engine streams one
// Submit per completed host; Finish is called once when all hosts
// terminal out.
func (h *GatewayHandlers) Submit(w http.ResponseWriter, r *http.Request) {
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
	// Cap the body before decoding so a malicious engine can't stream
	// an unbounded payload into memory. MaxBytesReader returns an
	// error whose message is "http: request body too large" once the
	// cap is tripped — map that to 413.
	r.Body = http.MaxBytesReader(w, r.Body, maxSubmitBodyBytes)
	var body submitRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		// MaxBytesReader returns *http.MaxBytesError once the cap is
		// tripped; json.Decoder wraps it but errors.As still peels
		// back to the sentinel type.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || err.Error() == "http: request body too large" {
			writeErr(w, http.StatusRequestEntityTooLarge, "scan result exceeds 32MB limit")
			return
		}
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := h.Store.RecordScanResult(r.Context(), eng.ID, jobID, body.HostID, body.ScanResult); err != nil {
		switch {
		case errors.Is(err, ErrJobNotFound):
			writeErr(w, http.StatusNotFound, "job not found")
		case errors.Is(err, ErrJobNotOwnedByEngine):
			writeErr(w, http.StatusForbidden, "job belongs to a different engine")
		case errors.Is(err, ErrJobAlreadyTerminal):
			writeErr(w, http.StatusConflict, "job already terminal")
		default:
			writeErr(w, http.StatusInternalServerError, "record scan result: "+err.Error())
		}
		return
	}
	h.audit(r, "scanjobs.host.submitted", jobID.String(), map[string]any{
		"engine_id":      eng.ID.String(),
		"host_id":        body.HostID.String(),
		"findings_count": body.FindingsCount,
	})
	w.WriteHeader(http.StatusNoContent)
}

type finishRequest struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Finish transitions the job to its terminal state. Idempotent retries
// from a crashed engine see 409 (ErrJobAlreadyTerminal).
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
		case errors.Is(err, ErrJobNotFound):
			writeErr(w, http.StatusNotFound, "job not found")
		case errors.Is(err, ErrJobNotOwnedByEngine):
			writeErr(w, http.StatusForbidden, "job belongs to a different engine")
		default:
			writeErr(w, http.StatusInternalServerError, "finish job: "+err.Error())
		}
		return
	}
	h.audit(r, "scanjobs.job.finished", jobID.String(), map[string]any{
		"engine_id": eng.ID.String(),
		"status":    body.Status,
		"has_error": body.Error != "",
	})
	w.WriteHeader(http.StatusNoContent)
}
