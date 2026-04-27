// pkg/manageserver/scanjobs/worker_handlers.go
package scanjobs

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// HostsStore is the subset of hosts.Store that WorkerHandlers needs for
// the GET /api/v1/worker/hosts/{id} endpoint. Using a local interface
// avoids a circular import between the scanjobs and hosts packages.
type HostsStore interface {
	GetHostBasic(ctx context.Context, id uuid.UUID) (hostname, ip string, err error)
}

// WorkerHostResp is returned by GET /api/v1/worker/hosts/{id}.
type WorkerHostResp struct {
	ID       uuid.UUID `json:"id"`
	Hostname string    `json:"hostname"`
	IP       string    `json:"ip"`
}

// ClaimWorkerResp is the JSON body returned by the claim endpoint.
type ClaimWorkerResp struct {
	JobID          uuid.UUID  `json:"job_id"`
	HostID         uuid.UUID  `json:"host_id"`
	Profile        string     `json:"profile"`
	PortOverride   []uint16   `json:"port_override,omitempty"`
	CredentialsRef *uuid.UUID `json:"credentials_ref,omitempty"`
}

// WorkerResultEnqueuer is the subset of ResultEnqueuer that WorkerHandlers
// needs for POST /worker/jobs/{id}/submit. Declared locally to avoid
// a circular import between scanjobs and scanresults.
type WorkerResultEnqueuer interface {
	Enqueue(ctx context.Context, scanJobID uuid.UUID, sourceType string, sourceID uuid.UUID, scan *model.ScanResult) error
}

// WorkerHandlers serves the /api/v1/worker/ route group.
type WorkerHandlers struct {
	store      Store
	hostsStore HostsStore
	enqueuer   WorkerResultEnqueuer // may be nil; Submit returns 501 if not wired

	// sourceID holds the Manage instance UUID stamped on every enqueued row.
	// Stored as [16]byte in an atomic.Value so SetSourceID can be called
	// from startScannerPipeline without a mutex. Workers are only dispatched
	// after the pipeline starts, so Submit will always see a non-zero value.
	sourceID atomic.Value // stores uuid.UUID
}

// NewWorkerHandlers constructs WorkerHandlers without a result enqueuer.
// Use NewWorkerHandlersWithEnqueuer when the submit endpoint is needed.
func NewWorkerHandlers(store Store, hostsStore HostsStore) *WorkerHandlers {
	return &WorkerHandlers{store: store, hostsStore: hostsStore}
}

// NewWorkerHandlersWithEnqueuer constructs WorkerHandlers with a result enqueuer
// so that POST /worker/jobs/{id}/submit can relay results to the Report Server.
func NewWorkerHandlersWithEnqueuer(store Store, hostsStore HostsStore, enqueuer WorkerResultEnqueuer) *WorkerHandlers {
	return &WorkerHandlers{
		store:      store,
		hostsStore: hostsStore,
		enqueuer:   enqueuer,
	}
}

// SetSourceID updates the Manage instance ID stamped on enqueued scan results.
// Called once from startScannerPipeline after instance_id is resolved.
func (h *WorkerHandlers) SetSourceID(id uuid.UUID) {
	h.sourceID.Store(id)
}

// getSourceID returns the current sourceID, or uuid.Nil if not yet set.
func (h *WorkerHandlers) getSourceID() uuid.UUID {
	v := h.sourceID.Load()
	if v == nil {
		return uuid.Nil
	}
	return v.(uuid.UUID)
}

// WorkerKeyAuth is middleware that validates the X-Worker-Key header.
// Uses constant-time comparison to resist timing attacks.
func WorkerKeyAuth(key string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := r.Header.Get("X-Worker-Key")
			if subtle.ConstantTimeCompare([]byte(got), []byte(key)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Claim handles POST /v1/worker/jobs/{id}/claim.
func (h *WorkerHandlers) Claim(w http.ResponseWriter, r *http.Request) {
	id, ok := parseJobID(w, r)
	if !ok {
		return
	}
	sum := sha256.Sum256([]byte(r.Header.Get("X-Worker-Key")))
	workerID := fmt.Sprintf("worker-%x", sum[:8])
	job, err := h.store.ClaimByID(r.Context(), id, workerID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrAlreadyClaimed) {
			http.Error(w, "conflict", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ClaimWorkerResp{
		JobID:          job.ID,
		HostID:         job.HostID,
		Profile:        string(job.Profile),
		PortOverride:   job.PortOverride,
		CredentialsRef: job.CredentialsRef,
	})
}

// Heartbeat handles PATCH /v1/worker/jobs/{id}/heartbeat.
func (h *WorkerHandlers) Heartbeat(w http.ResponseWriter, r *http.Request) {
	id, ok := parseJobID(w, r)
	if !ok {
		return
	}
	if err := h.store.Heartbeat(r.Context(), id, ""); err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Complete handles POST /v1/worker/jobs/{id}/complete.
func (h *WorkerHandlers) Complete(w http.ResponseWriter, r *http.Request) {
	id, ok := parseJobID(w, r)
	if !ok {
		return
	}
	if err := h.store.Complete(r.Context(), id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type failBody struct {
	Error string `json:"error"`
}

// Fail handles POST /v1/worker/jobs/{id}/fail.
func (h *WorkerHandlers) Fail(w http.ResponseWriter, r *http.Request) {
	id, ok := parseJobID(w, r)
	if !ok {
		return
	}
	var body failBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.store.Fail(r.Context(), id, body.Error); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetHost handles GET /api/v1/worker/hosts/{id}.
// Returns the hostname and IP for a host so the scanner subprocess can
// resolve its target without a JWT-authenticated admin API call.
func (h *WorkerHandlers) GetHost(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "id")
	id, err := uuid.Parse(raw)
	if err != nil {
		http.Error(w, "invalid host id", http.StatusBadRequest)
		return
	}
	hostname, ip, err := h.hostsStore.GetHostBasic(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(WorkerHostResp{ID: id, Hostname: hostname, IP: ip})
}

// Submit handles POST /v1/worker/jobs/{id}/submit.
// The worker posts the completed ScanResult JSON body. The handler:
//  1. Decodes the body.
//  2. Enqueues the result via the ResultEnqueuer (scanresults outbox).
//  3. Marks the job completed.
//
// This combines what the orchestrator does internally (Enqueue + Complete)
// into a single worker-facing endpoint so external binaries (triton-portscan,
// triton-sshagent) don't need a direct Report Server connection.
func (h *WorkerHandlers) Submit(w http.ResponseWriter, r *http.Request) {
	id, ok := parseJobID(w, r)
	if !ok {
		return
	}

	if h.enqueuer == nil {
		http.Error(w, "result enqueuer not configured", http.StatusNotImplemented)
		return
	}

	// Cap body at 32 MB — a generous upper bound for a ScanResult payload.
	const maxBodyBytes = 32 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close() //nolint:errcheck // MaxBytesReader already closed on limit; error not actionable here

	var result model.ScanResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		// Distinguish oversized body from malformed JSON.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) || errors.Is(err, io.ErrUnexpectedEOF) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	sourceType := string(result.Metadata.Source)
	if sourceType == "" {
		sourceType = "worker"
	}
	if err := h.enqueuer.Enqueue(r.Context(), id, sourceType, h.getSourceID(), &result); err != nil {
		http.Error(w, "enqueue result: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.store.Complete(r.Context(), id); err != nil {
		// Enqueue succeeded — log the Complete failure but still return 202
		// so the worker exits cleanly. The drain will deliver the result;
		// the job row stays in 'running' until the stale-job reaper reverts
		// it, which is cosmetic at this point.
		log.Printf("manageserver/scanjobs: submit: complete job %s: %v", id, err)
	}

	w.WriteHeader(http.StatusAccepted)
}

func parseJobID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := chi.URLParam(r, "id")
	id, err := uuid.Parse(raw)
	if err != nil {
		http.Error(w, "invalid job id", http.StatusBadRequest)
		return uuid.UUID{}, false
	}
	return id, true
}
