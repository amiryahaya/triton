// pkg/manageserver/scanjobs/worker_handlers.go
package scanjobs

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ClaimWorkerResp is the JSON body returned by the claim endpoint.
type ClaimWorkerResp struct {
	JobID          uuid.UUID  `json:"job_id"`
	HostID         uuid.UUID  `json:"host_id"`
	Profile        string     `json:"profile"`
	PortOverride   []uint16   `json:"port_override,omitempty"`
	CredentialsRef *uuid.UUID `json:"credentials_ref,omitempty"`
}

// WorkerHandlers serves the /v1/worker/ route group.
type WorkerHandlers struct {
	store Store
}

// NewWorkerHandlers constructs WorkerHandlers.
func NewWorkerHandlers(store Store) *WorkerHandlers {
	return &WorkerHandlers{store: store}
}

// WorkerKeyAuth is middleware that validates the X-Worker-Key header.
func WorkerKeyAuth(key string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Worker-Key") != key {
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
	workerID := r.Header.Get("X-Worker-Key")
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
	json.NewEncoder(w).Encode(ClaimWorkerResp{ //nolint:errcheck
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

func parseJobID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	raw := chi.URLParam(r, "id")
	id, err := uuid.Parse(raw)
	if err != nil {
		http.Error(w, "invalid job id", http.StatusBadRequest)
		return uuid.UUID{}, false
	}
	return id, true
}
