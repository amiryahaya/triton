package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server/engine"
	"github.com/amiryahaya/triton/pkg/server/inventory"
)

// InventoryTargetLookup is the narrow engine-facing view of
// inventory.Store used by the credentials gateway to resolve host
// addresses when enriching a claimed test job.
type InventoryTargetLookup interface {
	GetHostsByIDs(ctx context.Context, orgID uuid.UUID, ids []uuid.UUID) ([]inventory.Host, error)
}

// GatewayHandlers serves the /api/v1/engine/credentials/* mTLS API.
// Engine identity comes from engine.EngineFromContext — no JWT claims
// are ever involved here. Long-poll GETs block for up to PollTimeout
// and wake up every PollInterval; the defaults (30s / 1s) match the
// engine's polling cadence.
type GatewayHandlers struct {
	Store          Store
	InventoryStore InventoryTargetLookup
	PollTimeout    time.Duration
	PollInterval   time.Duration
}

// NewGatewayHandlers wires a GatewayHandlers with sensible defaults.
func NewGatewayHandlers(s Store, inv InventoryTargetLookup) *GatewayHandlers {
	return &GatewayHandlers{
		Store:          s,
		InventoryStore: inv,
		PollTimeout:    30 * time.Second,
		PollInterval:   1 * time.Second,
	}
}

// defaultPortFor returns the usual TCP port for each auth type. SSH
// variants use 22; WinRM uses 5985 (HTTP) — the engine is free to
// override when it knows better (host tags like "winrm_port=5986" can
// be read from hostmatch.HostSummary, but that plumbing is deferred).
func defaultPortFor(a AuthType) int {
	if a == AuthWinRMPassword {
		return 5985
	}
	return 22
}

// HostTarget is the engine-side projection of a host record: just
// enough to connect. Lives here (not in types.go) because it is strictly
// a gateway wire shape.
type HostTarget struct {
	ID      uuid.UUID `json:"id"`
	Address string    `json:"address"`
	Port    int       `json:"port"`
}

// TestJobPayload is the enriched wire form of a claimed test job. The
// engine consumes secret_ref against its local keystore to recover the
// plaintext credential.
type TestJobPayload struct {
	ID        uuid.UUID    `json:"id"`
	ProfileID uuid.UUID    `json:"profile_id"`
	SecretRef uuid.UUID    `json:"secret_ref"`
	AuthType  AuthType     `json:"auth_type"`
	Hosts     []HostTarget `json:"hosts"`
}

// PollDelivery long-polls for the next queued delivery. Returns 204 if
// no delivery shows up within PollTimeout so the engine's for-loop can
// restart cleanly without misinterpreting a timeout as an error.
func (h *GatewayHandlers) PollDelivery(w http.ResponseWriter, r *http.Request) {
	eng := engine.EngineFromContext(r.Context())
	if eng == nil {
		writeErr(w, http.StatusInternalServerError, "engine not in context")
		return
	}
	d, ok, err := h.pollDelivery(r.Context(), eng.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "poll delivery: "+err.Error())
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// pollDelivery implements the busy-wait: claim; if empty, sleep
// PollInterval; repeat until PollTimeout or context cancellation.
// Callers get exactly-one-delivery-or-none semantics.
func (h *GatewayHandlers) pollDelivery(ctx context.Context, engineID uuid.UUID) (Delivery, bool, error) {
	deadline := time.Now().Add(h.PollTimeout)
	for {
		d, ok, err := h.Store.ClaimNextDelivery(ctx, engineID)
		if err != nil {
			return Delivery{}, false, err
		}
		if ok {
			return d, true, nil
		}
		if time.Now().After(deadline) {
			return Delivery{}, false, nil
		}
		select {
		case <-ctx.Done():
			return Delivery{}, false, nil
		case <-time.After(h.PollInterval):
		}
	}
}

type ackPayload struct {
	Error string `json:"error"`
}

// AckDelivery transitions a delivery to acked/failed. Returns 409 on
// idempotent-retry of an already-terminal row so the engine knows to
// stop retrying.
func (h *GatewayHandlers) AckDelivery(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid delivery id")
		return
	}
	var body ackPayload
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := h.Store.AckDelivery(r.Context(), id, body.Error); err != nil {
		if errors.Is(err, ErrDeliveryAlreadyAcked) {
			writeErr(w, http.StatusConflict, "delivery already terminal")
			return
		}
		writeErr(w, http.StatusInternalServerError, "ack delivery: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PollTest long-polls for the next queued test job, enriches it with
// host addresses + ports, and returns the TestJobPayload wire shape.
func (h *GatewayHandlers) PollTest(w http.ResponseWriter, r *http.Request) {
	eng := engine.EngineFromContext(r.Context())
	if eng == nil {
		writeErr(w, http.StatusInternalServerError, "engine not in context")
		return
	}
	tj, ok, err := h.pollTest(r.Context(), eng.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "poll test: "+err.Error())
		return
	}
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	profile, err := h.Store.GetProfile(r.Context(), tj.OrgID, tj.ProfileID)
	if err != nil {
		// Profile deleted between claim and poll — fail the test so the
		// operator sees a crisp error instead of an indefinite claim.
		_ = h.Store.FinishTestJob(r.Context(), tj.ID, "failed", "profile no longer exists")
		writeErr(w, http.StatusGone, "profile deleted")
		return
	}

	hosts, err := h.InventoryStore.GetHostsByIDs(r.Context(), tj.OrgID, tj.HostIDs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "lookup hosts: "+err.Error())
		return
	}
	port := defaultPortFor(profile.AuthType)
	targets := make([]HostTarget, 0, len(hosts))
	for i := range hosts {
		h := &hosts[i]
		addr := ""
		if h.Address != nil {
			addr = h.Address.String()
		} else if h.Hostname != "" {
			addr = h.Hostname
		}
		targets = append(targets, HostTarget{ID: h.ID, Address: addr, Port: port})
	}

	writeJSON(w, http.StatusOK, TestJobPayload{
		ID:        tj.ID,
		ProfileID: tj.ProfileID,
		SecretRef: profile.SecretRef,
		AuthType:  profile.AuthType,
		Hosts:     targets,
	})
}

func (h *GatewayHandlers) pollTest(ctx context.Context, engineID uuid.UUID) (TestJob, bool, error) {
	deadline := time.Now().Add(h.PollTimeout)
	for {
		t, ok, err := h.Store.ClaimNextTest(ctx, engineID)
		if err != nil {
			return TestJob{}, false, err
		}
		if ok {
			return t, true, nil
		}
		if time.Now().After(deadline) {
			return TestJob{}, false, nil
		}
		select {
		case <-ctx.Done():
			return TestJob{}, false, nil
		case <-time.After(h.PollInterval):
		}
	}
}

type submitResultsPayload struct {
	Results []TestResult `json:"results"`
	Error   string       `json:"error"`
}

// SubmitTest inserts all per-host results and transitions the job to
// its terminal state. Retries with overlapping (test_id, host_id) pairs
// overwrite via ON CONFLICT so the engine can retry safely.
func (h *GatewayHandlers) SubmitTest(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid test id")
		return
	}
	var body submitResultsPayload
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Force every result's test_id to the URL id; this closes a minor
	// trust-boundary hole where a compromised engine could otherwise
	// write into another test job's result set.
	for i := range body.Results {
		body.Results[i].TestID = id
	}

	if err := h.Store.InsertTestResults(r.Context(), body.Results); err != nil {
		writeErr(w, http.StatusInternalServerError, "insert results: "+err.Error())
		return
	}

	finalStatus := "completed"
	if body.Error != "" {
		finalStatus = "failed"
	}
	if err := h.Store.FinishTestJob(r.Context(), id, finalStatus, body.Error); err != nil {
		if errors.Is(err, ErrTestAlreadyTerminal) {
			writeErr(w, http.StatusConflict, "test job already terminal")
			return
		}
		writeErr(w, http.StatusInternalServerError, "finish test job: "+err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
