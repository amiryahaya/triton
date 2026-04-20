package scanjobs

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
)

// QueueDepther is the narrow interface the Enqueue handler uses to
// consult downstream push-queue saturation before accepting new jobs.
// It's deliberately a one-method subset of scanresults.Store so the
// scanjobs package doesn't pull in the wider scanresults surface (and
// so tests can fake it with a one-liner).
type QueueDepther interface {
	QueueDepth(ctx context.Context) (int64, error)
}

// ScanCapGuard is the narrow licence-guard surface the Enqueue handler
// consults before accepting a new batch of jobs. Unlike the hard-cap
// guards on hosts/agents/users, scans use a soft-buffer enforcement
// model: the usage pusher reports monthly scan counts to the License
// Server, and the cap carries a soft-buffer percentage that lets
// operators burst slightly past the nominal cap.
//
// Three methods because the enforcement rule is:
//
//	used + expected > SoftBufferCeiling  => reject
//
// which requires reading all three. A nil Guard on AdminHandlers or
// any method returning -1 means "no cap for this metric".
type ScanCapGuard interface {
	LimitCap(metric, window string) int64
	CurrentUsage(metric, window string) int64
	SoftBufferCeiling(metric, window string) int64
}

// queueSaturationThreshold is the hard cap at which POST /scan-jobs
// responds 503. Matches the `attempt_count < 10` partial index on the
// queue; a 10k backlog means ~10k*10 = 100k potential retries before
// the dead-letter kicks in, which is plenty of headroom even on a
// slow upstream.
const queueSaturationThreshold = 10_000

// AdminHandlers serves the /api/v1/admin/scan-jobs API. All handlers
// pull the tenant ID from orgctx (populated upstream by the server's
// injectInstanceOrg middleware); clients never supply tenant_id.
//
// GuardProvider is consulted per-request so the Server can rotate the
// licence guard under a mutex during /setup/license activation without
// racing the admin handlers. A nil provider (or a provider returning
// nil) disables licence-cap enforcement.
type AdminHandlers struct {
	Store         Store
	ResultsStore  QueueDepther
	GuardProvider func() ScanCapGuard
}

// NewAdminHandlers wires an AdminHandlers with the given Store,
// results-queue reader, and (optional) licence-guard provider. A nil
// ResultsStore is acceptable for tests that don't exercise backpressure;
// the Enqueue handler treats a nil ResultsStore as "skip saturation
// check". A nil GuardProvider (or a provider returning nil) skips
// the licence-cap check.
func NewAdminHandlers(s Store, resultsStore QueueDepther, provider func() ScanCapGuard) *AdminHandlers {
	return &AdminHandlers{Store: s, ResultsStore: resultsStore, GuardProvider: provider}
}

// guard returns the ScanCapGuard to use for this request, or nil when
// no provider is wired or the provider yields nil. Centralises the
// nil-check so Enqueue reads as `if g := h.guard(); g != nil`.
func (h *AdminHandlers) guard() ScanCapGuard {
	if h.GuardProvider == nil {
		return nil
	}
	return h.GuardProvider()
}

// enqueueRequestBody is the accepted JSON shape for POST /. TenantID is
// deliberately omitted so a misbehaving client cannot forge another
// tenant's submission — the handler injects it from orgctx.
type enqueueRequestBody struct {
	ZoneIDs        []uuid.UUID `json:"zones"`
	HostFilter     string      `json:"target_filter"`
	Profile        Profile     `json:"profile"`
	CredentialsRef *uuid.UUID  `json:"credentials_ref"`
}

// validateEnqueue enforces the handler-layer invariants: at least one
// zone, and a valid profile. These are the same checks the DB would
// ultimately make (profile CHECK constraint, non-empty zone list =>
// non-empty job set) but catching them early keeps 400s separate from
// 500s.
func validateEnqueue(b enqueueRequestBody) error {
	if len(b.ZoneIDs) == 0 {
		return errors.New("zones must contain at least one zone id")
	}
	switch b.Profile {
	case ProfileQuick, ProfileStandard, ProfileComprehensive:
	case "":
		return errors.New("profile is required")
	default:
		return errors.New("profile must be one of quick|standard|comprehensive")
	}
	return nil
}

// Enqueue creates new scan jobs for the authenticated tenant.
// Body: {zones, target_filter?, profile, credentials_ref?}
func (h *AdminHandlers) Enqueue(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)

	tenantID, ok := orgctx.InstanceIDFromContext(r.Context())
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "instance not initialised")
		return
	}

	var body enqueueRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := validateEnqueue(body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Backpressure: if the downstream push queue is saturated, reject
	// new jobs with 503 so operators investigate the upstream outage
	// before the outbox eats the disk. A nil ResultsStore means the
	// caller (typically a test) opted out of backpressure.
	if h.ResultsStore != nil {
		depth, err := h.ResultsStore.QueueDepth(r.Context())
		if err != nil {
			internalErr(w, r, err, "read push queue depth")
			return
		}
		if depth >= queueSaturationThreshold {
			writeErr(w, http.StatusServiceUnavailable,
				"scan result queue saturated; upstream Report Server unreachable — see /api/v1/admin/push-status")
			return
		}
	}

	req := EnqueueReq{
		TenantID:       tenantID,
		ZoneIDs:        body.ZoneIDs,
		HostFilter:     body.HostFilter,
		Profile:        body.Profile,
		CredentialsRef: body.CredentialsRef,
	}

	// Licence scan cap (soft-buffered). Computed as:
	//   used + expected > SoftBufferCeiling  => reject with 403.
	// Pre-flighting via PlanEnqueueCount keeps the licence concern out
	// of the store layer while still expanding zones→hosts with the
	// exact same predicate Enqueue will use. A nil Guard or a cap of
	// -1 for scans/monthly disables this branch.
	if g := h.guard(); g != nil {
		if limit := g.LimitCap("scans", "monthly"); limit >= 0 {
			expected, err := h.Store.PlanEnqueueCount(r.Context(), req)
			if err != nil {
				internalErr(w, r, err, "plan enqueue count for cap")
				return
			}
			used := g.CurrentUsage("scans", "monthly")
			ceiling := g.SoftBufferCeiling("scans", "monthly")
			if used+expected > ceiling {
				writeErr(w, http.StatusForbidden,
					"licence scan cap exceeded (soft-buffered)")
				return
			}
		}
	}

	jobs, err := h.Store.Enqueue(r.Context(), req)
	if err != nil {
		internalErr(w, r, err, "enqueue scan jobs")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"jobs": jobs})
}

// List returns the most-recently-enqueued jobs for the authenticated
// tenant. Optional ?limit=<N> caps the response; invalid values fall
// back to the store default.
func (h *AdminHandlers) List(w http.ResponseWriter, r *http.Request) {
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

	list, err := h.Store.List(r.Context(), tenantID, limit)
	if err != nil {
		internalErr(w, r, err, "list scan jobs")
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// Get returns a single scan job by id. No cross-tenant check here: the
// admin subtree is already authenticated and scoped, and the client
// can't address a row it doesn't know the UUID of. If cross-tenant
// leakage becomes a concern we'd add a WHERE tenant_id guard on Get.
func (h *AdminHandlers) Get(w http.ResponseWriter, r *http.Request) {
	if _, ok := orgctx.InstanceIDFromContext(r.Context()); !ok {
		writeErr(w, http.StatusServiceUnavailable, "instance not initialised")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid scan job id")
		return
	}
	job, err := h.Store.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "scan job not found")
		return
	}
	if err != nil {
		internalErr(w, r, err, "get scan job")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// RequestCancel flips the cancel_requested flag; the terminal state
// write happens out-of-band inside the orchestrator worker loop.
func (h *AdminHandlers) RequestCancel(w http.ResponseWriter, r *http.Request) {
	if _, ok := orgctx.InstanceIDFromContext(r.Context()); !ok {
		writeErr(w, http.StatusServiceUnavailable, "instance not initialised")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid scan job id")
		return
	}
	err = h.Store.RequestCancel(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, "scan job not found")
		return
	}
	if err != nil {
		internalErr(w, r, err, "request cancel scan job")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeErr writes a JSON error body {"error": msg} with the given status.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// internalErr logs the underlying error with operation context and
// writes a generic 500 response body to the client, matching the
// zones/hosts sanitisation pattern. pg error strings (table names,
// SQLSTATEs, constraint names) never reach the wire. Request method
// + path are included so grep-ing server logs for a specific op
// lands you on the HTTP request without correlation tooling.
func internalErr(w http.ResponseWriter, r *http.Request, err error, op string) {
	log.Printf("manageserver/scanjobs: %s: %s %s: %v", op, r.Method, r.URL.Path, err)
	writeErr(w, http.StatusInternalServerError, "internal server error")
}
