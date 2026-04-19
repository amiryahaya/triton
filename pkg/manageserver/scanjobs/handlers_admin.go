package scanjobs

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
)

// AdminHandlers serves the /api/v1/admin/scan-jobs API. All handlers
// pull the tenant ID from orgctx (populated upstream by the server's
// injectInstanceOrg middleware); clients never supply tenant_id.
type AdminHandlers struct {
	Store Store
}

// NewAdminHandlers wires an AdminHandlers with the given Store.
func NewAdminHandlers(s Store) *AdminHandlers {
	return &AdminHandlers{Store: s}
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

	req := EnqueueReq{
		TenantID:       tenantID,
		ZoneIDs:        body.ZoneIDs,
		HostFilter:     body.HostFilter,
		Profile:        body.Profile,
		CredentialsRef: body.CredentialsRef,
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
// SQLSTATEs, constraint names) never reach the wire.
func internalErr(w http.ResponseWriter, r *http.Request, err error, op string) {
	_ = r // reserved for future enrichment (request ID, remote addr)
	log.Printf("manageserver/scanjobs: %s: %v", op, err)
	writeErr(w, http.StatusInternalServerError, "internal server error")
}
