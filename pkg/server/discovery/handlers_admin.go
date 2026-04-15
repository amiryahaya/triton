package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/server/inventory"
)

// AuditRecorder is the narrow audit hook used by discovery handlers.
// Implemented by pkg/server.Server; tests pass a no-op or capturing
// fake. Handlers tolerate a nil recorder.
type AuditRecorder interface {
	Record(ctx context.Context, event, subject string, fields map[string]any)
}

// AdminHandlers are the operator-facing discovery endpoints. They are
// mounted under an already-authenticated + tenant-scoped subtree; the
// handlers pull orgID + userID from JWT claims on every request.
type AdminHandlers struct {
	Store          Store
	InventoryStore inventory.Store
	Audit          AuditRecorder
}

// NewAdminHandlers constructs an AdminHandlers. InventoryStore is used
// only by PromoteCandidates (discovery → inventory_hosts lift).
func NewAdminHandlers(s Store, inv inventory.Store, a AuditRecorder) *AdminHandlers {
	return &AdminHandlers{Store: s, InventoryStore: inv, Audit: a}
}

// DefaultDiscoveryPorts are probed when the caller does not specify a
// port list. These cover common SSH/HTTP/WinRM/RDP footprints so a
// zero-config scan has reasonable coverage.
var DefaultDiscoveryPorts = []int{22, 80, 443, 3389, 5985}

// --- helpers ---

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

// --- Create ---

type createRequest struct {
	EngineID string   `json:"engine_id"`
	CIDRs    []string `json:"cidrs"`
	Ports    []int    `json:"ports"`
}

// CreateDiscovery queues a new discovery job bound to an engine. CIDRs
// are validated via net.ParseCIDR; ports must fall in 1..65535. If
// Ports is empty it defaults to DefaultDiscoveryPorts.
func (h *AdminHandlers) CreateDiscovery(w http.ResponseWriter, r *http.Request) {
	orgID, userID, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	engineID, err := uuid.Parse(req.EngineID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "engine_id is required and must be a UUID")
		return
	}
	if len(req.CIDRs) == 0 {
		writeErr(w, http.StatusBadRequest, "cidrs is required (at least one)")
		return
	}
	totalAddrs := 0
	for _, c := range req.CIDRs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid CIDR %q: %v", c, err))
			return
		}
		// Count addresses, skipping net + broadcast for IPv4 blocks of
		// /30 or larger (matches engine-side expandCIDRs semantics).
		ones, bits := ipnet.Mask.Size()
		hostBits := bits - ones
		var count int
		if hostBits >= 31 {
			// /0../1 IPv4 or huge IPv6 — overflow guard, bail early.
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("CIDR %q too large", c))
			return
		}
		count = 1 << uint(hostBits)
		if bits == 32 && ones <= 30 && count >= 2 {
			count -= 2
		}
		totalAddrs += count
		if totalAddrs > DiscoveryMaxAddresses {
			writeErr(w, http.StatusBadRequest,
				fmt.Sprintf("total addresses %d exceeds cap %d", totalAddrs, DiscoveryMaxAddresses))
			return
		}
	}
	ports := req.Ports
	if len(ports) == 0 {
		ports = append([]int(nil), DefaultDiscoveryPorts...)
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid port %d: must be 1..65535", p))
			return
		}
	}

	job := Job{
		ID:          uuid.Must(uuid.NewV7()),
		OrgID:       orgID,
		EngineID:    engineID,
		RequestedBy: &userID,
		CIDRs:       req.CIDRs,
		Ports:       ports,
		Status:      StatusQueued,
	}
	saved, err := h.Store.CreateJob(r.Context(), job)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r.Context(), "discovery.job.create", saved.ID.String(), map[string]any{
		"engine_id": engineID.String(), "cidrs": req.CIDRs, "ports": ports,
	})
	writeJSON(w, http.StatusCreated, saved)
}

// --- List / Get ---

// ListDiscoveries returns all jobs for the caller's org.
func (h *AdminHandlers) ListDiscoveries(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	jobs, err := h.Store.ListJobs(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, jobs)
}

type jobWithCandidates struct {
	Job        Job         `json:"job"`
	Candidates []Candidate `json:"candidates"`
}

// GetDiscovery returns one job plus its candidates. Candidate list may
// be empty if the engine has not reported yet.
func (h *AdminHandlers) GetDiscovery(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	job, err := h.Store.GetJob(r.Context(), orgID, id)
	if err != nil {
		if errors.Is(err, ErrJobNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cands, err := h.Store.ListCandidates(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, jobWithCandidates{Job: job, Candidates: cands})
}

// --- Promote ---

type promoteRequest struct {
	CandidateIDs []string `json:"candidate_ids"`
	GroupID      string   `json:"group_id"`
}

type promoteError struct {
	CandidateID string `json:"candidate_id"`
	Error       string `json:"error"`
}

type promoteResponse struct {
	Promoted int            `json:"promoted"`
	Failed   int            `json:"failed"`
	Errors   []promoteError `json:"errors,omitempty"`
}

// PromoteCandidates lifts one or more discovery candidates into
// inventory_hosts under the given group. Each candidate is handled
// independently; duplicates/constraint failures are captured per-
// candidate and do not abort the batch. Successfully promoted
// candidates are marked in discovery_candidates.promoted.
func (h *AdminHandlers) PromoteCandidates(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	jobID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid job id")
		return
	}
	var req promoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	groupID, err := uuid.Parse(req.GroupID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "group_id is required and must be a UUID")
		return
	}
	if len(req.CandidateIDs) == 0 {
		writeErr(w, http.StatusBadRequest, "candidate_ids is required")
		return
	}

	// Verify the job belongs to this org, which also validates the
	// candidate_ids scope transitively (candidates FK to this job).
	if _, err := h.Store.GetJob(r.Context(), orgID, jobID); err != nil {
		if errors.Is(err, ErrJobNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	cands, err := h.Store.ListCandidates(r.Context(), jobID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	byID := make(map[uuid.UUID]Candidate, len(cands))
	for i := range cands {
		byID[cands[i].ID] = cands[i]
	}

	var resp promoteResponse
	promotedIDs := make([]uuid.UUID, 0, len(req.CandidateIDs))
	for _, rawID := range req.CandidateIDs {
		cid, err := uuid.Parse(rawID)
		if err != nil {
			resp.Failed++
			resp.Errors = append(resp.Errors, promoteError{CandidateID: rawID, Error: "invalid UUID"})
			continue
		}
		c, ok := byID[cid]
		if !ok {
			resp.Failed++
			resp.Errors = append(resp.Errors, promoteError{CandidateID: rawID, Error: "candidate not found on this job"})
			continue
		}
		host := inventory.Host{
			ID:       uuid.Must(uuid.NewV7()),
			OrgID:    orgID,
			GroupID:  groupID,
			Hostname: c.Hostname,
			Address:  c.Address,
			Mode:     "agentless",
		}
		if _, err := h.InventoryStore.CreateHost(r.Context(), host); err != nil {
			resp.Failed++
			resp.Errors = append(resp.Errors, promoteError{CandidateID: rawID, Error: err.Error()})
			continue
		}
		resp.Promoted++
		promotedIDs = append(promotedIDs, cid)
	}
	if len(promotedIDs) > 0 {
		if err := h.Store.MarkCandidatesPromoted(r.Context(), jobID, promotedIDs); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	h.audit(r.Context(), "discovery.candidates.promote", jobID.String(), map[string]any{
		"promoted": resp.Promoted, "failed": resp.Failed, "group_id": groupID.String(),
	})
	writeJSON(w, http.StatusOK, resp)
}

// --- Cancel ---

// CancelDiscovery flips a queued job to 'cancelled'. Returns 409 if
// the engine has already claimed the job.
func (h *AdminHandlers) CancelDiscovery(w http.ResponseWriter, r *http.Request) {
	orgID, _, ok := h.claims(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "missing or invalid claims")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.Store.CancelJob(r.Context(), orgID, id); err != nil {
		switch {
		case errors.Is(err, ErrJobNotFound):
			writeErr(w, http.StatusNotFound, err.Error())
		case errors.Is(err, ErrJobNotCancellable):
			writeErr(w, http.StatusConflict, err.Error())
		default:
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	h.audit(r.Context(), "discovery.job.cancel", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}
