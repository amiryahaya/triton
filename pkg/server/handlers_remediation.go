package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/store"
)

// Audit event type constants for remediation actions.
const (
	auditFindingStatusSet    = "finding.status_set"
	auditFindingStatusRevert = "finding.status_revert"
)

// validRemediationStatuses is the set of statuses a caller may explicitly set.
// "open" is the implicit default and is only written by handleRevertFinding.
var validRemediationStatuses = map[string]bool{
	"in_progress": true,
	"resolved":    true,
	"accepted":    true,
}

// setFindingStatusRequest is the JSON body for POST /findings/{id}/status.
type setFindingStatusRequest struct {
	Status    string  `json:"status"`
	Reason    string  `json:"reason"`
	ExpiresAt *string `json:"expiresAt"` // RFC 3339 string or omitted
}

// revertFindingRequest is the JSON body for POST /findings/{id}/revert.
type revertFindingRequest struct {
	Reason string `json:"reason"`
}

// setStatusResponse is the body returned on a successful status mutation.
type setStatusResponse struct {
	FindingKey string    `json:"findingKey"`
	Status     string    `json:"status"`
	ChangedAt  time.Time `json:"changedAt"`
}

// actorIDFromRequest returns the authenticated user's ID, or "agent" when the
// request was submitted by a license-token agent (no JWT user in context).
func actorIDFromRequest(r *http.Request) string {
	if u := UserFromContext(r.Context()); u != nil {
		return u.ID
	}
	return "agent"
}

// POST /api/v1/findings/{id}/status
//
// Sets the remediation status of a finding. The finding must belong to the
// authenticated tenant. Valid statuses are in_progress, resolved, accepted.
// accepted may optionally carry an expiresAt timestamp; when the expiry
// passes the finding is treated as open again by the summary queries.
func (s *Server) handleSetFindingStatus(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	id := chi.URLParam(r, "id")

	var body setFindingStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if !validRemediationStatuses[body.Status] {
		writeError(w, http.StatusBadRequest, "status must be one of: in_progress, resolved, accepted")
		return
	}

	finding, err := s.store.GetFindingByID(r.Context(), id, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "finding not found")
			return
		}
		log.Printf("handleSetFindingStatus: GetFindingByID: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	findingKey := store.ComputeFindingKey(orgID, finding.Hostname, finding.Algorithm, finding.KeySize, finding.Module)

	var expiresAt *time.Time
	if body.ExpiresAt != nil && *body.ExpiresAt != "" {
		t, parseErr := time.Parse(time.RFC3339, *body.ExpiresAt)
		if parseErr != nil {
			writeError(w, http.StatusBadRequest, "expiresAt must be an RFC 3339 timestamp")
			return
		}
		expiresAt = &t
	}

	changedAt := time.Now().UTC()
	entry := &store.FindingStatusEntry{
		FindingKey: findingKey,
		OrgID:      orgID,
		Status:     body.Status,
		Reason:     body.Reason,
		ChangedBy:  actorIDFromRequest(r),
		ChangedAt:  changedAt,
		ExpiresAt:  expiresAt,
	}
	if err := s.store.SetFindingStatus(r.Context(), entry); err != nil {
		log.Printf("handleSetFindingStatus: SetFindingStatus: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.writeAudit(r, auditFindingStatusSet, id, map[string]any{
		"status":     body.Status,
		"findingKey": findingKey,
	})

	// Trigger T2+T3 pipeline refresh for the affected host.
	s.EnqueuePipelineJob(orgID, finding.Hostname, finding.ScanID)

	writeJSON(w, http.StatusOK, setStatusResponse{
		FindingKey: findingKey,
		Status:     body.Status,
		ChangedAt:  changedAt,
	})
}

// POST /api/v1/findings/{id}/revert
//
// Reverts a finding back to "open" status. This is equivalent to calling
// handleSetFindingStatus with status="open" and is a separate endpoint for
// clarity and separate RBAC auditing.
func (s *Server) handleRevertFinding(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	id := chi.URLParam(r, "id")

	var body revertFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		// Body is optional for revert — an empty body is fine.
		body = revertFindingRequest{}
	}

	finding, err := s.store.GetFindingByID(r.Context(), id, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "finding not found")
			return
		}
		log.Printf("handleRevertFinding: GetFindingByID: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	findingKey := store.ComputeFindingKey(orgID, finding.Hostname, finding.Algorithm, finding.KeySize, finding.Module)

	changedAt := time.Now().UTC()
	entry := &store.FindingStatusEntry{
		FindingKey: findingKey,
		OrgID:      orgID,
		Status:     "open",
		Reason:     body.Reason,
		ChangedBy:  actorIDFromRequest(r),
		ChangedAt:  changedAt,
	}
	if err := s.store.SetFindingStatus(r.Context(), entry); err != nil {
		log.Printf("handleRevertFinding: SetFindingStatus: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.writeAudit(r, auditFindingStatusRevert, id, map[string]any{
		"findingKey": findingKey,
	})

	s.EnqueuePipelineJob(orgID, finding.Hostname, finding.ScanID)

	writeJSON(w, http.StatusOK, setStatusResponse{
		FindingKey: findingKey,
		Status:     "open",
		ChangedAt:  changedAt,
	})
}

// GET /api/v1/findings/{id}/history
//
// Returns the full status-change history for a finding, newest first.
// The finding is resolved to a finding_key using the same deterministic hash
// so history is portable across scan IDs. Returns [] (not null) when no
// status changes have been recorded.
func (s *Server) handleFindingHistory(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())
	id := chi.URLParam(r, "id")

	finding, err := s.store.GetFindingByID(r.Context(), id, orgID)
	if err != nil {
		if isNotFound(err) {
			writeError(w, http.StatusNotFound, "finding not found")
			return
		}
		log.Printf("handleFindingHistory: GetFindingByID: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	findingKey := store.ComputeFindingKey(orgID, finding.Hostname, finding.Algorithm, finding.KeySize, finding.Module)

	history, err := s.store.GetFindingHistory(r.Context(), findingKey, orgID)
	if err != nil {
		log.Printf("handleFindingHistory: GetFindingHistory: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if history == nil {
		history = []store.FindingStatusEntry{}
	}
	writeJSON(w, http.StatusOK, history)
}

// GET /api/v1/remediation/summary
//
// Returns open/in_progress/resolved/accepted/total counts for the
// authenticated tenant's latest findings. Accepted findings whose
// expiresAt has passed are counted as open.
func (s *Server) handleRemediationSummary(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())

	summary, err := s.store.GetRemediationSummary(r.Context(), orgID)
	if err != nil {
		log.Printf("handleRemediationSummary: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// GET /api/v1/remediation?status=X&hostname=X&pqc_status=X
//
// Returns findings enriched with their current remediation status. All
// three query parameters are optional. Returns {"data": [...]} (never null).
func (s *Server) handleListRemediation(w http.ResponseWriter, r *http.Request) {
	orgID := TenantFromContext(r.Context())

	statusFilter := r.URL.Query().Get("status")
	hostnameFilter := r.URL.Query().Get("hostname")
	pqcFilter := r.URL.Query().Get("pqc_status")

	rows, err := s.store.ListRemediationFindings(r.Context(), orgID, statusFilter, hostnameFilter, pqcFilter)
	if err != nil {
		log.Printf("handleListRemediation: %v", err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rows == nil {
		rows = []store.RemediationRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rows})
}
