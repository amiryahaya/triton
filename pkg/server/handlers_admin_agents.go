package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/store"
)

// agentPauseMaxDuration caps how far into the future an admin can set
// paused_until. 90 days is enough to cover quarterly maintenance windows
// without letting a pause silently outlive the operator who set it.
const agentPauseMaxDuration = 90 * 24 * time.Hour

// defaultAgentCommandExpiryMinutes is the fallback expires_at offset when
// the admin request omits expiresInMinutes. One hour is generous for a
// normally-connected agent (poll interval ~30s) and short enough that an
// orphan command doesn't linger for days.
const defaultAgentCommandExpiryMinutes = 60

// adminListAgentsLimit is the maximum number of agent rows returned to
// an admin list request. Matches the 500-row convention used elsewhere
// in the server package (scans list).
const adminListAgentsLimit = 500

// adminListCommandsLimit is the default history depth returned with
// the agent detail view. 50 is enough to cover a typical day of poll
// activity without paging on the UI side.
const adminListCommandsLimit = 50

// adminTenantOrg resolves the requesting admin's org_id from the
// authenticated request context. Admin routes run behind JWTAuth which
// populates UserFromContext but not TenantContextFromContext, so we
// prefer the user's OrgID and fall back to TenantFromContext for
// defence-in-depth (a future admin route might be chained differently).
func adminTenantOrg(r *http.Request) string {
	if u := UserFromContext(r.Context()); u != nil && u.OrgID != "" {
		return u.OrgID
	}
	return TenantFromContext(r.Context())
}

// handleAdminListAgents returns every agent for the requesting admin's
// tenant, newest-last-seen first. Bounded at 500 rows.
func (s *Server) handleAdminListAgents(w http.ResponseWriter, r *http.Request) {
	tenant := adminTenantOrg(r)
	if tenant == "" {
		writeError(w, http.StatusUnauthorized, "tenant context required")
		return
	}
	rows, err := s.store.ListAgentsByTenant(r.Context(), tenant, adminListAgentsLimit)
	if err != nil {
		log.Printf("admin list agents (%s): %v", tenant, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": rows})
}

// handleAdminGetAgent returns one agent plus its most recent commands.
func (s *Server) handleAdminGetAgent(w http.ResponseWriter, r *http.Request) {
	tenant := adminTenantOrg(r)
	if tenant == "" {
		writeError(w, http.StatusUnauthorized, "tenant context required")
		return
	}
	mid := chi.URLParam(r, "machineID")
	if mid == "" {
		writeError(w, http.StatusBadRequest, "machineID required")
		return
	}

	agent, err := s.store.GetAgent(r.Context(), tenant, mid)
	if err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		log.Printf("admin get agent (%s/%s): %v", tenant, mid, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	cmds, err := s.store.ListAgentCommands(r.Context(), tenant, mid, adminListCommandsLimit)
	if err != nil {
		log.Printf("admin get agent list commands (%s/%s): %v", tenant, mid, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"agent":    agent,
		"commands": cmds,
	})
}

// handleAdminAgentPause sets paused_until for a specific agent.
//
// Exactly one of `until` or `durationSeconds` must be provided. The
// XOR constraint is enforced here rather than at the store level so
// the API surface is explicit (the store takes an absolute time) and
// the 400 response is easy to wire into the admin UI.
func (s *Server) handleAdminAgentPause(w http.ResponseWriter, r *http.Request) {
	tenant := adminTenantOrg(r)
	if tenant == "" {
		writeError(w, http.StatusUnauthorized, "tenant context required")
		return
	}
	mid := chi.URLParam(r, "machineID")
	if mid == "" {
		writeError(w, http.StatusBadRequest, "machineID required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req adminPauseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	hasUntil := req.Until != nil && !req.Until.IsZero()
	hasDuration := req.DurationSeconds > 0
	if hasUntil == hasDuration {
		writeError(w, http.StatusBadRequest, `exactly one of "until" or "durationSeconds" must be set`)
		return
	}

	now := time.Now().UTC()
	var until time.Time
	if hasUntil {
		until = req.Until.UTC()
	} else {
		until = now.Add(time.Duration(req.DurationSeconds) * time.Second)
	}

	if !until.After(now) {
		writeError(w, http.StatusBadRequest, "pause until must be in the future")
		return
	}
	if until.Sub(now) > agentPauseMaxDuration {
		writeError(w, http.StatusBadRequest, "pause duration exceeds 90-day maximum")
		return
	}

	if err := s.store.SetAgentPausedUntil(r.Context(), tenant, mid, until); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		log.Printf("admin pause agent (%s/%s): %v", tenant, mid, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.writeAudit(r, "agent.paused", mid, map[string]any{
		"machineID": mid,
		"until":     until.Format(time.RFC3339),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"pausedUntil": until,
	})
}

// handleAdminAgentPauseClear resumes a paused agent by nulling the
// paused_until column.
func (s *Server) handleAdminAgentPauseClear(w http.ResponseWriter, r *http.Request) {
	tenant := adminTenantOrg(r)
	if tenant == "" {
		writeError(w, http.StatusUnauthorized, "tenant context required")
		return
	}
	mid := chi.URLParam(r, "machineID")
	if mid == "" {
		writeError(w, http.StatusBadRequest, "machineID required")
		return
	}

	if err := s.store.ClearAgentPausedUntil(r.Context(), tenant, mid); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		log.Printf("admin clear pause (%s/%s): %v", tenant, mid, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.writeAudit(r, "agent.pause_cleared", mid, map[string]any{
		"machineID": mid,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAdminEnqueueCommand inserts a pending command into the queue
// for a specific agent. Rejects unknown agents with 404 rather than
// letting the FK violation surface as a 500.
func (s *Server) handleAdminEnqueueCommand(w http.ResponseWriter, r *http.Request) {
	tenant := adminTenantOrg(r)
	if tenant == "" {
		writeError(w, http.StatusUnauthorized, "tenant context required")
		return
	}
	mid := chi.URLParam(r, "machineID")
	if mid == "" {
		writeError(w, http.StatusBadRequest, "machineID required")
		return
	}

	// Verify the agent row exists first — without this, a typo'd
	// machineID would bubble up as a FK violation from the INSERT,
	// which surfaces as a generic 500 and hides the real cause.
	if _, err := s.store.GetAgent(r.Context(), tenant, mid); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "agent not found")
			return
		}
		log.Printf("admin enqueue get agent (%s/%s): %v", tenant, mid, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req adminAgentCommandRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Type != string(store.AgentCommandCancel) && req.Type != string(store.AgentCommandForceRun) {
		writeError(w, http.StatusBadRequest, `type must be "cancel" or "force_run"`)
		return
	}

	expiryMinutes := req.ExpiresInMinutes
	if expiryMinutes <= 0 {
		expiryMinutes = defaultAgentCommandExpiryMinutes
	}
	expiresAt := time.Now().UTC().Add(time.Duration(expiryMinutes) * time.Minute)

	actor := "unknown"
	if u := UserFromContext(r.Context()); u != nil {
		actor = u.ID
	} else if tc := TenantContextFromContext(r.Context()); tc != nil && tc.User != nil {
		actor = tc.User.ID
	}

	cmd := &store.AgentCommand{
		ID:        uuid.Must(uuid.NewV7()).String(),
		TenantID:  tenant,
		MachineID: mid,
		Type:      store.AgentCommandType(req.Type),
		Args:      req.Args,
		IssuedBy:  actor,
		ExpiresAt: expiresAt,
	}
	out, err := s.store.EnqueueAgentCommand(r.Context(), cmd)
	if err != nil {
		log.Printf("admin enqueue command (%s/%s): %v", tenant, mid, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	s.writeAudit(r, "agent.command_issued", mid, map[string]any{
		"commandID": out.ID,
		"type":      string(out.Type),
	})
	writeJSON(w, http.StatusCreated, out)
}
