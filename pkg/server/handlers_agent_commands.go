package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/store"
)

// agentPollTimeout bounds how long the server will hold a long-poll
// request waiting for a state change or queued command before returning
// 204 No Content. Chosen to stay well under typical load-balancer idle
// timeouts (60-90s) while still amortizing the HTTP round-trip cost.
//
// Exposed as a package-level var (rather than a constant) so integration
// tests can shorten it without having to wait 30 real seconds per poll
// scenario — tests restore the default in t.Cleanup.
var agentPollTimeout = 30 * time.Second

// agentPollInterval is the poll tick used inside the long-poll loop to
// re-check paused state + pending commands. One second is a sensible
// balance between responsiveness (admins expect a pause to take effect
// within seconds) and DB load (60 queries/min per connected agent).
// Exposed as a var for the same reason as agentPollTimeout.
var agentPollInterval = 1 * time.Second

// handleAgentCommandsPoll implements GET /api/v1/agent/commands/poll.
//
// The handler performs an UpsertAgent on every poll so first-seen
// metadata is recorded without a separate registration step, then
// enters a long-poll loop that returns as soon as either:
//
//   - the agent row has a non-zero paused_until (admin pressed pause);
//   - or ClaimPendingCommandsForAgent returns a non-empty slice.
//
// If neither condition is met within agentPollTimeout, the handler
// returns 204 No Content and the agent is expected to reconnect. The
// request's own context cancellation (client disconnect) aborts the
// loop immediately — there is no point continuing to poll when the
// other end has already hung up.
func (s *Server) handleAgentCommandsPoll(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	if tenant == "" {
		writeError(w, http.StatusUnauthorized, "tenant context required")
		return
	}
	machineID := MachineIDFromContext(r.Context())
	if machineID == "" {
		writeError(w, http.StatusUnauthorized, "machine id required")
		return
	}

	ctx := r.Context()

	// Upsert first — ensures the agents row exists for subsequent
	// EnqueueAgentCommand calls (which have a FK on the composite
	// key). Also refreshes last_seen_at on every poll.
	agent := &store.AgentRecord{
		TenantID:  tenant,
		MachineID: machineID,
		Hostname:  r.Header.Get("X-Triton-Hostname"),
		OS:        r.Header.Get("X-Triton-Agent-OS"),
		Arch:      r.Header.Get("X-Triton-Agent-Arch"),
	}
	if err := s.store.UpsertAgent(ctx, agent); err != nil {
		log.Printf("agent poll: upsert agent %s/%s: %v", tenant, machineID, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	deadline := time.Now().Add(agentPollTimeout)
	for {
		// Pull the latest agent row so we see any admin-pushed pause
		// state, then claim pending commands. These two reads are
		// intentionally separate rather than a single JOIN because
		// ClaimPendingCommandsForAgent is an UPDATE that marks rows
		// as dispatched — it can only be issued once per batch.
		current, err := s.store.GetAgent(ctx, tenant, machineID)
		if err != nil {
			// Unexpected — UpsertAgent above just wrote the row.
			// Treat as a transient backend error rather than 404.
			log.Printf("agent poll: get agent %s/%s after upsert: %v", tenant, machineID, err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		cmds, err := s.store.ClaimPendingCommandsForAgent(ctx, tenant, machineID)
		if err != nil {
			log.Printf("agent poll: claim commands %s/%s: %v", tenant, machineID, err)
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		pausedActive := !current.PausedUntil.IsZero() && current.PausedUntil.After(time.Now())
		if pausedActive || len(cmds) > 0 {
			resp := agentPollResponse{}
			if pausedActive {
				resp.State.PausedUntil = current.PausedUntil.UTC()
			}
			for _, c := range cmds {
				resp.Commands = append(resp.Commands, agentPollCommand{
					ID:        c.ID,
					Type:      string(c.Type),
					Args:      c.Args,
					IssuedAt:  c.IssuedAt.UTC(),
					ExpiresAt: c.ExpiresAt.UTC(),
				})
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}

		// Nothing to send — block for one interval unless we've hit
		// the deadline or the client disconnected.
		if time.Now().After(deadline) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(agentPollInterval):
			// fall through to next iteration
		}
	}
}

// handleAgentCommandResult implements POST /api/v1/agent/commands/{id}/result.
//
// The command ID is scoped to (tenantID, machineID) by the store layer —
// an agent cannot acknowledge a command enqueued for a different machine
// even if it guesses the ID, because the UPDATE's WHERE clause also
// matches on machine_id. Returns 404 on mismatch rather than 403 to
// avoid leaking the existence of cross-agent command IDs.
func (s *Server) handleAgentCommandResult(w http.ResponseWriter, r *http.Request) {
	tenant := TenantFromContext(r.Context())
	if tenant == "" {
		writeError(w, http.StatusUnauthorized, "tenant context required")
		return
	}
	machineID := MachineIDFromContext(r.Context())
	if machineID == "" {
		writeError(w, http.StatusUnauthorized, "machine id required")
		return
	}

	cmdID := chi.URLParam(r, "id")
	if cmdID == "" {
		writeError(w, http.StatusBadRequest, "command id required")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	var req agentResultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Status != "executed" && req.Status != "rejected" {
		writeError(w, http.StatusBadRequest, `status must be "executed" or "rejected"`)
		return
	}

	if err := s.store.SetAgentCommandResult(r.Context(), tenant, machineID, cmdID, req.Status, req.Meta); err != nil {
		var nf *store.ErrNotFound
		if errors.As(err, &nf) {
			writeError(w, http.StatusNotFound, "command not found")
			return
		}
		log.Printf("agent result: set command result %s/%s/%s: %v", tenant, machineID, cmdID, err)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
