package manageserver

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/license"
)

type licenceLifecycleResp struct {
	OK        bool   `json:"ok"`
	Tier      string `json:"tier,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// handleLicenceRefresh re-activates the stored licence key against the
// stored License Server URL, refreshing the signed token and guard.
func (s *Server) handleLicenceRefresh(w http.ResponseWriter, r *http.Request) {
	state, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !state.LicenseActivated {
		writeError(w, http.StatusConflict, "no active licence to refresh")
		return
	}

	client := license.NewServerClient(state.LicenseServerURL)
	resp, err := client.Activate(state.LicenseKey, license.ActivationTypeManageServer, state.ServerName)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := s.store.UpdateLicenseToken(r.Context(), resp.Token); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist token")
		return
	}
	s.refreshGuard(resp.Token)

	writeJSON(w, http.StatusOK, licenceLifecycleResp{
		OK:        true,
		Tier:      resp.Tier,
		ExpiresAt: resp.ExpiresAt,
	})
}

// handleLicenceReplace activates a new licence key against the stored
// License Server URL, replacing the key and token.
func (s *Server) handleLicenceReplace(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LicenseKey string `json:"license_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.LicenseKey == "" {
		writeError(w, http.StatusBadRequest, "license_key is required")
		return
	}

	state, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !state.LicenseActivated {
		writeError(w, http.StatusConflict, "no active licence to replace")
		return
	}

	client := license.NewServerClient(state.LicenseServerURL)
	resp, err := client.Activate(req.LicenseKey, license.ActivationTypeManageServer, state.ServerName)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := s.store.UpdateLicenseKey(r.Context(), req.LicenseKey, resp.Token); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist key")
		return
	}
	s.refreshGuard(resp.Token)

	writeJSON(w, http.StatusOK, licenceLifecycleResp{
		OK:        true,
		Tier:      resp.Tier,
		ExpiresAt: resp.ExpiresAt,
	})
}

// handleLicenceDeactivate releases the seat on the License Server. If
// scan jobs are active, schedules deactivation via the watcher instead.
func (s *Server) handleLicenceDeactivate(w http.ResponseWriter, r *http.Request) {
	state, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !state.LicenseActivated {
		writeError(w, http.StatusConflict, "no active licence")
		return
	}
	if state.PendingDeactivation {
		writeError(w, http.StatusConflict, "deactivation already pending")
		return
	}

	// Count active scan jobs via tenant ID (= instance_id).
	var activeScans int64
	if state.InstanceID != "" {
		if tenantID, err2 := uuid.Parse(state.InstanceID); err2 == nil {
			activeScans, _ = s.scanjobsStore.CountActive(r.Context(), tenantID)
		}
	}

	if activeScans == 0 {
		if err := s.deactivateNow(r.Context()); err != nil {
			log.Printf("licence: deactivateNow: %v", err)
			writeError(w, http.StatusInternalServerError, "deactivation failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pending": false})
		return
	}

	if err := s.store.SetPendingDeactivation(r.Context(), true); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if s.watcherRunning.CompareAndSwap(false, true) {
		s.mu.RLock()
		watcherCtx := s.runCtx
		s.mu.RUnlock()
		if watcherCtx == nil {
			watcherCtx = context.Background() // fallback for tests that don't call Run()
		}
		go func() {
			defer s.watcherRunning.Store(false)
			s.runDeactivationWatcher(watcherCtx)
		}()
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"pending":      true,
		"active_scans": activeScans,
	})
}

// handleCancelDeactivation clears a pending deactivation.
func (s *Server) handleCancelDeactivation(w http.ResponseWriter, r *http.Request) {
	if err := s.store.SetPendingDeactivation(r.Context(), false); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
