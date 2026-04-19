package manageserver

import (
	"encoding/json"
	"net/http"
)

// handleHealth returns a trivial OK payload for orchestrators / load balancers.
// Available even in setup mode so deployments can probe liveness before
// configuring the licence.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":         true,
		"setup_mode": s.isSetupMode(),
	})
}

// handleSetupStatus returns {admin_created, license_activated, setup_required}.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	state, err := s.store.GetSetup(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read setup state")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"admin_created":     state.AdminCreated,
		"license_activated": state.LicenseActivated,
		"setup_required":    !state.AdminCreated || !state.LicenseActivated,
	})
}

// --- tiny JSON helpers, identical shape to licenseserver's ---

const maxRequestBody = 1 << 20 // 1 MiB

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
