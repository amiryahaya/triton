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
