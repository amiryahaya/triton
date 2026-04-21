package manageserver

import (
	"net/http"
)

// handleListSecurityEvents returns the current set of active (email, IP)
// login lockouts.
// GET /api/v1/admin/security-events
// Response: {"active_lockouts": [...]} — empty slice, never null. 200 always.
func (s *Server) handleListSecurityEvents(w http.ResponseWriter, r *http.Request) {
	lockouts := s.loginLimiter.ActiveLockouts()
	if lockouts == nil {
		lockouts = []Lockout{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active_lockouts": lockouts,
	})
}

// handleClearSecurityEvent removes the lockout for one (email, IP) pair.
// DELETE /api/v1/admin/security-events?email=<email>&ip=<ip>
// 204 on success, 404 if the entry does not exist, 400 if params missing.
func (s *Server) handleClearSecurityEvent(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	ip := r.URL.Query().Get("ip")
	if email == "" || ip == "" {
		writeError(w, http.StatusBadRequest, "email and ip query parameters are required")
		return
	}
	if !s.loginLimiter.Clear(email, ip) {
		writeError(w, http.StatusNotFound, "no active lockout for the given email and ip")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
