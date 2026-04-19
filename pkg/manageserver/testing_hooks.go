package manageserver

// SetSeatCapGuardForTest swaps the seat-cap guard consulted by
// handleCreateUser for a caller-provided fake. Intended for integration
// tests that assert the seat-cap enforcement path without having to
// construct a signed licence token.
//
// Production code never calls this — the real guard is wired by
// startLicence. Pair with ClearSeatCapGuardForTest in t.Cleanup.
func SetSeatCapGuardForTest(s *Server, g SeatCapGuard) {
	s.mu.Lock()
	s.seatCapGuardOverride = g
	s.mu.Unlock()
}

// ClearSeatCapGuardForTest removes any test-injected cap guards from
// s. Clears the seat guard AND the per-package overrides that Batch H
// tests swap in for hosts (and later scanjobs / agents) so a single
// deferred call restores the server to a clean production default.
func ClearSeatCapGuardForTest(s *Server) {
	s.mu.Lock()
	s.seatCapGuardOverride = nil
	s.hostCapGuardOverride = nil
	s.scanCapGuardOverride = nil
	s.agentCapGuardOverride = nil
	if s.hostsAdmin != nil {
		s.hostsAdmin.Guard = nil
	}
	if s.scanjobsAdmin != nil {
		s.scanjobsAdmin.Guard = nil
	}
	if s.agentsAdmin != nil {
		s.agentsAdmin.Guard = nil
	}
	s.mu.Unlock()
}
