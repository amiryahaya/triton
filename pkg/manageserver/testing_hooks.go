package manageserver

import (
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// SubHandlerGuardsForTest returns the current Guard values on each
// sub-handler package (hosts, scan-jobs, agents) so integration tests
// can assert that startLicence correctly propagated the licence guard
// down to the handlers that enforce per-package caps.
//
// Production code never reads these; the handlers consult their own
// `Guard` field directly. This accessor is the only way to cross the
// package boundary without exporting the fields themselves.
func SubHandlerGuardsForTest(s *Server) (hosts.HostCapGuard, scanjobs.ScanCapGuard, agents.AgentCapGuard) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var (
		hg hosts.HostCapGuard
		sg scanjobs.ScanCapGuard
		ag agents.AgentCapGuard
	)
	if s.hostsAdmin != nil {
		hg = s.hostsAdmin.Guard
	}
	if s.scanjobsAdmin != nil {
		sg = s.scanjobsAdmin.Guard
	}
	if s.agentsAdmin != nil {
		ag = s.agentsAdmin.Guard
	}
	return hg, sg, ag
}

// LicenceGuardForTest returns the top-level Server.licenceGuard so
// tests can distinguish "guard never wired" from "guard wired but not
// propagated to sub-handlers" without having to mint a signed token.
func LicenceGuardForTest(s *Server) *license.Guard {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.licenceGuard
}

// StopLicenceForTest exposes the unexported stopLicence shutdown path
// so tests can assert the licence teardown contract (guard cleared on
// server, guards cleared on all sub-handlers) without having to drive
// a full Run() -> cancel cycle.
func StopLicenceForTest(s *Server) {
	s.stopLicence()
}

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
