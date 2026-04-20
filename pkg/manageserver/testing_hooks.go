package manageserver

import (
	"context"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/manageserver/agents"
	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// SubHandlerGuardsForTest returns the Guard that each sub-handler
// (hosts, scan-jobs, agents) would consult on its next request so
// integration tests can assert startLicence correctly plumbed the
// licence guard down to the per-package cap enforcement.
//
// Invokes each handler's GuardProvider closure — which reads the
// override or s.licenceGuard under s.mu — rather than reading a shared
// Guard field. That makes this test hook the single, race-free way to
// observe what a real cap check would see at request time.
func SubHandlerGuardsForTest(s *Server) (hosts.HostCapGuard, scanjobs.ScanCapGuard, agents.AgentCapGuard) {
	var (
		hg hosts.HostCapGuard
		sg scanjobs.ScanCapGuard
		ag agents.AgentCapGuard
	)
	if s.hostsAdmin != nil && s.hostsAdmin.GuardProvider != nil {
		hg = s.hostsAdmin.GuardProvider()
	}
	if s.scanjobsAdmin != nil && s.scanjobsAdmin.GuardProvider != nil {
		sg = s.scanjobsAdmin.GuardProvider()
	}
	if s.agentsAdmin != nil && s.agentsAdmin.GuardProvider != nil {
		ag = s.agentsAdmin.GuardProvider()
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

// StartLicenceForTest exposes the unexported startLicence activation
// path so tests can rotate the licence guard deterministically without
// going through the /setup/license HTTP handler. Mostly used by the
// race test to ping-pong start/stop against concurrent handler reads.
func StartLicenceForTest(s *Server) error {
	return s.startLicence(context.Background())
}

// CollectUsageForTest exposes the unexported collectUsage so tests
// can assert it (a) records scans into the in-memory Guard and (b)
// returns the same metric set to the caller. Production code calls
// this indirectly via the UsagePusher's tick.
func CollectUsageForTest(s *Server) []license.UsageMetric {
	return s.collectUsage()
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
// tests swap in for hosts / scanjobs / agents so a single deferred
// call restores the server to a clean production default. Handlers
// pick up the cleared overrides on their next request via their
// GuardProvider closures.
func ClearSeatCapGuardForTest(s *Server) {
	s.mu.Lock()
	s.seatCapGuardOverride = nil
	s.hostCapGuardOverride = nil
	s.scanCapGuardOverride = nil
	s.agentCapGuardOverride = nil
	s.mu.Unlock()
}
