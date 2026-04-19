package manageserver

import "github.com/amiryahaya/triton/pkg/manageserver/hosts"

// SetHostCapGuardForTest swaps the host-cap guard on the hosts admin
// handler. Intended for integration tests that assert the Batch H
// hard-cap enforcement path without constructing a signed licence.
//
// Safe to pass nil to revert; ClearSeatCapGuardForTest also clears
// this override as part of its blanket reset.
func SetHostCapGuardForTest(s *Server, g hosts.HostCapGuard) {
	s.mu.Lock()
	s.hostCapGuardOverride = g
	if s.hostsAdmin != nil {
		s.hostsAdmin.Guard = g
	}
	s.mu.Unlock()
}
