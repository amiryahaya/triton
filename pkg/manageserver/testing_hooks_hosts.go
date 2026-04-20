package manageserver

import "github.com/amiryahaya/triton/pkg/manageserver/hosts"

// SetHostCapGuardForTest swaps the host-cap guard on the hosts admin
// handler. Intended for integration tests that assert the Batch H
// hard-cap enforcement path without constructing a signed licence.
//
// Safe to pass nil to revert; ClearSeatCapGuardForTest also clears
// this override as part of its blanket reset. Handlers observe the
// change on their next request because they consult the GuardProvider
// closure — which reads s.hostCapGuardOverride under s.mu — per call.
func SetHostCapGuardForTest(s *Server, g hosts.HostCapGuard) {
	s.mu.Lock()
	s.hostCapGuardOverride = g
	s.mu.Unlock()
}
