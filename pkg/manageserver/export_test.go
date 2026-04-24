package manageserver

import "github.com/amiryahaya/triton/pkg/managestore"

// TestRefreshGuard calls refreshGuard — used in unit tests.
func (s *Server) TestRefreshGuard(token string) { s.refreshGuard(token) }

// TestGuardTier returns the current guard's tier string — used in unit tests.
func (s *Server) TestGuardTier() string {
	g := s.guardSnapshot()
	if g == nil {
		return ""
	}
	return string(g.Tier())
}

// TestStore returns the server's store — used in tests.
func (s *Server) TestStore() managestore.Store { return s.store }
