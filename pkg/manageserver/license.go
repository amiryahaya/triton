package manageserver

import "context"

// startLicence is a placeholder that Task 5.1 replaces with the full licence
// guard + usage pusher wiring. Declared here so /setup/license handler links
// in commits that land before Task 5.1. The real implementation is in the
// follow-up commit.
func (s *Server) startLicence(ctx context.Context) error { //nolint:unused,revive // populated by Task 5.1
	_ = ctx
	return nil
}
