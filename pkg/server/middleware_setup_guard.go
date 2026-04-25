package server

import (
	"log"
	"net/http"
	"strings"

	"github.com/amiryahaya/triton/pkg/store"
)

// SetupGuard blocks all non-setup requests with 307→/ui/ when no
// platform_admin exists, allowing the browser to reach the first-run
// setup wizard. Setup endpoints, auth paths, and health checks bypass
// the guard via isSetupPath.
//
// Performance: after the first request that confirms setup is complete,
// s.setupComplete is set to true and subsequent requests skip the
// ListUsers DB query entirely. Setup completion is permanent — the
// flag is never cleared. Fix D4/C1.
func (s *Server) SetupGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.config.DisableSetupGuard || isSetupPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		// Fast path: once setup is confirmed complete, skip the DB query.
		if s.setupComplete.Load() {
			next.ServeHTTP(w, r)
			return
		}
		users, err := s.store.ListUsers(r.Context(), store.UserFilter{OrgID: store.PlatformOrgFilter})
		if err != nil {
			log.Printf("setup guard: %v", err)
			// On error, pass through rather than blocking all traffic.
			next.ServeHTTP(w, r)
			return
		}
		if len(users) == 0 {
			http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
			return
		}
		// Mark setup as complete so future requests skip this query.
		s.setupComplete.Store(true)
		next.ServeHTTP(w, r)
	})
}

// isSetupPath reports whether the request path should bypass the setup guard.
// The setup endpoints themselves, static UI assets, and health checks are
// always allowed through so the client can complete first-run onboarding.
func isSetupPath(path string) bool {
	return path == "/api/v1/setup/status" ||
		path == "/api/v1/setup" ||
		strings.HasPrefix(path, "/ui/") ||
		strings.HasPrefix(path, "/api/v1/auth/") ||
		strings.HasPrefix(path, "/api/v1/health")
}
