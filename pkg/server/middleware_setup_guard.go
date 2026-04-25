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
func (s *Server) SetupGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSetupPath(r.URL.Path) {
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
