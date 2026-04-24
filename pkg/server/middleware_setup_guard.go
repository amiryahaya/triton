package server

import (
	"log"
	"net/http"
	"strings"

	"github.com/amiryahaya/triton/pkg/store"
)

// SetupGuard blocks all requests with 307→/api/v1/setup/status when no
// platform_admin exists, except for the setup endpoints and static assets.
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
			http.Redirect(w, r, "/api/v1/setup/status", http.StatusTemporaryRedirect)
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
		path == "/api/v1/health" ||
		strings.HasPrefix(path, "/ui/")
}
