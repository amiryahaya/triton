package server

import (
	"net/http"
	"strings"

	"github.com/amiryahaya/triton/internal/license"
)

// LicenceGate is middleware that checks whether the request's API path
// is allowed by the licence. If guard is nil, all requests pass through.
//
// Gate logic uses HasFeature("diff_trend") which already handles the
// compat fallback: v2 tokens consult their Features.DiffTrend flag;
// pre-v2 tokens fall back to the tier-based compat mapping. This
// replaces the previous hard-coded tier check so a single code path
// covers both v2 and legacy tokens without duplicate logic.
func LicenceGate(guard *license.Guard) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if guard == nil {
				next.ServeHTTP(w, r)
				return
			}

			path := r.URL.Path
			if isDiffTrendPath(path) {
				if !guard.HasFeature("diff_trend") {
					writeError(w, http.StatusForbidden, "licence does not grant diff/trend access")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isDiffTrendPath returns true for /api/v1/diff and /api/v1/trend subtrees.
func isDiffTrendPath(path string) bool {
	return path == "/api/v1/diff" || strings.HasPrefix(path, "/api/v1/diff/") ||
		path == "/api/v1/trend" || strings.HasPrefix(path, "/api/v1/trend/")
}
