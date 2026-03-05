package server

import (
	"net/http"
	"strings"

	"github.com/amiryahaya/triton/internal/license"
)

// featureGateMapping maps API path prefixes to the licence feature they require.
var featureGateMapping = map[string]license.Feature{
	"/api/v1/diff":  license.FeatureDiff,
	"/api/v1/trend": license.FeatureTrend,
}

// LicenceGate is middleware that checks whether the request's API path
// is allowed by the licence tier. If guard is nil, all requests pass through.
func LicenceGate(guard *license.Guard) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if guard == nil {
				next.ServeHTTP(w, r)
				return
			}

			path := r.URL.Path
			for prefix, feature := range featureGateMapping {
				if path == prefix || strings.HasPrefix(path, prefix+"/") {
					if err := guard.EnforceFeature(feature); err != nil {
						writeError(w, http.StatusForbidden, err.Error())
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
