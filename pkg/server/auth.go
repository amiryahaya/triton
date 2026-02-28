package server

import (
	"crypto/subtle"
	"net/http"
)

const apiKeyHeader = "X-Triton-API-Key"

// APIKeyAuth returns middleware that validates the X-Triton-API-Key header
// using constant-time comparison to prevent timing attacks.
func APIKeyAuth(validKeys []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get(apiKeyHeader)
			if key == "" {
				writeError(w, http.StatusUnauthorized, "missing API key")
				return
			}
			valid := false
			// Check all keys to ensure constant-time comparison regardless of
			// which key matches. Breaking early would leak timing information.
			for _, k := range validKeys {
				if subtle.ConstantTimeCompare([]byte(key), []byte(k)) == 1 {
					valid = true
				}
			}
			if !valid {
				writeError(w, http.StatusForbidden, "invalid API key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
