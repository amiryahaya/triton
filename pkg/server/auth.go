package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
)

const (
	apiKeyHeader     = "X-Triton-API-Key"
	serviceKeyHeader = "X-Triton-Service-Key"
)

// ServiceKeyAuth returns middleware that validates the X-Triton-Service-Key
// header against a single shared secret. Used by the report server's
// /api/v1/admin/* routes to authenticate service-to-service calls from the
// license server (org provisioning, future propagation events).
//
// Constant-time comparison via SHA-256 pre-hash, same pattern as APIKeyAuth.
// An empty sharedKey is a misconfiguration — the route group should not be
// registered at all in that case (see server.go).
func ServiceKeyAuth(sharedKey string) func(http.Handler) http.Handler {
	hashedExpected := sha256.Sum256([]byte(sharedKey))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provided := r.Header.Get(serviceKeyHeader)
			if provided == "" {
				writeError(w, http.StatusUnauthorized, "missing service key")
				return
			}
			hashedProvided := sha256.Sum256([]byte(provided))
			if !hmac.Equal(hashedProvided[:], hashedExpected[:]) {
				writeError(w, http.StatusForbidden, "invalid service key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// APIKeyAuth returns middleware that validates the X-Triton-API-Key header
// using constant-time comparison to prevent timing attacks.
// Keys are pre-hashed with SHA-256 so that hmac.Equal always compares
// fixed-length slices, eliminating the length side-channel present when
// using subtle.ConstantTimeCompare on variable-length strings.
func APIKeyAuth(validKeys []string) func(http.Handler) http.Handler {
	// Hash all valid keys once at closure creation time.
	hashedValid := make([][sha256.Size]byte, len(validKeys))
	for i, k := range validKeys {
		hashedValid[i] = sha256.Sum256([]byte(k))
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get(apiKeyHeader)
			if key == "" {
				writeError(w, http.StatusUnauthorized, "missing API key")
				return
			}
			hashedKey := sha256.Sum256([]byte(key))
			valid := false
			// Always iterate all keys to prevent early-exit timing leaks.
			for _, h := range hashedValid {
				if hmac.Equal(hashedKey[:], h[:]) {
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
