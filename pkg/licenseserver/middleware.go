package licenseserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"log"
	"net/http"
)

const adminKeyHeader = "X-Triton-Admin-Key"

// AdminKeyAuth returns middleware that validates the X-Triton-Admin-Key header.
// Keys are pre-hashed with SHA-256 so that hmac.Equal always compares
// fixed-length slices, eliminating the length side-channel present when
// using subtle.ConstantTimeCompare on variable-length strings.
func AdminKeyAuth(validKeys []string) func(http.Handler) http.Handler {
	// Hash all valid keys once at closure creation time.
	hashedValid := make([][sha256.Size]byte, len(validKeys))
	for i, k := range validKeys {
		hashedValid[i] = sha256.Sum256([]byte(k))
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get(adminKeyHeader)
			if key == "" {
				log.Printf("auth failure: missing admin key from %s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
				writeError(w, http.StatusUnauthorized, "missing admin key")
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
				log.Printf("auth failure: invalid admin key from %s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
				writeError(w, http.StatusForbidden, "invalid admin key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
