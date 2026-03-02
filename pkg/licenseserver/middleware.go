package licenseserver

import (
	"crypto/subtle"
	"net/http"
)

const adminKeyHeader = "X-Triton-Admin-Key"

// AdminKeyAuth returns middleware that validates the X-Triton-Admin-Key header.
func AdminKeyAuth(validKeys []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get(adminKeyHeader)
			if key == "" {
				writeError(w, http.StatusUnauthorized, "missing admin key")
				return
			}
			valid := false
			for _, k := range validKeys {
				if subtle.ConstantTimeCompare([]byte(key), []byte(k)) == 1 {
					valid = true
				}
			}
			if !valid {
				writeError(w, http.StatusForbidden, "invalid admin key")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
