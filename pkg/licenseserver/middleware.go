package licenseserver

import (
	"crypto/subtle"
	"log"
	"net/http"
)

const adminKeyHeader = "X-Triton-Admin-Key"

// AdminKeyAuth returns middleware that validates the X-Triton-Admin-Key header.
func AdminKeyAuth(validKeys []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get(adminKeyHeader)
			if key == "" {
				log.Printf("auth failure: missing admin key from %s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
				writeError(w, http.StatusUnauthorized, "missing admin key")
				return
			}
			valid := false
			for _, k := range validKeys {
				if subtle.ConstantTimeEq(int32(len(key)), int32(len(k))) == 1 &&
					subtle.ConstantTimeCompare([]byte(key), []byte(k)) == 1 {
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
