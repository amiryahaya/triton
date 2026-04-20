package agents

import (
	"context"
	"net/http"
	"strings"

	"github.com/amiryahaya/triton/pkg/manageserver/ca"
)

// cnCtxKey is the private context key under which MTLSCNAuth stashes
// the client cert's CN. CNFromContext is the only way for handlers
// to read it — prevents accidental clobber by unrelated context
// values that happen to use the same string.
type cnCtxKey struct{}

// MTLSCNAuth is the gateway's authentication + authorisation middleware.
// It assumes the caller has configured the TLS listener with
// tls.RequireAndVerifyClientCert + ClientCAs pinned to the Manage CA,
// so by the time a request arrives here the cert chain has already
// been verified. The middleware adds two additional checks:
//
//  1. The leaf CN starts with `prefix` (e.g. "agent:") — a defence-
//     in-depth guard against the Manage CA accidentally issuing a
//     valid-chain cert with the wrong subject.
//  2. The leaf's serial is not in the revocation list. IsRevoked
//     hits the 30s in-memory cache and only falls through to the DB
//     on TTL expiry, so the per-request overhead is a map lookup.
//
// On success, the CN is stashed in the request context so downstream
// handlers can recover the agent ID without re-parsing the cert.
func MTLSCNAuth(prefix string, caStore ca.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "client cert required", http.StatusUnauthorized)
				return
			}
			leaf := r.TLS.PeerCertificates[0]
			cn := leaf.Subject.CommonName
			if !strings.HasPrefix(cn, prefix) {
				http.Error(w, "wrong cn prefix", http.StatusUnauthorized)
				return
			}
			serial := leaf.SerialNumber.Text(16)
			revoked, err := caStore.IsRevoked(r.Context(), serial)
			if err != nil {
				// Fail closed on DB errors — otherwise a postgres outage
				// silently opens the gateway to every revoked cert.
				http.Error(w, "revocation check failed", http.StatusServiceUnavailable)
				return
			}
			if revoked {
				http.Error(w, "cert revoked", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), cnCtxKey{}, cn)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CNFromContext returns the client cert CN that MTLSCNAuth stashed
// during authentication. Returns "" if the middleware didn't run —
// handlers wired outside the gateway should NOT call this.
func CNFromContext(ctx context.Context) string {
	v, _ := ctx.Value(cnCtxKey{}).(string)
	return v
}
