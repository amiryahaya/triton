package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

type mtlsCtxKey struct{}

// EngineFromContext returns the enrolled engine resolved by
// MTLSMiddleware, or nil if the request did not pass through the
// middleware (which is a programming error for gateway routes).
func EngineFromContext(ctx context.Context) *Engine {
	e, _ := ctx.Value(mtlsCtxKey{}).(*Engine)
	return e
}

// MTLSMiddleware rejects requests that do not present a client
// certificate matching a known (non-revoked) engine. On success it
// stashes the resolved Engine into the request context so downstream
// handlers can access it via EngineFromContext.
//
// Trust chain validation is the TLS stack's job — this middleware
// only maps verified leaf fingerprints to engines in the database.
// The server's TLS config uses ClientAuth = RequireAnyClientCert
// plus a VerifyPeerCertificate callback that walks the per-org CA
// pool (see cmd/server_engine.go buildEngineTLSConfig). By the time
// a request reaches this middleware, the chain is already verified;
// we trust whatever leaf came through and only resolve identity.
func MTLSMiddleware(store Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "client cert required", http.StatusUnauthorized)
				return
			}
			leaf := r.TLS.PeerCertificates[0]
			fp := sha256.Sum256(leaf.Raw)
			fpHex := hex.EncodeToString(fp[:])

			eng, err := store.GetEngineByFingerprint(r.Context(), fpHex)
			if err != nil {
				http.Error(w, "unknown engine", http.StatusUnauthorized)
				return
			}
			if eng.Status == StatusRevoked {
				http.Error(w, "engine revoked", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), mtlsCtxKey{}, &eng)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
