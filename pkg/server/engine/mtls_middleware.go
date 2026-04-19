package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/amiryahaya/triton/pkg/server/manage_enrol"
)

type mtlsCtxKey struct{}
type manageCtxKey struct{}

// EngineFromContext returns the enrolled engine resolved by
// MTLSMiddleware, or nil if the request did not pass through the
// middleware (which is a programming error for gateway routes).
func EngineFromContext(ctx context.Context) *Engine {
	e, _ := ctx.Value(mtlsCtxKey{}).(*Engine)
	return e
}

// ContextWithEngine injects an Engine into ctx using the same key the
// mTLS middleware uses. Exported solely for tests (and for wiring
// alternatives to the mTLS middleware such as a local test harness).
func ContextWithEngine(ctx context.Context, e *Engine) context.Context {
	return context.WithValue(ctx, mtlsCtxKey{}, e)
}

// ManageInstanceFromContext returns the enrolled Manage instance
// resolved by MTLSMiddleware when the client cert's CN starts with
// `manage:`, or nil otherwise. Handlers that expect a Manage caller
// MUST nil-check — a caller presenting an `engine:` CN will not have
// this value set.
func ManageInstanceFromContext(ctx context.Context) *manage_enrol.ManageInstance {
	mi, _ := ctx.Value(manageCtxKey{}).(*manage_enrol.ManageInstance)
	return mi
}

// ContextWithManageInstance mirrors ContextWithEngine for the Manage
// bucket. Exported for tests.
func ContextWithManageInstance(ctx context.Context, mi *manage_enrol.ManageInstance) context.Context {
	return context.WithValue(ctx, manageCtxKey{}, mi)
}

// MTLSMiddleware rejects requests that do not present a recognised
// client cert, resolves the caller identity via the appropriate store,
// and stashes the resolved *Engine or *ManageInstance on the request
// context for downstream handlers.
//
// CN prefixes are the routing discriminator:
//
//	engine:<label>              — fleet engine; resolved by SHA-256
//	                              fingerprint via engineStore.
//	manage:<licHash>:<uuid>     — enrolled Manage instance; resolved by
//	                              the signed leaf's serial number via
//	                              manageStore.
//	<anything else>             — rejected 401.
//
// Both stores are independently optional. Passing nil for manageStore
// is legal — a Report-only deployment without Manage enrolled sees 401
// when any `manage:` CN arrives (the caller is presenting a cert this
// server cannot validate, which is exactly the behaviour we want).
//
// Trust chain validation is still the TLS stack's job. By the time
// a request reaches this middleware, the chain is already verified;
// we trust whatever leaf came through and only resolve identity.
func MTLSMiddleware(engineStore Store, manageStore manage_enrol.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "client cert required", http.StatusUnauthorized)
				return
			}
			leaf := r.TLS.PeerCertificates[0]
			cn := leaf.Subject.CommonName

			switch {
			case strings.HasPrefix(cn, "engine:"):
				if engineStore == nil {
					http.Error(w, "engine store not configured", http.StatusUnauthorized)
					return
				}
				fp := sha256.Sum256(leaf.Raw)
				fpHex := hex.EncodeToString(fp[:])
				eng, err := engineStore.GetEngineByFingerprint(r.Context(), fpHex)
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

			case strings.HasPrefix(cn, "manage:"):
				if manageStore == nil {
					http.Error(w, "manage enrolment not configured on this server", http.StatusUnauthorized)
					return
				}
				// Serial.Text(16) mirrors what handlers_admin.go records
				// in manage_instances.cert_serial. Both sides must agree
				// on the encoding or the middleware can't resolve the row.
				serial := leaf.SerialNumber.Text(16)
				mi, err := manageStore.GetByCertSerial(r.Context(), serial)
				if err != nil {
					if errors.Is(err, manage_enrol.ErrNotFound) {
						http.Error(w, "unknown manage instance", http.StatusUnauthorized)
						return
					}
					http.Error(w, "manage lookup failed", http.StatusInternalServerError)
					return
				}
				if mi.Status != manage_enrol.StatusActive {
					http.Error(w, "manage instance revoked", http.StatusForbidden)
					return
				}
				ctx := context.WithValue(r.Context(), manageCtxKey{}, &mi)
				next.ServeHTTP(w, r.WithContext(ctx))

			default:
				http.Error(w, "unrecognised CN prefix", http.StatusUnauthorized)
			}
		})
	}
}
