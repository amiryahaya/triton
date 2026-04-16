// Package agentgw provides the engine-side mTLS listener for triton-agent
// daemons. Agents present per-host certs minted by the engine; the
// gateway verifies them via custom VerifyPeerCertificate (raw Ed25519
// signature check, not full X.509 chain validation — engine cert lacks IsCA).
package agentgw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

type agentCtxKey struct{}

// AgentIdentity represents an authenticated agent extracted from the mTLS
// client certificate. HostID is empty for agents that haven't registered yet.
type AgentIdentity struct {
	HostID          string
	CertFingerprint string
}

// AgentFromContext returns the agent identity from the request context,
// or nil if no agent identity is present.
func AgentFromContext(ctx context.Context) *AgentIdentity {
	a, _ := ctx.Value(agentCtxKey{}).(*AgentIdentity)
	return a
}

// AgentLookup resolves a cert fingerprint to a known agent identity.
type AgentLookup interface {
	LookupAgentByFingerprint(fingerprint string) (*AgentIdentity, bool)
}

// AgentIdentityMiddleware extracts the agent's cert fingerprint from the
// mTLS connection and looks up the agent identity. Agents that aren't
// registered yet (freshly pushed, calling /register for the first time)
// are allowed through with a fingerprint-only identity.
func AgentIdentityMiddleware(lookup AgentLookup) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "client cert required", http.StatusUnauthorized)
				return
			}
			leaf := r.TLS.PeerCertificates[0]
			fp := sha256.Sum256(leaf.Raw)
			fpHex := hex.EncodeToString(fp[:])

			identity := &AgentIdentity{CertFingerprint: fpHex}
			if lookup != nil {
				if known, ok := lookup.LookupAgentByFingerprint(fpHex); ok {
					identity = known
				}
			}
			// For /register, unknown fingerprints are expected — the agent
			// is registering for the first time. Other endpoints check
			// identity.HostID != "" in the handler.

			ctx := context.WithValue(r.Context(), agentCtxKey{}, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
