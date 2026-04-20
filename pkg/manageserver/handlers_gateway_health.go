package manageserver

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"github.com/amiryahaya/triton/pkg/manageserver/ca"
)

// GatewayHealthResponse is the JSON body of GET /api/v1/admin/gateway-health.
type GatewayHealthResponse struct {
	CABootstrapped    bool       `json:"ca_bootstrapped"`
	ListenerState     string     `json:"listener_state"`
	CertExpiresAt     *time.Time `json:"cert_expires_at"`
	CertDaysRemaining int        `json:"cert_days_remaining"`
}

var listenerStateNames = map[int32]string{
	gatewayStatePendingSetup: "pending_setup",
	gatewayStateRetryLoop:    "retry_loop",
	gatewayStateUp:           "up",
	gatewayStateFailed:       "failed",
}

// handleGatewayHealth reports gateway listener + CA + cert state.
// Always returns 200 with best-effort data; a DB error on the CA-load
// path returns ca_bootstrapped=false. This endpoint must never panic
// or block even when the gateway is in a bad state.
//
// GET /api/v1/admin/gateway-health
func (s *Server) handleGatewayHealth(w http.ResponseWriter, r *http.Request) {
	state := s.gatewayState.Load()
	resp := GatewayHealthResponse{
		ListenerState: listenerStateNames[state],
	}

	if s.caStore != nil {
		if _, err := s.caStore.Load(r.Context()); err == nil {
			resp.CABootstrapped = true
		} else if !errors.Is(err, ca.ErrNotFound) {
			// Transient DB error — treat as not-bootstrapped for safety,
			// but let the listener_state field reflect the actual state.
			resp.CABootstrapped = false
		}
	}

	if state == gatewayStateUp {
		if leafAny := s.serverLeaf.Load(); leafAny != nil {
			if leaf, ok := leafAny.(tls.Certificate); ok && len(leaf.Certificate) > 0 {
				if cert, err := x509.ParseCertificate(leaf.Certificate[0]); err == nil {
					expiresAt := cert.NotAfter
					resp.CertExpiresAt = &expiresAt
					resp.CertDaysRemaining = int(time.Until(expiresAt) / (24 * time.Hour))
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
