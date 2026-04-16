package agentgw

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// Server is the agent-facing mTLS listener. It runs on a dedicated port
// (default 9443), separate from the portal-facing 8443, and accepts only
// agents whose certs were signed by this engine's key.
type Server struct {
	Addr       string            // default ":9443"
	EngineCert tls.Certificate   // engine's TLS certificate + private key
	EngineX509 *x509.Certificate // parsed engine cert for signature verification
	Handlers   *Handlers
}

// verifyAgentCert checks that leaf was signed by the engine's Ed25519 key.
// We cannot use leaf.CheckSignatureFrom because the engine cert does not
// have BasicConstraints.IsCA set, and Go's x509 library rejects non-CA
// issuers. Instead we verify the raw Ed25519 signature directly.
func verifyAgentCert(leaf, issuer *x509.Certificate) error {
	pub, ok := issuer.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("engine cert has non-Ed25519 key (%T)", issuer.PublicKey)
	}
	if !ed25519.Verify(pub, leaf.RawTBSCertificate, leaf.Signature) {
		return fmt.Errorf("agent cert signature invalid")
	}
	return nil
}

// ListenAndServe starts the mTLS listener and blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.Addr == "" {
		s.Addr = ":9443"
	}

	engineX509 := s.EngineX509

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{s.EngineCert},
		ClientAuth:   tls.RequireAnyClientCert, // we verify manually
		MinVersion:   tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no client certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse client cert: %w", err)
			}
			return verifyAgentCert(leaf, engineX509)
		},
	}

	r := chi.NewRouter()
	r.Use(AgentIdentityMiddleware(s.Handlers.AgentStore))
	s.Handlers.Mount(r)

	srv := &http.Server{
		Addr:         s.Addr,
		Handler:      r,
		TLSConfig:    tlsCfg,
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("agent gateway listening on %s", s.Addr)
	return srv.ListenAndServeTLS("", "") // certs from TLSConfig
}
