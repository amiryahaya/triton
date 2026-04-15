package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"crypto/tls"

	"github.com/go-chi/chi/v5"

	"github.com/amiryahaya/triton/pkg/server"
	credentialspkg "github.com/amiryahaya/triton/pkg/server/credentials"
	discoverypkg "github.com/amiryahaya/triton/pkg/server/discovery"
	enginepkg "github.com/amiryahaya/triton/pkg/server/engine"
)

// loadEngineMasterKey reads TRITON_PORTAL_CA_ENCRYPTION_KEY (hex-encoded,
// 32 bytes). Returns nil when unset — engine admin endpoints will fail at
// CA bootstrap time, but the rest of the portal keeps working. A malformed
// value is a fatal configuration error: silently downgrading would leave
// operators staring at a "bootstrap failed" response with no root-cause
// signal in the logs.
func loadEngineMasterKey() []byte {
	s := os.Getenv("TRITON_PORTAL_CA_ENCRYPTION_KEY")
	if s == "" {
		log.Printf("warning: TRITON_PORTAL_CA_ENCRYPTION_KEY unset — engine creation will fail until set")
		return nil
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		log.Fatalf("TRITON_PORTAL_CA_ENCRYPTION_KEY must be hex-encoded: %v", err)
	}
	if len(key) != 32 {
		log.Fatalf("TRITON_PORTAL_CA_ENCRYPTION_KEY must be 64 hex chars (32 bytes), got %d bytes", len(key))
	}
	return key
}

// enginePortalURL returns the URL the engine binary should dial for
// gateway API calls. Baked into bundle.yaml on issuance.
func enginePortalURL() string {
	if v := os.Getenv("TRITON_PORTAL_URL"); v != "" {
		return v
	}
	return "https://localhost:8443"
}

// engineGatewayAddr returns the listen address for the mTLS gateway.
func engineGatewayAddr() string {
	if v := os.Getenv("TRITON_ENGINE_GATEWAY_ADDR"); v != "" {
		return v
	}
	return ":8443"
}

// ensurePortalTLS returns the cert+key file paths for the mTLS listener.
// Prefers operator-supplied TRITON_PORTAL_TLS_CERT / TRITON_PORTAL_TLS_KEY
// paths; otherwise generates a self-signed cert in a temp directory with
// a loud WARNING so it's unmistakable this isn't production-grade.
func ensurePortalTLS() (certPath, keyPath string, err error) {
	certPath = os.Getenv("TRITON_PORTAL_TLS_CERT")
	keyPath = os.Getenv("TRITON_PORTAL_TLS_KEY")
	if certPath != "" && keyPath != "" {
		return certPath, keyPath, nil
	}

	log.Println("WARNING: generating self-signed portal TLS cert for engine gateway — NOT FOR PRODUCTION")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "triton-portal"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}

	dir, err := os.MkdirTemp("", "triton-portal-tls-")
	if err != nil {
		return "", "", err
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// loadClientCAs builds an x509 pool from every org's engine CA. The mTLS
// listener trusts every org because the cert_fingerprint UNIQUE index on
// the engines table is what actually resolves per-engine identity — the
// CA pool is purely a trust anchor.
func loadClientCAs(ctx context.Context, store enginepkg.Store) (*x509.CertPool, error) {
	pems, err := store.ListAllCAs(ctx)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, p := range pems {
		pool.AppendCertsFromPEM(p)
	}
	return pool, nil
}

// buildEngineTLSConfig assembles a *tls.Config for the mTLS listener
// with a live-refreshing client-CA pool. RequireAnyClientCert is used
// (rather than RequireAndVerifyClientCert) because we verify the chain
// ourselves inside VerifyPeerCertificate against the current pool —
// swapping pools for the built-in verifier requires rebuilding the
// listener, which this pattern avoids.
func buildEngineTLSConfig(ctx context.Context, store enginepkg.Store) (*tls.Config, error) {
	pool, err := loadClientCAs(ctx, store)
	if err != nil {
		return nil, err
	}
	var cur atomic.Pointer[x509.CertPool]
	cur.Store(pool)

	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if p, err := loadClientCAs(ctx, store); err == nil {
					cur.Store(p)
				} else {
					log.Printf("engine gateway: refresh client CAs: %v", err)
				}
			}
		}
	}()

	return &tls.Config{
		ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no client cert")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			opts := x509.VerifyOptions{
				Roots:     cur.Load(),
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			_, err = leaf.Verify(opts)
			return err
		},
	}, nil
}

// startEngineGateway starts a second HTTP server on addr with mTLS
// enforcement and the engine gateway routes mounted. The returned
// *http.Server is handed back so graceful shutdown in cmd/server.go
// can drain it alongside the main portal server.
func startEngineGateway(
	ctx context.Context,
	addr string,
	store enginepkg.Store,
	discoveryStore discoverypkg.Store,
	credStore credentialspkg.Store,
	credInventory credentialspkg.InventoryTargetLookup,
	audit *server.AuditAdapter,
	certPath, keyPath string,
) (*http.Server, error) {
	gwHandlers := &enginepkg.GatewayHandlers{Store: store}
	discoveryGateway := &discoverypkg.GatewayHandlers{Store: discoveryStore}
	credGateway := &credentialspkg.GatewayHandlers{
		Store:          credStore,
		InventoryStore: credInventory,
		Audit:          audit,
		PollTimeout:    30 * time.Second,
		PollInterval:   1 * time.Second,
	}
	r := chi.NewRouter()
	// Stash the request on the context so AuditAdapter can reach
	// RemoteAddr when recording gateway events.
	r.Use(server.StashRequestMiddleware)
	r.Use(enginepkg.MTLSMiddleware(store))
	r.Route("/api/v1/engine", func(sub chi.Router) {
		enginepkg.MountGatewayRoutes(sub, gwHandlers)
		// Onboarding Phase 3 — discovery long-poll + submit, mounted
		// sibling to enroll/heartbeat so engines reach them via the
		// same mTLS-authenticated listener.
		sub.Route("/discoveries", func(dsub chi.Router) {
			discoverypkg.MountGatewayRoutes(dsub, discoveryGateway)
		})
		// Onboarding Phase 4 — credential delivery + test long-poll,
		// mounted alongside discovery on the same mTLS listener.
		sub.Route("/credentials", func(csub chi.Router) {
			credentialspkg.MountGatewayRoutes(csub, credGateway)
		})
	})
	// Back-compat: routes were previously mounted at root (/enroll,
	// /heartbeat). Keep both paths live so any out-of-tree client or
	// test that predates the prefix split still works.
	enginepkg.MountGatewayRoutes(r, gwHandlers)

	tlsCfg, err := buildEngineTLSConfig(ctx, store)
	if err != nil {
		return nil, err
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("engine gateway listening on %s (mTLS required)", addr)
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("engine gateway: %v", err)
		}
	}()
	return srv, nil
}
