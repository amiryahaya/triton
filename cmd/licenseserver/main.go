package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amiryahaya/triton/pkg/auth"
	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("license server error: %v", err)
	}
}

func run() error {
	listen := envOr("TRITON_LICENSE_SERVER_LISTEN", ":8081")
	dbURL := envOr("TRITON_LICENSE_SERVER_DB_URL", "")
	signingKeyHex := envOr("TRITON_LICENSE_SERVER_SIGNING_KEY", "")
	tlsCert := envOr("TRITON_LICENSE_SERVER_TLS_CERT", "")
	tlsKey := envOr("TRITON_LICENSE_SERVER_TLS_KEY", "")
	binariesDir := envOr("TRITON_LICENSE_SERVER_BINARIES_DIR", "/opt/triton/binaries")
	keycloakIssuer := envOr("TRITON_LICENSE_SERVER_KEYCLOAK_ISSUER", "")
	keycloakClientID := envOr("TRITON_LICENSE_SERVER_KEYCLOAK_CLIENT_ID", "triton")

	if dbURL == "" {
		return fmt.Errorf("TRITON_LICENSE_SERVER_DB_URL is required")
	}
	if signingKeyHex == "" {
		return fmt.Errorf("TRITON_LICENSE_SERVER_SIGNING_KEY is required (Ed25519 private key as hex)")
	}
	if keycloakIssuer == "" {
		return fmt.Errorf("TRITON_LICENSE_SERVER_KEYCLOAK_ISSUER is required")
	}

	signingKeyBytes, err := hex.DecodeString(signingKeyHex)
	if err != nil {
		return fmt.Errorf("decoding signing key: %w", err)
	}
	if len(signingKeyBytes) != ed25519.PrivateKeySize {
		return fmt.Errorf("signing key must be %d bytes (got %d)", ed25519.PrivateKeySize, len(signingKeyBytes))
	}
	privKey := ed25519.PrivateKey(signingKeyBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	if err := os.MkdirAll(binariesDir, 0o755); err != nil {
		return fmt.Errorf("creating binaries directory: %w", err)
	}

	ctx := context.Background()

	verifier, err := auth.NewVerifier(ctx, auth.OIDCConfig{
		IssuerURL: keycloakIssuer,
		ClientID:  keycloakClientID,
	})
	if err != nil {
		return fmt.Errorf("creating OIDC verifier: %w", err)
	}
	store, err := licensestore.NewPostgresStore(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer func() { _ = store.Close() }()

	cfg := &licenseserver.Config{
		ListenAddr:  listen,
		DBUrl:       dbURL,
		TLSCert:     tlsCert,
		TLSKey:      tlsKey,
		SigningKey:  privKey,
		PublicKey:   pubKey,
		BinariesDir: binariesDir,
	}

	srv := licenseserver.New(cfg, store, verifier)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Println("shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
		return nil
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
