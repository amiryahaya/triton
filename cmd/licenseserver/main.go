package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
	adminKey := envOr("TRITON_LICENSE_SERVER_ADMIN_KEY", "")
	signingKeyHex := envOr("TRITON_LICENSE_SERVER_SIGNING_KEY", "")
	tlsCert := envOr("TRITON_LICENSE_SERVER_TLS_CERT", "")
	tlsKey := envOr("TRITON_LICENSE_SERVER_TLS_KEY", "")

	if dbURL == "" {
		return fmt.Errorf("TRITON_LICENSE_SERVER_DB_URL is required")
	}
	if adminKey == "" {
		return fmt.Errorf("TRITON_LICENSE_SERVER_ADMIN_KEY is required (protects admin API)")
	}
	if signingKeyHex == "" {
		return fmt.Errorf("TRITON_LICENSE_SERVER_SIGNING_KEY is required (Ed25519 private key as hex)")
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

	var adminKeys []string
	if adminKey != "" {
		adminKeys = strings.Split(adminKey, ",")
	}

	ctx := context.Background()
	store, err := licensestore.NewPostgresStore(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer store.Close()

	cfg := &licenseserver.Config{
		ListenAddr: listen,
		DBUrl:      dbURL,
		AdminKeys:  adminKeys,
		TLSCert:    tlsCert,
		TLSKey:     tlsKey,
		SigningKey:  privKey,
		PublicKey:   pubKey,
	}

	srv := licenseserver.New(cfg, store)

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}()

	return srv.Start()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
