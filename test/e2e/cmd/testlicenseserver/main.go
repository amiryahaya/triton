// Package main provides a lightweight test license server for E2E browser tests.
// It generates an ephemeral Ed25519 keypair and starts the license server
// directly, backed by a real PostgreSQL database.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amiryahaya/triton/pkg/licenseserver"
	"github.com/amiryahaya/triton/pkg/licensestore"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run() error {
	dbURL := os.Getenv("TRITON_TEST_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://triton:triton@localhost:5434/triton_test?sslmode=disable"
	}

	listen := os.Getenv("TRITON_LICENSE_TEST_LISTEN")
	if listen == "" {
		listen = ":8081"
	}

	ctx := context.Background()
	store, err := licensestore.NewPostgresStore(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.TruncateAll(ctx); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}

	binDir, err := os.MkdirTemp("", "triton-e2e-binaries-*")
	if err != nil {
		return fmt.Errorf("create temp binaries dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(binDir) }()

	cfg := &licenseserver.Config{
		ListenAddr:  listen,
		SigningKey:  priv,
		PublicKey:   pub,
		BinariesDir: binDir,
	}
	srv := licenseserver.New(cfg, store)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	case sig := <-sigCh:
		fmt.Printf("\nReceived %v, shutting down...\n", sig)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
