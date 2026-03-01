// Package main provides a lightweight test server for E2E browser tests.
// It bypasses the CLI licence gate and starts the Triton REST API server
// directly, backed by a real PostgreSQL database.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/store"
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

	listen := os.Getenv("TRITON_TEST_LISTEN")
	if listen == "" {
		listen = ":8080"
	}

	ctx := context.Background()
	db, err := store.NewPostgresStore(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Truncate stale data so E2E count-based assertions are deterministic.
	// The global-setup will re-seed immediately after the health check passes.
	if err := db.TruncateAll(ctx); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}

	cfg := &server.Config{
		ListenAddr: listen,
		DBUrl:      dbURL,
	}
	srv := server.New(cfg, db)

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
