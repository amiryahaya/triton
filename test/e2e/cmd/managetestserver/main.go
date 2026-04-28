// Package main provides a lightweight test server for manage-portal E2E tests.
// It starts the Manage Server backed by a real PostgreSQL database and seeds
// fixed test fixtures so Playwright specs have deterministic data to interact with.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/manageserver/discovery"
	"github.com/amiryahaya/triton/pkg/managestore"
)

const (
	// Stable instance UUID stamped by SaveLicenseActivation and used as the
	// tenant ID for discovery jobs.
	testInstanceID = "00000000-0000-0000-0000-000000000001"

	seedAdminEmail    = "e2e-manage@triton.test"
	seedAdminPassword = "Manage123!"

	// testJWTKey is a 32-byte HS256 secret used only by the E2E harness.
	testJWTKey = "e2e-manage-jwt-signing-key-xxxxx"
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

	listen := os.Getenv("TRITON_MANAGE_TEST_LISTEN")
	if listen == "" {
		listen = ":8082"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect pool: %w", err)
	}
	defer pool.Close()

	// Wipe manage tables so count-based assertions are deterministic.
	if err := truncateManageTables(ctx, pool); err != nil {
		return fmt.Errorf("truncate: %w", err)
	}

	// Run schema migrations.
	if err := managestore.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	store := managestore.NewPostgresStoreFromPool(pool)

	// Mark setup complete so RequireOperational passes.
	if err := store.MarkAdminCreated(ctx); err != nil {
		return fmt.Errorf("mark admin created: %w", err)
	}
	if err := store.SaveLicenseActivation(ctx,
		"https://ls.example.com", "e2e-key", "e2e-tok", testInstanceID,
	); err != nil {
		return fmt.Errorf("save license activation: %w", err)
	}

	// Seed admin user for login.
	if err := seedAdmin(ctx, store); err != nil {
		return fmt.Errorf("seed admin: %w", err)
	}

	// Seed a completed discovery job with two candidates so the Discovery
	// E2E tests can import without running a real network scan.
	discStore := discovery.NewPostgresStore(pool)
	if err := seedDiscovery(ctx, discStore); err != nil {
		return fmt.Errorf("seed discovery: %w", err)
	}

	cfg := &manageserver.Config{
		Listen:               listen,
		GatewayListen:        ":0", // random port — E2E doesn't test mTLS
		JWTSigningKey:        []byte(testJWTKey),
		SessionTTL:           8 * time.Hour,
		GatewayRetryInterval: 100 * time.Millisecond,
	}
	srv, err := manageserver.New(cfg, store, pool)
	if err != nil {
		return fmt.Errorf("new server: %w", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	case sig := <-sigCh:
		fmt.Printf("\nReceived %v, shutting down...\n", sig)
		cancel()
		// Give server up to 10 s to finish in-flight requests.
		select {
		case err := <-errCh:
			return err
		case <-time.After(10 * time.Second):
			return nil
		}
	}
}

func truncateManageTables(ctx context.Context, pool *pgxpool.Pool) error {
	tables := []string{
		"manage_discovery_candidates",
		"manage_discovery_jobs",
		"manage_host_tags",
		"manage_hosts",
		"manage_credentials",
		"manage_scan_jobs",
		"manage_agents",
		"manage_tags",
		"manage_sessions",
		"manage_users",
		"manage_config",
	}
	for _, t := range tables {
		if _, err := pool.Exec(ctx, "TRUNCATE "+t+" CASCADE"); err != nil {
			// Table may not exist before first Migrate run — ignore.
			continue
		}
	}
	return nil
}

func seedAdmin(ctx context.Context, store *managestore.PostgresStore) error {
	hash, err := manageserver.HashPassword(seedAdminPassword)
	if err != nil {
		return err
	}
	u := &managestore.ManageUser{
		Email:        seedAdminEmail,
		Name:         "E2E Admin",
		Role:         "admin",
		PasswordHash: hash,
		MustChangePW: false,
	}
	return store.CreateUser(ctx, u)
}

func seedDiscovery(ctx context.Context, ds *discovery.PostgresStore) error {
	tenantID := uuid.MustParse(testInstanceID)

	// Create a completed job.
	job, err := ds.CreateJob(ctx, discovery.EnqueueReq{
		CIDR:     "10.99.0.0/30",
		Ports:    []int{22, 80, 443},
		TotalIPs: 2,
	}, tenantID)
	if err != nil {
		return fmt.Errorf("create discovery job: %w", err)
	}

	now := time.Now()
	if err := ds.UpdateStatus(ctx, discovery.StatusUpdate{
		JobID:      job.ID,
		Status:     "completed",
		StartedAt:  &now,
		FinishedAt: &now,
	}); err != nil {
		return fmt.Errorf("update discovery status: %w", err)
	}

	hostname1 := "e2e-host-01"
	// Candidate 1: new host (not yet in inventory).
	if err := ds.InsertCandidate(ctx, discovery.Candidate{
		JobID:     job.ID,
		IP:        "10.99.0.1",
		Hostname:  &hostname1,
		OpenPorts: []int{22, 443},
		OS:        "linux",
	}); err != nil {
		return fmt.Errorf("insert candidate 1: %w", err)
	}

	// Candidate 2: no hostname — tests the inline-hostname-edit path.
	if err := ds.InsertCandidate(ctx, discovery.Candidate{
		JobID:     job.ID,
		IP:        "10.99.0.2",
		OpenPorts: []int{80},
	}); err != nil {
		return fmt.Errorf("insert candidate 2: %w", err)
	}

	return nil
}
