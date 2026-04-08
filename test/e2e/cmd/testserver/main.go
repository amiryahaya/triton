// Package main provides a lightweight test server for E2E browser tests.
// It bypasses the CLI licence gate and starts the Triton REST API server
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

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/store"
)

// testOrgID is the org_id stamped onto seed data and used as the
// single-tenant Guard identity for E2E tests. Matches the value used
// by global-setup.js when seeding scans.
const testOrgID = "00000000-0000-0000-0000-000000000abc"

// Seed credentials for the auth-flow E2E tests (auth.spec.js). A fresh
// admin user is created on every testserver startup so the password
// change flow has a clean slate. These values are public test fixtures
// — do NOT reuse outside the E2E harness.
const (
	seedAdminEmail    = "e2e-admin@triton.test"
	seedAdminPassword = "e2e-initial-pw-12345"
	seedAdminName     = "E2E Admin"
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

	// Install a single-tenant Guard so Phase 2's RequireTenant middleware
	// is satisfied without requiring login. The E2E suite tests dashboard
	// rendering, not the auth flow — auth-flow tests should explicitly
	// log in via the login page (Phase 3 test additions).
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating test keypair: %w", err)
	}
	lic := &license.License{
		ID:        "e2e-test-license",
		Tier:      license.TierEnterprise,
		OrgID:     testOrgID,
		Org:       "E2E Test Org",
		Seats:     100,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	}
	token, err := license.Encode(lic, priv)
	if err != nil {
		return fmt.Errorf("encoding test license: %w", err)
	}
	guard := license.NewGuardFromToken(token, pub)

	// Also generate a report-server JWT signing keypair so the auth
	// endpoints (/api/v1/auth/login, change-password, /api/v1/users)
	// are registered. Existing E2E tests never hit these routes; the
	// auth.spec.js suite added in Phase 3+4 review follow-up does.
	jwtPub, jwtPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating JWT keypair: %w", err)
	}

	// Seed the initial org + admin user. The login E2E needs an
	// account to sign in with, and we want the same credentials on
	// every testserver start so the Playwright spec can hard-code
	// them. Password is bcrypt-hashed to match server expectations.
	if err := seedAuthFixtures(ctx, db); err != nil {
		return fmt.Errorf("seeding auth fixtures: %w", err)
	}

	cfg := &server.Config{
		ListenAddr:    listen,
		DBUrl:         dbURL,
		Guard:         guard,
		JWTSigningKey: jwtPriv,
		JWTPublicKey:  jwtPub,
	}
	srv, err := server.New(cfg, db)
	if err != nil {
		return fmt.Errorf("initializing test server: %w", err)
	}

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

// seedAuthFixtures creates testOrgID + a seed admin user with
// must_change_password=true so the auth.spec.js flow can walk through
// login → change-password → users CRUD on every testserver start.
// Safe to call after TruncateAll.
func seedAuthFixtures(ctx context.Context, db *store.PostgresStore) error {
	org := &store.Organization{
		ID:   testOrgID,
		Name: "E2E Test Org",
	}
	if err := db.CreateOrg(ctx, org); err != nil {
		return fmt.Errorf("create org: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(seedAdminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}
	user := &store.User{
		ID:                 uuid.Must(uuid.NewV7()).String(),
		OrgID:              testOrgID,
		Email:              seedAdminEmail,
		Name:               seedAdminName,
		Role:               "org_admin",
		Password:           string(hash),
		MustChangePassword: true, // force change-pw flow on first login
	}
	if err := db.CreateUser(ctx, user); err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}
