// Package main provides a lightweight test server for manage-portal E2E tests.
// It starts the Manage Server backed by a real PostgreSQL database and seeds
// fixed test fixtures so Playwright specs have deterministic data to interact with.
//
// A Vault dev container (hashicorp/vault) is started automatically via podman
// so that credentials E2E tests hit a real Vault KV v2 instance. The container
// is stopped on shutdown. The root token is always "dev-root-token".
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
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

	// Vault dev server constants — stable across test runs.
	vaultContainerName = "triton-vault-e2e"
	vaultAddr          = "http://127.0.0.1:8210" // port 8210 avoids conflict with prod :8200
	vaultRootToken     = "dev-root-token"
	vaultMount         = "secret"
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
		dbURL = "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
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

	// Run schema migrations first.
	if err := managestore.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// Only truncate when MANAGE_E2E_RESET=1 (set by Playwright test runner).
	// Manual "go run" sessions skip truncation so data persists across restarts.
	if os.Getenv("MANAGE_E2E_RESET") == "1" {
		truncateManageTables(ctx, pool)
	}

	store := managestore.NewPostgresStoreFromPool(pool)

	// These seed operations are idempotent: MarkAdminCreated is a no-op when
	// already set; SaveLicenseActivation upserts; seedAdmin/seedDiscovery skip
	// when data already exists.
	if err := store.MarkAdminCreated(ctx); err != nil {
		return fmt.Errorf("mark admin created: %w", err)
	}
	if err := store.SaveLicenseActivation(ctx,
		"https://ls.example.com", "e2e-key", "e2e-tok", testInstanceID,
	); err != nil {
		return fmt.Errorf("save license activation: %w", err)
	}
	if err := seedAdmin(ctx, store); err != nil {
		return fmt.Errorf("seed admin: %w", err)
	}
	discStore := discovery.NewPostgresStore(pool)
	if err := seedDiscovery(ctx, pool, discStore); err != nil {
		return fmt.Errorf("seed discovery: %w", err)
	}

	// Start Vault dev container for credentials tests.
	if err := startVaultDev(ctx); err != nil {
		return fmt.Errorf("start vault dev: %w", err)
	}
	defer stopVaultDev()

	cfg := &manageserver.Config{
		Listen:               listen,
		GatewayListen:        ":0", // random port — E2E doesn't test mTLS
		JWTSigningKey:        []byte(testJWTKey),
		SessionTTL:           8 * time.Hour,
		GatewayRetryInterval: 100 * time.Millisecond,
		VaultAddr:            vaultAddr,
		VaultMount:           vaultMount,
		VaultToken:           vaultRootToken,
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

func truncateManageTables(ctx context.Context, pool *pgxpool.Pool) {
	tables := []string{
		"manage_discovery_candidates",
		"manage_discovery_jobs",
		"manage_host_tags",
		"manage_enrolled_agents",
		"manage_enrollment_tokens",
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
		// Table may not exist before first Migrate run — ignore errors.
		_, _ = pool.Exec(ctx, "TRUNCATE "+t+" CASCADE")
	}
}

func seedAdmin(ctx context.Context, store *managestore.PostgresStore) error {
	// Skip if the admin user already exists.
	if _, err := store.GetUserByEmail(ctx, seedAdminEmail); err == nil {
		return nil
	}
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

// startVaultDev pulls and starts a Vault dev container via podman, waits until
// the HTTP API is reachable, then enables the KV v2 mount at vaultMount.
// It is idempotent: if the container already exists it is removed first.
func startVaultDev(ctx context.Context) error {
	// Remove any leftover container from a previous run.
	_ = exec.CommandContext(ctx, "podman", "rm", "-f", vaultContainerName).Run()

	cmd := exec.CommandContext(ctx, "podman", "run", "--rm", "-d",
		"--name", vaultContainerName,
		"-p", "8210:8200",
		"-e", "VAULT_DEV_ROOT_TOKEN_ID="+vaultRootToken,
		"-e", "VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		"--cap-add=IPC_LOCK",
		"hashicorp/vault:latest",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("podman run vault: %w\n%s", err, out)
	}

	// Poll until Vault API responds (up to 30 s).
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(vaultAddr + "/v1/sys/health")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode < 500 {
				break
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}

	// Enable KV v2 at the configured mount path.
	return vaultEnableKV(ctx, client)
}

// vaultEnableKV enables the KV v2 secrets engine at vaultMount. Safe to call
// when the mount already exists (409 is treated as success).
func vaultEnableKV(ctx context.Context, client *http.Client) error {
	body, _ := json.Marshal(map[string]string{"type": "kv", "options": `{"version":"2"}`})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		vaultAddr+"/v1/sys/mounts/"+vaultMount,
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", vaultRootToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("vault enable kv: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is not actionable
	// 200 = newly enabled, 400 = already exists — both are fine.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK &&
		resp.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("vault enable kv: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// stopVaultDev removes the Vault dev container.
func stopVaultDev() {
	_ = exec.Command("podman", "rm", "-f", vaultContainerName).Run()
}

func seedDiscovery(ctx context.Context, pool *pgxpool.Pool, ds *discovery.PostgresStore) error {
	// Skip if any discovery job already exists for this tenant.
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM manage_discovery_jobs WHERE tenant_id = $1`,
		testInstanceID,
	).Scan(&n); err != nil || n > 0 {
		return nil
	}

	tenantID := uuid.MustParse(testInstanceID)
	job, err := ds.CreateJob(ctx, discovery.EnqueueReq{
		CIDR:     "10.99.0.0/30",
		SSHPort:  22,
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
	if err := ds.InsertCandidate(ctx, discovery.Candidate{
		JobID:    job.ID,
		IP:       "10.99.0.1",
		Hostname: &hostname1,
	}); err != nil {
		return fmt.Errorf("insert candidate 1: %w", err)
	}
	if err := ds.InsertCandidate(ctx, discovery.Candidate{
		JobID: job.ID,
		IP:    "10.99.0.2",
	}); err != nil {
		return fmt.Errorf("insert candidate 2: %w", err)
	}
	return nil
}
