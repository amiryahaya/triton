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
	staleThresholdStr := envOr("TRITON_LICENSE_SERVER_STALE_THRESHOLD", "336h")

	if dbURL == "" {
		return fmt.Errorf("TRITON_LICENSE_SERVER_DB_URL is required")
	}
	if tlsCert == "" && tlsKey == "" {
		log.Printf("WARNING: TLS is not configured; the server will accept plain HTTP connections. " +
			"Set TRITON_LICENSE_SERVER_TLS_CERT and TRITON_LICENSE_SERVER_TLS_KEY for production deployments.")
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

	if err := os.MkdirAll(binariesDir, 0o755); err != nil {
		return fmt.Errorf("creating binaries directory: %w", err)
	}

	staleThreshold, err := time.ParseDuration(staleThresholdStr)
	if err != nil {
		return fmt.Errorf("parsing TRITON_LICENSE_SERVER_STALE_THRESHOLD %q (use Go duration format, e.g. 336h for 14 days): %w", staleThresholdStr, err)
	}
	if staleThreshold < 24*time.Hour {
		return fmt.Errorf("TRITON_LICENSE_SERVER_STALE_THRESHOLD must be at least 24h (got %s)", staleThreshold)
	}

	ctx := context.Background()
	store, err := licensestore.NewPostgresStore(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer func() { _ = store.Close() }()

	// Seed an initial superadmin if the users table is empty (idempotent).
	// On a fresh database, TRITON_LICENSE_SERVER_ADMIN_PASSWORD must be set;
	// once seeded, subsequent boots no-op even without the env var.
	bootstrapEmail := envOr("TRITON_LICENSE_SERVER_ADMIN_EMAIL", "admin@localhost")
	bootstrapPassword := envOr("TRITON_LICENSE_SERVER_ADMIN_PASSWORD", "")
	created, err := licenseserver.SeedInitialSuperadmin(ctx, store, bootstrapEmail, bootstrapPassword)
	if err != nil {
		if bootstrapPassword == "" {
			return fmt.Errorf("license server has no users and no bootstrap password set; set TRITON_LICENSE_SERVER_ADMIN_PASSWORD (and optionally TRITON_LICENSE_SERVER_ADMIN_EMAIL) to seed an initial superadmin: %w", err)
		}
		return fmt.Errorf("seeding initial superadmin: %w", err)
	}
	if created {
		log.Printf("seeded initial superadmin: %s", bootstrapEmail)
	}

	// Optional: report server integration (Phase 1.7) and Resend mailer
	// (Phase 1.8). Both are no-ops when their env vars are unset — on-prem
	// single-server deployments can skip them entirely.
	//
	// Env var naming: TRITON_LICENSE_SERVER_REPORT_* prefix for consistency
	// with the rest of this binary's config surface. The report server
	// binary reads its end of the shared key from its own env var name —
	// each side owns its own variable, ops sets both to the same value.
	reportServerURL := envOr("TRITON_LICENSE_SERVER_REPORT_URL", "")
	reportServerKey := envOr("TRITON_LICENSE_SERVER_REPORT_KEY", "")
	// Public URL is the hostname customer agents use to reach
	// the report server. Distinct from REPORT_URL because the
	// latter is typically an internal service-mesh name (e.g.,
	// http://triton:8080) that only resolves inside the deploy
	// network. The public URL is embedded in agent.yaml
	// downloads and invite emails. When unset, handlers fall
	// back to REPORT_URL with a log warning at first use.
	reportServerPublicURL := envOr("TRITON_LICENSE_SERVER_REPORT_PUBLIC_URL", "")
	publicURL := envOr("TRITON_LICENSE_SERVER_PUBLIC_URL", "")
	resendAPIKey := envOr("TRITON_LICENSE_SERVER_RESEND_API_KEY", "")
	resendFromEmail := envOr("TRITON_LICENSE_SERVER_RESEND_FROM_EMAIL", "")
	resendFromName := envOr("TRITON_LICENSE_SERVER_RESEND_FROM_NAME", "Triton License")
	loginURL := envOr("TRITON_LICENSE_SERVER_LOGIN_URL", "")
	reportInviteURL := envOr("REPORT_SERVER_INVITE_URL_BASE", "")

	// Fail loud on partial report server config — either both URL and
	// key are set (enable provisioning) or neither (skip entirely).
	// Silently degrading is worse than warning the operator.
	if (reportServerURL == "") != (reportServerKey == "") {
		log.Printf("WARNING: TRITON_LICENSE_SERVER_REPORT_URL and TRITON_LICENSE_SERVER_REPORT_KEY must both be set to enable report server provisioning; provisioning is DISABLED")
	}

	var mailer licenseserver.Mailer
	switch {
	case resendAPIKey != "" && resendFromEmail != "":
		mailer = licenseserver.NewResendMailer(resendAPIKey, resendFromEmail, resendFromName)
		log.Printf("Resend mailer enabled (from=%s)", resendFromEmail)
	case resendAPIKey != "" || resendFromEmail != "":
		log.Printf("WARNING: TRITON_LICENSE_SERVER_RESEND_API_KEY and TRITON_LICENSE_SERVER_RESEND_FROM_EMAIL must both be set to enable invite emails; email delivery is DISABLED")
	default:
		log.Printf("Resend mailer not configured; invites will return temp password in response body")
	}

	cfg := &licenseserver.Config{
		ListenAddr:               listen,
		DBUrl:                    dbURL,
		TLSCert:                  tlsCert,
		TLSKey:                   tlsKey,
		SigningKey:               privKey,
		PublicKey:                pubKey,
		BinariesDir:              binariesDir,
		ReportServerURL:          reportServerURL,
		ReportServerPublicURL:    reportServerPublicURL,
		ReportServerServiceKey:   reportServerKey,
		PublicURL:                publicURL,
		Mailer:                   mailer,
		ReportServerInviteURL:    reportInviteURL,
		InviteLoginURL:           loginURL,
		StaleActivationThreshold: staleThreshold,
	}

	srv := licenseserver.New(cfg, store)

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
