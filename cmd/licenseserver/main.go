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
	binariesDir := envOr("TRITON_LICENSE_SERVER_BINARIES_DIR", "/opt/triton/binaries")

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

	if err := os.MkdirAll(binariesDir, 0o755); err != nil {
		return fmt.Errorf("creating binaries directory: %w", err)
	}

	adminKeys := strings.Split(adminKey, ",")
	// Filter out empty keys that result from trailing/consecutive commas.
	filtered := adminKeys[:0]
	for _, k := range adminKeys {
		k = strings.TrimSpace(k)
		if k != "" {
			filtered = append(filtered, k)
		}
	}
	adminKeys = filtered
	if len(adminKeys) == 0 {
		return fmt.Errorf("TRITON_LICENSE_SERVER_ADMIN_KEY contains no valid keys after parsing")
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
	resendAPIKey := envOr("RESEND_API_KEY", "")
	resendFromEmail := envOr("RESEND_FROM_EMAIL", "")
	resendFromName := envOr("RESEND_FROM_NAME", "Triton Reports")
	reportInviteURL := envOr("REPORT_SERVER_INVITE_URL_BASE", "")

	// Fail loud on partial report server config — either both URL and
	// key are set (enable provisioning) or neither (skip entirely).
	// Silently degrading is worse than warning the operator.
	if (reportServerURL == "") != (reportServerKey == "") {
		log.Printf("WARNING: TRITON_LICENSE_SERVER_REPORT_URL and TRITON_LICENSE_SERVER_REPORT_KEY must both be set to enable report server provisioning; provisioning is DISABLED")
	}

	var mailer licenseserver.Mailer
	if resendAPIKey != "" && resendFromEmail != "" {
		mailer = licenseserver.NewResendMailer(resendAPIKey, resendFromEmail, resendFromName)
		log.Printf("Resend mailer configured: from=%s", resendFromEmail)
	} else if resendAPIKey != "" || resendFromEmail != "" {
		log.Printf("WARNING: RESEND_API_KEY and RESEND_FROM_EMAIL must both be set to enable invite emails; email delivery is DISABLED")
	}

	cfg := &licenseserver.Config{
		ListenAddr:             listen,
		DBUrl:                  dbURL,
		AdminKeys:              adminKeys,
		TLSCert:                tlsCert,
		TLSKey:                 tlsKey,
		SigningKey:             privKey,
		PublicKey:              pubKey,
		BinariesDir:            binariesDir,
		ReportServerURL:        reportServerURL,
		ReportServerServiceKey: reportServerKey,
		Mailer:                 mailer,
		ReportServerInviteURL:  reportInviteURL,
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
