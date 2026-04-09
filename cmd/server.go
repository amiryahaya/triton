package cmd

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/auth"
	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/internal/mailer"
	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/store"
)

var (
	serverListen  string
	serverDB      string
	serverTLSCert string
	serverTLSKey  string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the Triton report server (REST API + web UI)",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return guard.EnforceFeature(license.FeatureServerMode)
	},
	RunE: runServer,
}

func init() {
	serverCmd.Flags().StringVar(&serverListen, "listen", ":8080", "Listen address")
	serverCmd.Flags().StringVar(&serverDB, "db", "", "PostgreSQL connection URL (default: postgres://triton:triton@localhost:5434/triton?sslmode=disable)")
	serverCmd.Flags().StringVar(&serverTLSCert, "tls-cert", "", "TLS certificate file")
	serverCmd.Flags().StringVar(&serverTLSKey, "tls-key", "", "TLS key file")
	rootCmd.AddCommand(serverCmd)
}

func runServer(_ *cobra.Command, _ []string) error {
	dbUrlVal := serverDB
	if dbUrlVal == "" {
		dbUrlVal = config.DefaultDBUrl()
	}

	ctx := context.Background()
	db, err := store.NewPostgresStore(ctx, dbUrlVal)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	cfg := &server.Config{
		ListenAddr:           serverListen,
		DBUrl:                dbUrlVal,
		TLSCert:              serverTLSCert,
		TLSKey:               serverTLSKey,
		Guard:                guard,
		DataEncryptionKeyHex: os.Getenv("REPORT_SERVER_DATA_ENCRYPTION_KEY"),
		InviteLoginURL:       os.Getenv("REPORT_SERVER_INVITE_URL"),
		// Phase 5 Sprint 3 A2 — cross-server service key for
		// license-server → report-server provisioning. When empty,
		// the /api/v1/admin/* route group is NOT registered (see
		// pkg/server/server.go), which is the correct behavior for
		// single-tenant deployments. Multi-tenant deployments MUST
		// set this to the same value as the license server's
		// TRITON_LICENSE_SERVER_REPORT_SERVICE_KEY.
		ServiceKey: os.Getenv("REPORT_SERVER_SERVICE_KEY"),
	}

	// Phase 5 Sprint 3 A2 — JWT signing key for org-user login. When
	// unset, the /api/v1/auth/* and /api/v1/users routes are NOT
	// registered and the server runs in "agents only" mode. This is
	// acceptable for deployments where humans use the license server
	// admin UI exclusively; multi-tenant deployments with human org
	// users MUST set this to a hex-encoded Ed25519 private key.
	if jwtHex := os.Getenv("REPORT_SERVER_JWT_SIGNING_KEY"); jwtHex != "" {
		priv, err := decodeEd25519PrivateKey(jwtHex)
		if err != nil {
			return fmt.Errorf("REPORT_SERVER_JWT_SIGNING_KEY: %w", err)
		}
		cfg.JWTSigningKey = priv
		cfg.JWTPublicKey = priv.Public().(ed25519.PublicKey)
		log.Printf("JWT signing configured; /api/v1/auth and /api/v1/users endpoints enabled")
	}

	// Phase 5 Sprint 3 A2 — optional tenant public key override for
	// license-token verification. Multi-tenant deployments that want
	// a different signing key from the build-time embedded default
	// set this to a hex-encoded Ed25519 public key. When unset the
	// embedded default (loaded via license.LoadPublicKeyBytes) is
	// used.
	if pubHex := os.Getenv("REPORT_SERVER_TENANT_PUBKEY"); pubHex != "" {
		pubBytes, err := hex.DecodeString(pubHex)
		if err != nil {
			return fmt.Errorf("REPORT_SERVER_TENANT_PUBKEY: %w", err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return fmt.Errorf("REPORT_SERVER_TENANT_PUBKEY: expected %d bytes, got %d",
				ed25519.PublicKeySize, len(pubBytes))
		}
		cfg.TenantPubKey = pubBytes
		log.Printf("tenant public key loaded from REPORT_SERVER_TENANT_PUBKEY")
	}

	// Phase 5 Sprint 3 A2 — optional login rate-limiter tuning.
	// When any of the three REPORT_SERVER_LOGIN_RATE_LIMIT_* env
	// vars is set, we construct a custom LoginRateLimiterConfig.
	// Missing values fall back to DefaultLoginRateLimiterConfig
	// (5 attempts / 15min window / 15min lockout).
	if rlCfg := parseLoginRateLimitEnv(); rlCfg != nil {
		cfg.LoginRateLimiterConfig = rlCfg
		log.Printf("login rate limiter tuned: maxAttempts=%d window=%s lockout=%s",
			rlCfg.MaxAttempts, rlCfg.Window, rlCfg.LockoutDuration)
	}

	// Phase 5 Sprint 3 B3 — optional per-tenant request rate
	// limiter tuning via REPORT_SERVER_REQUEST_RATE_LIMIT_* vars.
	// Default is 600 req/min per tenant. Sprint 3 full-review N1
	// flagged that the earlier commit had no env wiring for this
	// limiter at all.
	if rlCfg := parseRequestRateLimitEnv(); rlCfg != nil {
		cfg.RequestRateLimiterConfig = rlCfg
		log.Printf("request rate limiter tuned: maxRequests=%d window=%s",
			rlCfg.MaxRequests, rlCfg.Window)
	}

	// Sprint 4 Arch #4 — JWT session cache. Enabled by default at
	// 10,000 entries / 60 s TTL whenever JWT auth is configured,
	// because without it the per-request DB round-trip caps p99 at
	// around 500 req/s and the plan explicitly flags shipping
	// without this cache as unacceptable for multi-tenant
	// production. Operators can tune or disable via
	// REPORT_SERVER_SESSION_CACHE_SIZE (0 disables) and
	// REPORT_SERVER_SESSION_CACHE_TTL (Go duration).
	if cfg.JWTSigningKey != nil {
		cfg.SessionCacheSize = 10000
		cfg.SessionCacheTTL = 60 * time.Second
		sizeExplicit := false
		if raw := os.Getenv("REPORT_SERVER_SESSION_CACHE_SIZE"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 {
				log.Printf("REPORT_SERVER_SESSION_CACHE_SIZE=%q is not a non-negative integer, ignoring", raw)
			} else {
				cfg.SessionCacheSize = n
				sizeExplicit = true
			}
		}
		if raw := os.Getenv("REPORT_SERVER_SESSION_CACHE_TTL"); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil || d <= 0 {
				log.Printf("REPORT_SERVER_SESSION_CACHE_TTL=%q is not a positive duration, ignoring", raw)
			} else {
				cfg.SessionCacheTTL = d
			}
		}
		switch {
		case cfg.SessionCacheSize == 0 && sizeExplicit:
			log.Printf("JWT session cache disabled by operator (REPORT_SERVER_SESSION_CACHE_SIZE=0); multi-tenant p99 will be DB-bound")
		case cfg.SessionCacheSize == 0:
			log.Printf("WARNING: JWT session cache is disabled — multi-tenant p99 is DB-bound; expect <500 req/s sustained")
		default:
			log.Printf("JWT session cache enabled: size=%d ttl=%s", cfg.SessionCacheSize, cfg.SessionCacheTTL)
		}
	}

	// Phase 5 Sprint 2 D3 — optional Resend mailer wiring for the
	// resend-invite flow. When all three REPORT_SERVER_RESEND_*
	// env vars are set, we build a mailer so handleResendInvite
	// pushes the temp password via email instead of returning it
	// in the JSON response body. Missing any variable silently
	// falls back to the body-return path with Cache-Control:
	// no-store — see handleResendInvite for the fallback logic.
	if apiKey := os.Getenv("REPORT_SERVER_RESEND_API_KEY"); apiKey != "" {
		fromEmail := os.Getenv("REPORT_SERVER_RESEND_FROM_EMAIL")
		fromName := os.Getenv("REPORT_SERVER_RESEND_FROM_NAME")
		if m := mailer.NewResendMailer(apiKey, fromEmail, fromName); m != nil {
			cfg.Mailer = m
			log.Printf("resend mailer enabled for resend-invite delivery (from=%s)", fromEmail)
		} else {
			log.Printf("REPORT_SERVER_RESEND_API_KEY set but REPORT_SERVER_RESEND_FROM_EMAIL is empty; mailer NOT enabled")
		}
	}

	srv, err := server.New(cfg, db)
	if err != nil {
		return fmt.Errorf("initializing server: %w", err)
	}

	// Graceful shutdown.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		fmt.Printf("\nReceived %v, shutting down...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

// decodeEd25519PrivateKey parses a hex-encoded Ed25519 private key.
// Accepts either the 32-byte seed form or the full 64-byte key form
// produced by ed25519.GenerateKey, because operators encoding keys
// with different tooling may get different representations.
func decodeEd25519PrivateKey(hexStr string) (ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("expected %d or %d bytes, got %d",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}
}

// parseLoginRateLimitEnv reads REPORT_SERVER_LOGIN_RATE_LIMIT_* env
// vars and returns a LoginRateLimiterConfig pointer if ANY of the
// three recognized vars is set. Returns nil (= use
// DefaultLoginRateLimiterConfig) when none of the vars is present.
//
// Invalid values (non-integer attempts, unparseable duration) are
// silently ignored and fall back to the default. This matches the
// pattern for other optional env vars in this file.
//
// For backward compatibility with the earlier REPORT_SERVER_RATE_LIMIT_*
// names (Sprint 3 Round 1), those legacy vars are still honored
// but log a deprecation warning. The Sprint 3 full-review N1 flagged
// the earlier naming as ambiguous between login and request limiters.
func parseLoginRateLimitEnv() *auth.LoginRateLimiterConfig {
	attemptsRaw := envOrLegacy("REPORT_SERVER_LOGIN_RATE_LIMIT_MAX_ATTEMPTS", "REPORT_SERVER_RATE_LIMIT_MAX_ATTEMPTS")
	windowRaw := envOrLegacy("REPORT_SERVER_LOGIN_RATE_LIMIT_WINDOW", "REPORT_SERVER_RATE_LIMIT_WINDOW")
	lockoutRaw := envOrLegacy("REPORT_SERVER_LOGIN_RATE_LIMIT_LOCKOUT", "REPORT_SERVER_RATE_LIMIT_LOCKOUT")
	if attemptsRaw == "" && windowRaw == "" && lockoutRaw == "" {
		return nil
	}
	cfg := auth.DefaultLoginRateLimiterConfig
	if attemptsRaw != "" {
		if n, err := strconv.Atoi(attemptsRaw); err == nil && n > 0 {
			cfg.MaxAttempts = n
		} else {
			log.Printf("REPORT_SERVER_LOGIN_RATE_LIMIT_MAX_ATTEMPTS=%q is not a positive integer, ignoring", attemptsRaw)
		}
	}
	if windowRaw != "" {
		if d, err := time.ParseDuration(windowRaw); err == nil && d > 0 {
			cfg.Window = d
		} else {
			log.Printf("REPORT_SERVER_LOGIN_RATE_LIMIT_WINDOW=%q is not a valid duration, ignoring", windowRaw)
		}
	}
	if lockoutRaw != "" {
		if d, err := time.ParseDuration(lockoutRaw); err == nil && d > 0 {
			cfg.LockoutDuration = d
		} else {
			log.Printf("REPORT_SERVER_LOGIN_RATE_LIMIT_LOCKOUT=%q is not a valid duration, ignoring", lockoutRaw)
		}
	}
	return &cfg
}

// parseRequestRateLimitEnv reads REPORT_SERVER_REQUEST_RATE_LIMIT_*
// env vars and returns a RequestRateLimiterConfig pointer if any
// are set. Default is 600 requests per minute per tenant.
func parseRequestRateLimitEnv() *auth.RequestRateLimiterConfig {
	maxRaw := os.Getenv("REPORT_SERVER_REQUEST_RATE_LIMIT_MAX_REQUESTS")
	windowRaw := os.Getenv("REPORT_SERVER_REQUEST_RATE_LIMIT_WINDOW")
	if maxRaw == "" && windowRaw == "" {
		return nil
	}
	cfg := auth.DefaultRequestRateLimiterConfig
	if maxRaw != "" {
		if n, err := strconv.Atoi(maxRaw); err == nil && n > 0 {
			cfg.MaxRequests = n
		} else {
			log.Printf("REPORT_SERVER_REQUEST_RATE_LIMIT_MAX_REQUESTS=%q is not a positive integer, ignoring", maxRaw)
		}
	}
	if windowRaw != "" {
		if d, err := time.ParseDuration(windowRaw); err == nil && d > 0 {
			cfg.Window = d
		} else {
			log.Printf("REPORT_SERVER_REQUEST_RATE_LIMIT_WINDOW=%q is not a valid duration, ignoring", windowRaw)
		}
	}
	return &cfg
}

// envOrLegacy returns the value of the canonical env var when set,
// or the legacy env var's value with a deprecation warning when the
// legacy one is still in use. Empty means neither was set.
func envOrLegacy(canonical, legacy string) string {
	if v := os.Getenv(canonical); v != "" {
		return v
	}
	if v := os.Getenv(legacy); v != "" {
		log.Printf("WARN: %s is deprecated; rename to %s", legacy, canonical)
		return v
	}
	return ""
}
