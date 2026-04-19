// Command manageserver runs the Manage Portal backend — the on-prem,
// multi-tenant-naive admin server that activates against the Triton License
// Server and authenticates operators with self-managed JWT + bcrypt.
//
// Configuration is env-var driven; see the env table in the package README
// or the B1 design plan. Required vars at startup:
//
//   - TRITON_MANAGE_DB_URL
//   - TRITON_MANAGE_JWT_SIGNING_KEY          (hex; min 32 bytes after decode)
//   - TRITON_MANAGE_LICENSE_SERVER_PUBKEY    (hex; 32-byte Ed25519 pub key)
//
// Optional:
//
//   - TRITON_MANAGE_LISTEN        (default ":8082")
//   - TRITON_MANAGE_SESSION_TTL   (default "24h")
//
// Reserved (unused in B1; kept in the contract for B2):
//
//   - TRITON_MANAGE_INSTANCE_ID
//   - TRITON_MANAGE_LICENSE_SERVER
//   - TRITON_MANAGE_LICENSE_KEY
//   - TRITON_MANAGE_REPORT_SERVER
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

	"github.com/amiryahaya/triton/pkg/manageserver"
	"github.com/amiryahaya/triton/pkg/managestore"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("manage server error: %v", err)
	}
}

func run() error {
	listen := envOr("TRITON_MANAGE_LISTEN", ":8082")
	dbURL := envOr("TRITON_MANAGE_DB_URL", "")
	jwtHex := envOr("TRITON_MANAGE_JWT_SIGNING_KEY", "")
	pubHex := envOr("TRITON_MANAGE_LICENSE_SERVER_PUBKEY", "")
	sessionTTLStr := envOr("TRITON_MANAGE_SESSION_TTL", "24h")

	if dbURL == "" {
		return fmt.Errorf("TRITON_MANAGE_DB_URL is required")
	}
	if jwtHex == "" {
		return fmt.Errorf("TRITON_MANAGE_JWT_SIGNING_KEY is required (hex-encoded HS256 secret; min 32 bytes after decode)")
	}
	if pubHex == "" {
		return fmt.Errorf("TRITON_MANAGE_LICENSE_SERVER_PUBKEY is required (hex-encoded Ed25519 public key)")
	}

	jwtKey, err := hex.DecodeString(jwtHex)
	if err != nil {
		return fmt.Errorf("decoding TRITON_MANAGE_JWT_SIGNING_KEY: %w", err)
	}
	if len(jwtKey) < 32 {
		return fmt.Errorf("TRITON_MANAGE_JWT_SIGNING_KEY must decode to at least 32 bytes (got %d)", len(jwtKey))
	}

	pubKeyBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		return fmt.Errorf("decoding TRITON_MANAGE_LICENSE_SERVER_PUBKEY: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("TRITON_MANAGE_LICENSE_SERVER_PUBKEY must be %d bytes (got %d)", ed25519.PublicKeySize, len(pubKeyBytes))
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	sessionTTL, err := time.ParseDuration(sessionTTLStr)
	if err != nil {
		return fmt.Errorf("parsing TRITON_MANAGE_SESSION_TTL %q (use Go duration format, e.g. 24h): %w", sessionTTLStr, err)
	}

	ctx := context.Background()
	store, err := managestore.NewPostgresStore(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer func() { _ = store.Close() }()

	cfg := &manageserver.Config{
		Listen:        listen,
		DBUrl:         dbURL,
		JWTSigningKey: jwtKey,
		PublicKey:     pubKey,
		SessionTTL:    sessionTTL,
	}

	srv, err := manageserver.New(cfg, store)
	if err != nil {
		return fmt.Errorf("constructing server: %w", err)
	}

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("manage server listening on %s", listen)
	if err := srv.Run(runCtx); err != nil {
		return fmt.Errorf("running server: %w", err)
	}
	log.Println("manage server stopped")
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
