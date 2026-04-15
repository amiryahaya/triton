// Command triton-engine is the long-running agent binary that phones
// home to the Triton portal. It loads an onboarding bundle (cert/key/
// manifest) from disk, enrolls, then heartbeats every 30s until the
// process receives SIGINT or SIGTERM.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/amiryahaya/triton/pkg/engine/client"
	"github.com/amiryahaya/triton/pkg/engine/credentials"
	trcrypto "github.com/amiryahaya/triton/pkg/engine/crypto"
	"github.com/amiryahaya/triton/pkg/engine/discovery"
	"github.com/amiryahaya/triton/pkg/engine/keystore"
	"github.com/amiryahaya/triton/pkg/engine/loop"
)

// loadKeystoreMasterKey returns the 32-byte master key used to encrypt
// the at-rest secret store. Precedence:
//  1. TRITON_ENGINE_KEYSTORE_KEY — 64 hex chars. Production path.
//  2. Derived from the engine's X25519 private key via
//     SHA-256(priv.Bytes() || "triton-engine-keystore-v1"). Dev-only
//     fallback — logs a loud WARNING.
//
// A malformed env var is a fatal configuration error rather than a
// silent downgrade so operators can spot misconfigured production
// deployments immediately.
func loadKeystoreMasterKey(priv *ecdh.PrivateKey) []byte {
	s := os.Getenv("TRITON_ENGINE_KEYSTORE_KEY")
	if s != "" {
		key, err := hex.DecodeString(s)
		if err != nil {
			log.Fatalf("TRITON_ENGINE_KEYSTORE_KEY must be hex-encoded: %v", err)
		}
		if len(key) != 32 {
			log.Fatalf("TRITON_ENGINE_KEYSTORE_KEY must be 64 hex chars (32 bytes), got %d", len(key))
		}
		return key
	}
	log.Println("WARNING: TRITON_ENGINE_KEYSTORE_KEY unset — deriving keystore master key from X25519 private key (DEV ONLY)")
	h := sha256.New()
	h.Write(priv.Bytes())
	h.Write([]byte("triton-engine-keystore-v1"))
	return h.Sum(nil)
}

// run is the real entry point — factored out so that main() stays
// free of `defer + log.Fatalf` hazards flagged by gocritic. main()
// simply calls run() and propagates the exit code.
func run() int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutdown signal received")
		cancel()
	}()

	bundlePath := os.Getenv("TRITON_BUNDLE_PATH")
	if bundlePath == "" {
		bundlePath = "/etc/triton/bundle.tar.gz"
	}

	c, err := client.New(bundlePath)
	if err != nil {
		log.Printf("bundle load: %v", err)
		return 1
	}

	log.Printf("triton-engine starting: engine_id=%s portal=%s", c.EngineID, c.PortalURL)

	// X25519 keypair for credential sealed-box delivery. In-memory,
	// regenerated per startup — the public key is (re-)submitted after
	// every enroll so the portal always has the current half.
	priv, pub, err := trcrypto.GenerateKeypair()
	if err != nil {
		log.Printf("keygen: %v", err)
		return 1
	}

	ksPath := os.Getenv("TRITON_ENGINE_KEYSTORE_PATH")
	if ksPath == "" {
		ksPath = "/var/lib/triton-engine/keystore.db"
	}
	if err := os.MkdirAll(filepath.Dir(ksPath), 0o700); err != nil {
		log.Printf("mkdir keystore dir: %v", err)
		return 1
	}
	masterKey := loadKeystoreMasterKey(priv)
	ks, err := keystore.Open(ksPath, masterKey)
	if err != nil {
		log.Printf("open keystore: %v", err)
		return 1
	}
	defer func() { _ = ks.Close() }()

	// Discovery worker: long-poll the portal for queued discovery
	// jobs, run TCP-connect scans, stream candidates back.
	scanner := &discovery.Scanner{}
	discoveryWorker := &discovery.Worker{
		Client:  c,
		Scanner: scanner,
	}

	// Credential delivery handler + test worker.
	credHandler := &credentials.Handler{
		Client:     c,
		Keystore:   ks,
		PrivateKey: priv,
	}
	credTestWorker := &credentials.TestWorker{
		Client:   c,
		Keystore: ks,
		Prober:   &credentials.Prober{},
	}

	cfg := loop.Config{
		DiscoveryWorker:      discoveryWorker,
		CredentialHandler:    credHandler,
		CredentialTestWorker: credTestWorker,
		OnEnrolled: func(ctx context.Context) {
			if err := c.SubmitEncryptionPubkey(ctx, pub); err != nil {
				log.Printf("submit encryption pubkey: %v", err)
			}
		},
	}

	if err := loop.Run(ctx, c, cfg); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("loop: %v", err)
		return 1
	}
	log.Println("triton-engine stopped")
	return 0
}

func main() { os.Exit(run()) }
