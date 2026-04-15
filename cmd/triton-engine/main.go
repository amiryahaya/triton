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
	"github.com/amiryahaya/triton/pkg/engine/scanexec"
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
// loadKeystoreMasterKey returns the master key and a flag indicating
// whether the key was derived from the ephemeral X25519 private key
// (dev-only mode). Callers use the flag to decide whether to wipe
// stale rows that are unreadable under the fresh key.
func loadKeystoreMasterKey(priv *ecdh.PrivateKey) (key []byte, derived bool) {
	s := os.Getenv("TRITON_ENGINE_KEYSTORE_KEY")
	if s != "" {
		k, err := hex.DecodeString(s)
		if err != nil {
			log.Fatalf("TRITON_ENGINE_KEYSTORE_KEY must be hex-encoded: %v", err)
		}
		if len(k) != 32 {
			log.Fatalf("TRITON_ENGINE_KEYSTORE_KEY must be 64 hex chars (32 bytes), got %d", len(k))
		}
		return k, false
	}
	log.Printf("WARNING: TRITON_ENGINE_KEYSTORE_KEY not set — deriving ephemeral master key from engine X25519 private key.")
	log.Printf("WARNING: This key rotates on every restart. ALL PREVIOUSLY STORED SECRETS WILL BE UNREADABLE after restart.")
	log.Printf("WARNING: Set TRITON_ENGINE_KEYSTORE_KEY (64 hex chars = 32 bytes) in production to persist secrets across restarts.")
	h := sha256.New()
	h.Write(priv.Bytes())
	h.Write([]byte("triton-engine-keystore-v1"))
	return h.Sum(nil), true
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
	masterKey, derivedKey := loadKeystoreMasterKey(priv)
	ks, err := keystore.Open(ksPath, masterKey)
	if err != nil {
		log.Printf("open keystore: %v", err)
		return 1
	}
	defer func() { _ = ks.Close() }()

	// When using a derived (ephemeral) master key, any secrets carried
	// over from a previous run are permanently undecryptable. Wipe them
	// proactively so the keystore doesn't accumulate zombie rows and
	// the engine re-requests a fresh delivery from the portal.
	if derivedKey {
		if n, err := ks.Wipe(ctx); err != nil {
			log.Printf("keystore: wipe stale secrets: %v", err)
		} else if n > 0 {
			log.Printf("keystore: wiped %d stale secrets (ephemeral master key)", n)
		}
	}

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

	// Scan job worker: claim scan jobs from the portal, run each host
	// through SSH+scanner, stream progress + findings back.
	scanExecutor := &scanexec.Executor{Keystore: ks}
	scanWorker := &scanexec.Worker{
		Client:   c,
		Executor: scanExecutor,
	}

	cfg := loop.Config{
		DiscoveryWorker:      discoveryWorker,
		CredentialHandler:    credHandler,
		CredentialTestWorker: credTestWorker,
		ScanWorker:           scanWorker,
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
