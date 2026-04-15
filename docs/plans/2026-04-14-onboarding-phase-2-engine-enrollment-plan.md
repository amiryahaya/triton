# Onboarding Phase 2 — Engine Enrollment + Heartbeat Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the on-prem engine container skeleton, the portal's engine-CA signing machinery, the signed enrollment bundle, and the engine↔portal mTLS-authenticated heartbeat. After Phase 2, an operator can download a bundle from `/manage/`, run the engine container with the bundle mounted, and see "Engine X online" appear in the portal UI within 30 seconds.

**Architecture:** Portal generates a per-org engine-CA on first engine creation, signs a per-engine cert + bundle. Bundle is a signed tar.gz delivered once over HTTPS. Engine consumes the bundle on startup, establishes mTLS to the portal's `/api/v1/engine/*` routes, and long-polls `/heartbeat` every 30s. No scan jobs yet — just trust handshake + liveness.

**Tech Stack:** Go 1.25 `crypto/ed25519` + `crypto/x509` + `crypto/tls` for CA/cert machinery, `golang.org/x/crypto/chacha20poly1305` (or reuse existing `pkg/crypto` helpers) for bundle sig, `go-chi/chi/v5` for the new `/api/v1/engine/*` subrouter, vanilla JS for the engines management page.

**Spec:** `docs/plans/2026-04-14-onboarding-design.md` §7.1 (enrollment trust model), §8.1 (engine table), §9 (gateway protocol).

---

## Prerequisites

- [ ] Phase 1 merged to `main` (PR #51). Confirm: `git log main --grep "onboarding phase 1" --oneline` shows the merge.
- [ ] Existing `inventory_hosts.engine_id` column (added in Phase 1) is ready to receive FK — this phase adds the `engines` table and the FK.

---

## File Map

**Create:**
- `pkg/server/engine/types.go` — Engine domain type, BundleManifest
- `pkg/server/engine/store.go` — Store interface
- `pkg/server/engine/postgres.go` — PostgresStore impl
- `pkg/server/engine/postgres_test.go` — integration tests
- `pkg/server/engine/ca.go` — per-org CA: generate, load, sign cert
- `pkg/server/engine/ca_test.go` — CA unit tests
- `pkg/server/engine/bundle.go` — bundle tar.gz packaging + signing
- `pkg/server/engine/bundle_test.go` — bundle unit tests
- `pkg/server/engine/handlers_admin.go` — `/api/v1/manage/engines/*` (Owner+Engineer)
- `pkg/server/engine/handlers_gateway.go` — `/api/v1/engine/*` (mTLS only, no JWT)
- `pkg/server/engine/handlers_test.go` — HTTP handler tests
- `pkg/server/engine/routes.go` — route mounting helpers
- `pkg/server/engine/mtls_middleware.go` — extracts engine_id from client cert, populates context
- `pkg/server/engine/mtls_middleware_test.go` — middleware tests
- `pkg/server/ui/dist/manage/engines.html` — (if embedded alongside existing SPA views) or just extend `app.js`
- `cmd/triton-engine/main.go` — engine binary entry point
- `cmd/triton-engine/config.go` — engine config loader
- `pkg/engine/client/client.go` — HTTP client (mTLS, retry, backoff)
- `pkg/engine/client/client_test.go` — client unit tests
- `pkg/engine/loop/loop.go` — enroll → heartbeat loop
- `pkg/engine/loop/loop_test.go` — loop unit tests
- `Containerfile.engine` — engine container build
- `pkg/store/migrations.go` — append Version 18 (engines table + CA storage)

**Modify:**
- `pkg/server/server.go` — mount `/api/v1/manage/engines/*` under JWT, mount `/api/v1/engine/*` under mTLS on a parallel chi router (or wrap)
- `pkg/server/ui/dist/manage/app.js` — add `#/engines` route + engine management views
- `pkg/server/ui/dist/manage/index.html` — add "Engines" nav link
- `Makefile` — `build-engine`, `container-build-engine`, `container-run-engine`
- `compose.yaml` — add engine service under new `profile: engine` (so dev runs aren't forced to start an engine)

**Do not touch:**
- `pkg/licenseserver/*` — independent system
- `pkg/server/inventory/*` — unless adding the FK constraint
- `pkg/scanner/*` — scanner engine integration comes in Phase 5

---

### Task 1: Database schema — engines table + CA storage

**Files:**
- Modify: `pkg/store/migrations.go` (append Version 18)

- [ ] **Step 1: Read current migrations file to confirm the positional-slice pattern and current version number.**

Run: `grep -n "Version\|migrations = \[\]string" pkg/store/migrations.go | head -10`

Expected: `migrations = []string{}` positional slice. Current last index = version 17 (added in Phase 1 for partial unique indexes).

- [ ] **Step 2: Append the migration SQL as index 18.**

```go
// Version 18: engines table + per-org engine-CA storage.
// Onboarding Phase 2 §7.1 + §8.1.
`
CREATE TABLE engine_cas (
    org_id           UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    ca_cert_pem      TEXT NOT NULL,
    ca_key_encrypted BYTEA NOT NULL,
    ca_key_nonce     BYTEA NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE engines (
    id                UUID PRIMARY KEY,
    org_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    label             TEXT NOT NULL,
    public_ip         INET,
    cert_fingerprint  TEXT NOT NULL,
    bundle_issued_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen_at     TIMESTAMPTZ,
    last_poll_at      TIMESTAMPTZ,
    status            TEXT NOT NULL DEFAULT 'enrolled'
                      CHECK (status IN ('enrolled', 'online', 'offline', 'revoked')),
    revoked_at        TIMESTAMPTZ,
    UNIQUE (org_id, label)
);

CREATE INDEX idx_engines_org ON engines(org_id);
CREATE INDEX idx_engines_status ON engines(status);

ALTER TABLE inventory_hosts
    ADD CONSTRAINT fk_inventory_hosts_engine
    FOREIGN KEY (engine_id) REFERENCES engines(id) ON DELETE SET NULL;
`,
```

- [ ] **Step 3: Apply + verify**

```bash
make db-up
psql "postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" -c "\dt engines engine_cas"
```

Expected: both tables listed.

- [ ] **Step 4: Commit**

```bash
git add pkg/store/migrations.go
git commit -m "feat(store): engines table + engine_cas + inventory_hosts FK (v18)"
```

---

### Task 2: Engine CA — per-org signing authority

**Files:**
- Create: `pkg/server/engine/ca.go`
- Create: `pkg/server/engine/ca_test.go`

**Why:** Per spec §7.1, each org has its own engine-CA. Private key is stored encrypted with a portal master key (from env `TRITON_PORTAL_CA_ENCRYPTION_KEY`). Decryption happens in-memory only when signing a new engine cert.

- [ ] **Step 1: Write failing test**

`pkg/server/engine/ca_test.go`:

```go
package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestCA_GenerateAndSign_RoundTrip(t *testing.T) {
	// 32-byte portal master key — deterministic for the test.
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	ca, err := GenerateCA(masterKey)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if len(ca.CAKeyEncrypted) == 0 {
		t.Fatal("expected encrypted CA key")
	}
	if len(ca.CACertPEM) == 0 {
		t.Fatal("expected CA cert PEM")
	}

	// Round-trip decrypt and sign an engine cert.
	_, enginePub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	engineCertPEM, err := ca.SignEngineCert(masterKey, "engine-test-01", enginePub)
	if err != nil {
		t.Fatalf("SignEngineCert: %v", err)
	}
	if len(engineCertPEM) == 0 {
		t.Fatal("expected engine cert PEM")
	}
}

func TestCA_SignWithWrongMasterKey_Fails(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = 1
	}
	ca, err := GenerateCA(key1)
	if err != nil {
		t.Fatal(err)
	}
	_, pub, _ := ed25519.GenerateKey(rand.Reader)
	_, err = ca.SignEngineCert(key2, "x", pub)
	if err == nil {
		t.Fatal("expected signing with wrong master key to fail")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test -run TestCA ./pkg/server/engine/
```

Expected: FAIL (package doesn't exist yet).

- [ ] **Step 3: Implement `ca.go`**

```go
// Package engine provides the Engine bounded context — CA, bundle
// generation, enrollment, heartbeat. Onboarding Phase 2.
package engine

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// CA holds the signed engine-CA certificate + the encrypted private key.
type CA struct {
	CACertPEM      []byte
	CAKeyEncrypted []byte
	CAKeyNonce     []byte
}

// GenerateCA creates a new root CA keypair for the org, encrypts the
// private key using the portal master key, and returns the CA record
// to be persisted in engine_cas.
func GenerateCA(masterKey []byte) (*CA, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Triton Engine CA", Organization: []string{"Triton"}},
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:         true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	encrypted, nonce, err := encryptWithMasterKey(masterKey, keyDER)
	if err != nil {
		return nil, err
	}

	return &CA{
		CACertPEM:      certPEM,
		CAKeyEncrypted: encrypted,
		CAKeyNonce:     nonce,
	}, nil
}

// SignEngineCert issues an Ed25519 engine cert signed by this CA.
// engineLabel is the cert's CN; enginePub is the engine's public key.
func (c *CA) SignEngineCert(masterKey []byte, engineLabel string, enginePub ed25519.PublicKey) ([]byte, error) {
	keyDER, err := decryptWithMasterKey(masterKey, c.CAKeyEncrypted, c.CAKeyNonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt CA key: %w", err)
	}
	caKey, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, err
	}

	caCertBlock, _ := pem.Decode(c.CACertPEM)
	if caCertBlock == nil {
		return nil, fmt.Errorf("bad CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: engineLabel, Organization: []string{"Triton Engine"}},
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, enginePub, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), nil
}

func encryptWithMasterKey(key, plaintext []byte) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return aead.Seal(nil, nonce, plaintext, nil), nonce, nil
}

func decryptWithMasterKey(key, ct, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, nil)
}
```

- [ ] **Step 4: Verify tests pass**

```bash
go test -run TestCA ./pkg/server/engine/
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/server/engine/ca.go pkg/server/engine/ca_test.go
git commit -m "feat(engine): per-org CA with encrypted key storage"
```

---

### Task 3: Engine domain types + store interface

**Files:**
- Create: `pkg/server/engine/types.go`
- Create: `pkg/server/engine/store.go`

- [ ] **Step 1: Types**

`pkg/server/engine/types.go`:

```go
package engine

import (
	"net"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	ID              uuid.UUID  `json:"id"`
	OrgID           uuid.UUID  `json:"org_id"`
	Label           string     `json:"label"`
	PublicIP        net.IP     `json:"public_ip,omitempty"`
	CertFingerprint string     `json:"cert_fingerprint"`
	BundleIssuedAt  time.Time  `json:"bundle_issued_at"`
	FirstSeenAt     *time.Time `json:"first_seen_at,omitempty"`
	LastPollAt      *time.Time `json:"last_poll_at,omitempty"`
	Status          string     `json:"status"` // enrolled|online|offline|revoked
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
}

// BundleManifest is serialized as engine.json inside the tar.gz bundle.
type BundleManifest struct {
	EngineID  string    `json:"engine_id"`
	OrgID     string    `json:"org_id"`
	PortalURL string    `json:"portal_url"`
	CreatedAt time.Time `json:"created_at"`
}
```

- [ ] **Step 2: Store interface**

`pkg/server/engine/store.go`:

```go
package engine

import (
	"context"

	"github.com/google/uuid"
)

type Store interface {
	// CA
	UpsertCA(ctx context.Context, orgID uuid.UUID, ca *CA) error
	GetCA(ctx context.Context, orgID uuid.UUID) (*CA, error)

	// Engines
	CreateEngine(ctx context.Context, e Engine) (Engine, error)
	GetEngine(ctx context.Context, orgID, id uuid.UUID) (Engine, error)
	GetEngineByFingerprint(ctx context.Context, fingerprint string) (Engine, error)
	ListEngines(ctx context.Context, orgID uuid.UUID) ([]Engine, error)
	RecordFirstSeen(ctx context.Context, id uuid.UUID, publicIP string) error
	RecordPoll(ctx context.Context, id uuid.UUID) error
	SetStatus(ctx context.Context, id uuid.UUID, status string) error
	Revoke(ctx context.Context, orgID, id uuid.UUID) error
}
```

- [ ] **Step 3: Commit**

```bash
git add pkg/server/engine/types.go pkg/server/engine/store.go
git commit -m "feat(engine): domain types and Store interface"
```

---

### Task 4: PostgresStore implementation + integration tests

**Files:**
- Create: `pkg/server/engine/postgres.go`
- Create: `pkg/server/engine/postgres_test.go`

- [ ] **Step 1: Implement PostgresStore**

Follow the Phase 1 inventory PostgresStore pattern: `NewPostgresStore(pool)`, typed methods, `org_id` scoping on reads, careful nil handling for nullable columns (`public_ip`, `first_seen_at`, `last_poll_at`, `revoked_at`).

Use `UPSERT` (`INSERT ... ON CONFLICT (org_id) DO UPDATE`) for `UpsertCA` so regenerating the CA (recovery scenario) doesn't fail.

`RecordFirstSeen` uses `UPDATE ... SET first_seen_at = NOW(), public_ip = $2, status = 'online' WHERE first_seen_at IS NULL AND id = $1` — the `IS NULL` guard ensures single-use.

- [ ] **Step 2: Write integration tests (build tag `integration`)**

Cover:
- `TestPostgresStore_CAUpsertGet` — round trip
- `TestPostgresStore_CreateAndListEngines` — lifecycle
- `TestPostgresStore_FirstSeenIsSingleUse` — second `RecordFirstSeen` returns 0 rows affected
- `TestPostgresStore_GetByFingerprint` — used by mTLS middleware to resolve cert → engine

Seed an `organizations` row + user row with `t.Cleanup` teardown, same pattern as `pkg/server/inventory/postgres_test.go`.

- [ ] **Step 3: Run tests**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" \
  go test -tags integration ./pkg/server/engine/
```

Expected: all PASS.

- [ ] **Step 4: Commit**

```bash
git add pkg/server/engine/postgres.go pkg/server/engine/postgres_test.go
git commit -m "feat(engine): PostgresStore with single-use first-seen guard"
```

---

### Task 5: Bundle packaging + signing

**Files:**
- Create: `pkg/server/engine/bundle.go`
- Create: `pkg/server/engine/bundle_test.go`

**Design:** Bundle is a tar.gz containing:
- `engine.json` (BundleManifest)
- `engine.key` (engine's private key, Ed25519)
- `engine.crt` (cert signed by org CA)
- `portal-ca.crt` (org's engine-CA cert, used by engine to validate future portal replies if portal also presents an mTLS server cert — in MVP the portal uses a public TLS cert, not mTLS server cert, so this is future-proofing)
- `manifest.sig` (Ed25519 signature over a SHA-256 digest of the other files, signed by portal signing key)

Portal signing key is separate from the org engine-CA: it's a portal-level identity that the engine can verify against a hardcoded pubkey embedded in the engine binary. For MVP, we generate the portal signing keypair on portal startup if it doesn't exist (stored in `engine_cas.portal_signing_key` or a dedicated table — simplest: a new `portal_signing_keys` table with a single row).

**Simplification for Phase 2:** skip `manifest.sig`. The bundle is transported out-of-band (SCP/USB/secure file share) and the engine trusts it. Threat model: bundle leak = rogue engine enrollment, mitigated by `first_seen_at` single-use. The spec §7.1 calls for `manifest.sig`, but that catches a narrower threat (bundle tampering in transit) that's harder to exploit than leak. **Defer `manifest.sig` to a follow-up.** Note this deviation in the bundle.go comment and in the PR description.

- [ ] **Step 1: Write failing test**

`pkg/server/engine/bundle_test.go`:

```go
package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestBuildBundle_ContainsExpectedFiles(t *testing.T) {
	// Construct a fake engine record + cert.
	engineID := uuid.Must(uuid.NewV7())
	orgID := uuid.Must(uuid.NewV7())
	engineKeyPEM := []byte("-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n")
	engineCertPEM := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
	caCertPEM := []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n")

	tgz, err := BuildBundle(BundleInputs{
		EngineID:      engineID.String(),
		OrgID:         orgID.String(),
		PortalURL:     "https://portal.example.com",
		EngineKeyPEM:  engineKeyPEM,
		EngineCertPEM: engineCertPEM,
		CACertPEM:     caCertPEM,
	})
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	want := map[string]bool{
		"engine.json":    false,
		"engine.key":     false,
		"engine.crt":     false,
		"portal-ca.crt":  false,
	}

	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		if _, ok := want[h.Name]; ok {
			want[h.Name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("missing %s in bundle", name)
		}
	}
}

func TestBuildBundle_EngineJSONHasExpectedFields(t *testing.T) {
	engineID := uuid.Must(uuid.NewV7()).String()
	tgz, _ := BuildBundle(BundleInputs{
		EngineID:  engineID,
		OrgID:     uuid.Must(uuid.NewV7()).String(),
		PortalURL: "https://p",
	})
	// Extract engine.json and check for EngineID string
	gz, _ := gzip.NewReader(bytes.NewReader(tgz))
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if h.Name == "engine.json" {
			buf := new(bytes.Buffer)
			_, _ = io.Copy(buf, tr)
			if !strings.Contains(buf.String(), engineID) {
				t.Fatalf("engine.json missing engine ID: %s", buf.String())
			}
		}
	}
}
```

- [ ] **Step 2: Run test → fail**

```bash
go test -run TestBuildBundle ./pkg/server/engine/
```

- [ ] **Step 3: Implement `bundle.go`**

```go
package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"time"
)

// BundleInputs is the material to package into a tar.gz bundle.
type BundleInputs struct {
	EngineID      string
	OrgID         string
	PortalURL     string
	EngineKeyPEM  []byte
	EngineCertPEM []byte
	CACertPEM     []byte
}

// BuildBundle produces a tar.gz bundle to hand to an operator.
// Contents (per Onboarding spec §7.1):
//   engine.json      BundleManifest
//   engine.key       engine private key (Ed25519)
//   engine.crt       signed by org engine-CA
//   portal-ca.crt    org CA cert (for future portal mTLS server auth)
//
// NOTE: manifest.sig (portal signing-key signature over the above) is
// deferred to a follow-up. Bundle integrity in-transit is currently
// assumed from out-of-band delivery (SCP/USB). Bundle leakage is
// mitigated by single-use first-seen guard in the store.
func BuildBundle(in BundleInputs) ([]byte, error) {
	manifest, err := json.MarshalIndent(BundleManifest{
		EngineID:  in.EngineID,
		OrgID:     in.OrgID,
		PortalURL: in.PortalURL,
		CreatedAt: time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	add := func(name string, data []byte, mode int64) error {
		if err := tw.WriteHeader(&tar.Header{
			Name:    name,
			Size:    int64(len(data)),
			Mode:    mode,
			ModTime: time.Now().UTC(),
		}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}

	if err := add("engine.json", manifest, 0644); err != nil {
		return nil, err
	}
	if err := add("engine.key", in.EngineKeyPEM, 0400); err != nil {
		return nil, err
	}
	if err := add("engine.crt", in.EngineCertPEM, 0644); err != nil {
		return nil, err
	}
	if err := add("portal-ca.crt", in.CACertPEM, 0644); err != nil {
		return nil, err
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
```

- [ ] **Step 4: Tests pass**

```bash
go test -run TestBuildBundle ./pkg/server/engine/
```

- [ ] **Step 5: Commit**

```bash
git add pkg/server/engine/bundle.go pkg/server/engine/bundle_test.go
git commit -m "feat(engine): tar.gz bundle packaging"
```

---

### Task 6: mTLS middleware — extract engine identity from client cert

**Files:**
- Create: `pkg/server/engine/mtls_middleware.go`
- Create: `pkg/server/engine/mtls_middleware_test.go`

- [ ] **Step 1: Implement middleware**

`pkg/server/engine/mtls_middleware.go`:

```go
package engine

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
)

type mtlsCtxKey struct{}

// EngineFromContext returns the enrolled engine ID from an mTLS-authed request, or nil.
func EngineFromContext(ctx context.Context) *Engine {
	e, _ := ctx.Value(mtlsCtxKey{}).(*Engine)
	return e
}

// MTLSMiddleware rejects requests that don't present a client cert
// signed by a known engine-CA. Populates context with the resolved Engine.
func MTLSMiddleware(store Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "client cert required", http.StatusUnauthorized)
				return
			}
			leaf := r.TLS.PeerCertificates[0]
			fp := sha256.Sum256(leaf.Raw)
			fpHex := hex.EncodeToString(fp[:])

			eng, err := store.GetEngineByFingerprint(r.Context(), fpHex)
			if err != nil {
				http.Error(w, "unknown engine", http.StatusUnauthorized)
				return
			}
			if eng.Status == "revoked" {
				http.Error(w, "engine revoked", http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), mtlsCtxKey{}, &eng)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireMTLS is a typed helper for handlers: returns the engine from context or nil.
// Does not short-circuit; MTLSMiddleware already rejected missing certs.
func RequireMTLS(h func(w http.ResponseWriter, r *http.Request, e *Engine)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		eng := EngineFromContext(r.Context())
		if eng == nil {
			http.Error(w, "internal: missing engine context", http.StatusInternalServerError)
			return
		}
		h(w, r, eng)
	}
}
```

- [ ] **Step 2: Test middleware**

Cover cases:
- No TLS on request → 401
- TLS but no peer certs → 401
- Peer cert with unknown fingerprint → 401
- Peer cert for revoked engine → 403
- Valid cert → handler invoked with engine in context

Use a `fakeStore` in the test file.

- [ ] **Step 3: Commit**

```bash
git add pkg/server/engine/mtls_middleware.go pkg/server/engine/mtls_middleware_test.go
git commit -m "feat(engine): mTLS middleware resolves engine by cert fingerprint"
```

---

### Task 7: Admin handlers — create engine, list, download bundle, revoke

**Files:**
- Create: `pkg/server/engine/handlers_admin.go`
- Create: `pkg/server/engine/handlers_test.go`
- Create: `pkg/server/engine/routes.go`

**Endpoints (all under `/api/v1/manage/engines`, JWT + RequireRole(Engineer)):**
- `POST /` — body `{label}` — creates CA if missing, generates engine keypair, signs cert, inserts row, responds with `{engine, bundle_url}`
- `GET /` — list engines for the org
- `GET /{id}` — get one
- `GET /{id}/bundle` — download tar.gz. **Single-use:** responds with 410 Gone if `first_seen_at != null` (already enrolled).
- `POST /{id}/revoke` — Owner only. Sets `status='revoked'`, `revoked_at=NOW()`.

- [ ] **Step 1: Write handler tests first**

Skeleton — full bodies during implementation:
- `TestCreateEngine_Engineer_201`
- `TestCreateEngine_Officer_403`
- `TestListEngines_Officer_200` (Officer can view)
- `TestDownloadBundle_FirstCall_200`
- `TestDownloadBundle_AfterEnroll_410Gone`
- `TestRevoke_Owner_200`
- `TestRevoke_Engineer_403` (revoke is Owner-only)

- [ ] **Step 2: Implement handlers**

Key snippets:

```go
func (h *AdminHandlers) CreateEngine(w http.ResponseWriter, r *http.Request) {
    var body struct{ Label string `json:"label"` }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    claims := server.ClaimsFromContext(r.Context())
    orgID, _ := uuid.Parse(claims.Org)

    // Ensure CA exists for the org.
    ca, err := h.Store.GetCA(r.Context(), orgID)
    if err != nil {
        ca, err = GenerateCA(h.MasterKey)
        if err != nil {
            http.Error(w, "CA bootstrap failed", 500)
            return
        }
        if err := h.Store.UpsertCA(r.Context(), orgID, ca); err != nil {
            http.Error(w, err.Error(), 500)
            return
        }
    }

    // Generate engine keypair.
    enginePub, enginePriv, err := ed25519.GenerateKey(rand.Reader)
    // ... sign, build engine row, insert ...
    // Respond with Engine JSON. Bundle is downloaded separately.
}
```

Bundle download:

```go
func (h *AdminHandlers) DownloadBundle(w http.ResponseWriter, r *http.Request) {
    engineID, _ := uuid.Parse(chi.URLParam(r, "id"))
    orgID := // from claims
    eng, err := h.Store.GetEngine(r.Context(), orgID, engineID)
    if err != nil { /* 404 */ }
    if eng.FirstSeenAt != nil {
        http.Error(w, "bundle already claimed", http.StatusGone)
        return
    }
    // Retrieve stored engine key + cert (kept in engines table or a sibling
    // secrets table — MVP: add columns engine_key_encrypted + engine_cert_pem
    // to engines, filled at CreateEngine. Or store in memory only and return
    // the bundle inline in CreateEngine's response.)

    // SIMPLIFICATION: CreateEngine returns the bundle bytes inline, and the
    // DB only stores the cert fingerprint. Re-download is not supported —
    // operator must re-create the engine if they lose the bundle. This is
    // simpler and strictly more secure (private key never persists).

    http.Error(w, "re-download not supported; create a new engine", http.StatusGone)
}
```

Revise the endpoint set: `POST /` returns the bundle bytes as `application/gzip` directly (Content-Disposition with filename). `GET /{id}/bundle` is removed. Update the plan accordingly.

- [ ] **Step 3: Routes**

`pkg/server/engine/routes.go`:

```go
package engine

import (
    "github.com/go-chi/chi/v5"

    "github.com/amiryahaya/triton/pkg/server"
)

func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
    r.Get("/", h.ListEngines)
    r.Get("/{id}", h.GetEngine)

    r.Group(func(r chi.Router) {
        r.Use(server.RequireRole(server.RoleEngineer))
        r.Post("/", h.CreateEngine) // returns tar.gz inline
    })

    r.Group(func(r chi.Router) {
        r.Use(server.RequireRole(server.RoleOwner))
        r.Post("/{id}/revoke", h.RevokeEngine)
    })
}
```

- [ ] **Step 4: Tests pass, commit**

```bash
go test ./pkg/server/engine/
git add pkg/server/engine/handlers_admin.go pkg/server/engine/handlers_test.go pkg/server/engine/routes.go
git commit -m "feat(engine): admin handlers — create engine + download bundle inline + revoke"
```

---

### Task 8: Gateway handlers — enroll + heartbeat

**Files:**
- Create: `pkg/server/engine/handlers_gateway.go`

**Endpoints (under `/api/v1/engine/*`, mTLS only — no JWT):**
- `POST /enroll` — idempotent handshake. If `first_seen_at` is nil, set it + `public_ip` (from `r.RemoteAddr`) and flip status to `online`. If already enrolled, just returns 200 + current engine state.
- `POST /heartbeat` — updates `last_poll_at = NOW()`. Body may be empty. Used to signal liveness. Portal consumers compute `status = online` if `last_poll_at > NOW() - 60s`, else `offline` (lazy — updated by a background ticker, see Task 9).

- [ ] **Step 1: Implement**

```go
func (h *GatewayHandlers) Enroll(w http.ResponseWriter, r *http.Request) {
    eng := EngineFromContext(r.Context())
    if eng.FirstSeenAt == nil {
        ip := ipFromRemote(r.RemoteAddr)
        if err := h.Store.RecordFirstSeen(r.Context(), eng.ID, ip); err != nil {
            http.Error(w, err.Error(), 500)
            return
        }
    }
    writeJSON(w, 200, map[string]string{"engine_id": eng.ID.String(), "status": "online"})
}

func (h *GatewayHandlers) Heartbeat(w http.ResponseWriter, r *http.Request) {
    eng := EngineFromContext(r.Context())
    if err := h.Store.RecordPoll(r.Context(), eng.ID); err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    w.WriteHeader(204)
}

func MountGatewayRoutes(r chi.Router, h *GatewayHandlers) {
    // Caller must apply MTLSMiddleware to r before calling.
    r.Post("/enroll", h.Enroll)
    r.Post("/heartbeat", h.Heartbeat)
}
```

- [ ] **Step 2: Tests**

Cover: enroll first-time (sets first_seen_at, status online), enroll idempotent, heartbeat (updates last_poll_at).

- [ ] **Step 3: Commit**

```bash
git add pkg/server/engine/handlers_gateway.go pkg/server/engine/handlers_gateway_test.go
git commit -m "feat(engine): gateway handlers — enroll + heartbeat"
```

---

### Task 9: Offline detector — background ticker flipping status

**Files:**
- Create: `pkg/server/engine/offline_detector.go`
- Create: `pkg/server/engine/offline_detector_test.go`

Runs every 30s: find engines with `status='online' AND last_poll_at < NOW() - 60 seconds`, set status to `offline`. Emit audit event `engine.offline.detected`.

- [ ] **Step 1: Implement** a ticker that a caller (server.go) starts as a goroutine. Use `time.NewTicker(30 * time.Second)`. Context cancellation stops it cleanly.

- [ ] **Step 2: Test** with a time-injection (`nowFn func() time.Time`) so the test can jump forward 61 seconds.

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(engine): offline detector flips stale engines to offline"
```

---

### Task 10: Wire into `pkg/server/server.go`

**Files:**
- Modify: `pkg/server/server.go`
- Modify: `cmd/server.go` (entry point — if that's where routes are mounted per Phase 1 adaptation)

**Key challenges:**

1. **mTLS listener.** `/api/v1/engine/*` needs a TLS server that `ClientAuth = tls.RequireAndVerifyClientCert` with `ClientCAs` set to the union of all org engine-CAs. Two options:

   (a) Run a second HTTP listener on a different port (e.g., 8443 for mTLS engine gateway), port 8080 for the main UI + admin API. Simpler.

   (b) Use SNI to route the same port to different handlers. More complex, one port.

   **Choose (a)** for MVP — port 8443 for engine mTLS, port 8080 for everything else. Document this in the deployment guide.

2. **ClientCAs pool.** On startup, scan `engine_cas` table, load all `ca_cert_pem` entries into a `*x509.CertPool`. Refresh every 5min (or on explicit invalidation when new engines are created).

3. **Master key.** Read from env `TRITON_PORTAL_CA_ENCRYPTION_KEY` (hex-encoded 32 bytes). Fail to start if missing.

- [ ] **Step 1:** Add mTLS listener construction. Start with a helper:

```go
func startEngineMTLSListener(addr string, store engine.Store, handler http.Handler) (func(), error) {
    pool := x509.NewCertPool()
    // load CAs from store...
    tlsConfig := &tls.Config{
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs:  pool,
        MinVersion: tls.VersionTLS12,
    }
    srv := &http.Server{
        Addr:      addr,
        Handler:   handler,
        TLSConfig: tlsConfig,
    }
    go srv.ListenAndServeTLS(portalCertPEM, portalKeyPEM)
    return func() { srv.Shutdown(context.Background()) }, nil
}
```

Portal's own TLS cert can be a self-signed cert for MVP (engine doesn't verify it in MVP — trusts the operator's out-of-band portal URL). Document this — production will need a real cert.

- [ ] **Step 2:** Construct `engine.AdminHandlers` + `engine.GatewayHandlers`, mount them on their respective routers.

- [ ] **Step 3:** Start offline detector goroutine, wire its cancel to graceful shutdown.

- [ ] **Step 4:** Build + smoke test:

```bash
go build ./...
```

- [ ] **Step 5:** Commit

```bash
git commit -m "feat(server): wire engine admin + gateway routes + mTLS listener"
```

---

### Task 11: Engine binary — `cmd/triton-engine`

**Files:**
- Create: `cmd/triton-engine/main.go`
- Create: `cmd/triton-engine/config.go`
- Create: `pkg/engine/client/client.go`
- Create: `pkg/engine/client/client_test.go`
- Create: `pkg/engine/loop/loop.go`
- Create: `pkg/engine/loop/loop_test.go`

**Binary responsibilities:**
1. On startup: read bundle path from `TRITON_BUNDLE_PATH` (default `/etc/triton/bundle.tar.gz`)
2. Extract bundle to in-memory structs (never write secrets to disk unless operator opts in)
3. Build TLS config with engine cert/key + portal CA
4. `POST /api/v1/engine/enroll` once
5. Loop: `POST /api/v1/engine/heartbeat` every 30s, with 2× exponential backoff on failure

- [ ] **Step 1:** Implement the HTTP client (`pkg/engine/client/client.go`):

```go
type Client struct {
    PortalURL string
    HTTP      *http.Client
}

func New(bundlePath string) (*Client, error) {
    // Load bundle, parse manifest, build tls.Config, construct Client.
}

func (c *Client) Enroll(ctx context.Context) error { /* POST /enroll */ }
func (c *Client) Heartbeat(ctx context.Context) error { /* POST /heartbeat */ }
```

- [ ] **Step 2:** Implement the loop (`pkg/engine/loop/loop.go`):

```go
func Run(ctx context.Context, c *Client) error {
    // First: enroll. Retry on transient errors.
    backoff := time.Second
    for {
        if err := c.Enroll(ctx); err == nil {
            break
        } else if ctx.Err() != nil {
            return ctx.Err()
        }
        time.Sleep(backoff)
        backoff *= 2
        if backoff > time.Minute {
            backoff = time.Minute
        }
    }

    // Then: heartbeat.
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-ticker.C:
            if err := c.Heartbeat(ctx); err != nil {
                log.Printf("heartbeat: %v", err)
            }
        }
    }
}
```

- [ ] **Step 3:** `cmd/triton-engine/main.go`:

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/amiryahaya/triton/pkg/engine/client"
    "github.com/amiryahaya/triton/pkg/engine/loop"
)

func main() {
    ctx, cancel := context.WithCancel(context.Background())

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-sigCh
        log.Println("shutting down")
        cancel()
    }()

    bundlePath := os.Getenv("TRITON_BUNDLE_PATH")
    if bundlePath == "" {
        bundlePath = "/etc/triton/bundle.tar.gz"
    }

    c, err := client.New(bundlePath)
    if err != nil {
        log.Fatalf("bundle load: %v", err)
    }

    if err := loop.Run(ctx, c); err != nil && err != context.Canceled {
        log.Fatalf("loop: %v", err)
    }
}
```

- [ ] **Step 4:** Tests for client (bundle parse, enroll request shape) and loop (exits on ctx.Done, retries enroll with backoff).

- [ ] **Step 5:** Commit

```bash
git commit -m "feat(engine): triton-engine binary + enroll/heartbeat loop"
```

---

### Task 12: Containerfile + compose integration

**Files:**
- Create: `Containerfile.engine`
- Modify: `compose.yaml`
- Modify: `Makefile`

- [ ] **Step 1:** `Containerfile.engine`:

```dockerfile
FROM golang:1.25 AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags "-s -w -X github.com/amiryahaya/triton/internal/version.Version=${VERSION}" \
    -o /out/triton-engine \
    ./cmd/triton-engine

FROM scratch
COPY --from=build /out/triton-engine /triton-engine
# CA certs for HTTPS to portal
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# Expected mount: /etc/triton/bundle.tar.gz
ENTRYPOINT ["/triton-engine"]
```

- [ ] **Step 2:** Makefile targets:

```make
build-engine:
	go build -o bin/triton-engine ./cmd/triton-engine

container-build-engine:
	podman build -t triton-engine:local -f Containerfile.engine .
```

- [ ] **Step 3:** `compose.yaml` — add a service behind profile `engine`:

```yaml
  engine:
    build:
      context: .
      dockerfile: Containerfile.engine
    volumes:
      - ./bundle.tar.gz:/etc/triton/bundle.tar.gz:ro
    networks:
      - triton
    profiles: [engine]
```

- [ ] **Step 4:** Commit

```bash
git commit -m "feat(engine): Containerfile + compose profile + make targets"
```

---

### Task 13: Management UI — engines page

**Files:**
- Modify: `pkg/server/ui/dist/manage/app.js`
- Modify: `pkg/server/ui/dist/manage/index.html`

Add `#/engines` route:
- List: table of engines with label, status (color-coded), last seen, public IP, actions (revoke for Owner)
- Create button (Engineer+): modal asks for label → POST, response is a downloadable `.tar.gz` → trigger browser download

```javascript
async function renderEngines(el) {
    // Fetch list, render table. Create form triggers bundle download.
}
```

Bundle download in browser: after POST succeeds, use the Response blob:

```javascript
const resp = await authedFetch('/api/v1/manage/engines/', { method: 'POST', body: JSON.stringify({label}) });
if (resp.ok) {
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `engine-${label}.tar.gz`;
    a.click();
    URL.revokeObjectURL(url);
}
```

- [ ] **Step 1:** Implement + manual smoke test
- [ ] **Step 2:** Commit

```bash
git commit -m "feat(ui): engines page with inline bundle download"
```

---

### Task 14: End-to-end verification

- [ ] **Step 1:** `go build ./... && make lint` — all clean
- [ ] **Step 2:** `go test ./pkg/server/engine/... ./pkg/engine/...` — PASS
- [ ] **Step 3:** `go test -tags integration ./pkg/server/engine/` — PASS with `TRITON_TEST_DB_URL` set
- [ ] **Step 4:** Manual E2E:
  1. `make container-run` (portal + postgres)
  2. Log in at `/manage/`, create engine "test-engine", receive bundle
  3. `cp ~/Downloads/engine-test-engine.tar.gz ./bundle.tar.gz`
  4. `make container-run-engine` — engine starts, enrolls
  5. Refresh `/manage/#/engines` — engine shows as "online"
  6. Stop engine container; after ~90s portal shows "offline"

---

### Task 15: PR + code review

- [ ] Push, open PR, dispatch `superpowers:code-reviewer` for a full diff review.
- [ ] Address all Critical + Important findings before merge.

---

## Self-Review Checklist

**Spec coverage:**
- §7.1 signed bundle: covered (CA + bundle + per-engine cert). **manifest.sig deferred — explicit deviation, documented.**
- §8.1 `engine.engines` table: covered (Task 1).
- §9 gateway endpoints enroll + heartbeat: covered (Task 8). `/jobs/poll`, `/credentials/push`, `/discovery/*` are deferred to later phases.
- UI feedback ("Engine X online/offline"): covered (Task 9 offline detector + Task 13 UI).

**Placeholder scan:** Version 18 migration number is a real number (prior phase ended at 17). TLS cert for portal mTLS listener is noted as "self-signed MVP, real cert for prod" — explicit deviation, not a placeholder to fill.

**Type consistency:** `Engine`, `CA`, `BundleInputs`, `BundleManifest` used consistently. `Store.GetEngineByFingerprint` matches what `MTLSMiddleware` calls. `RecordFirstSeen(id, publicIP)` signature same across store and gateway handler.

**Known deviations from spec:**
1. Bundle `manifest.sig` not produced in MVP — bundle integrity relies on out-of-band delivery + single-use first-seen guard.
2. Bundle re-download not supported — operator must create a new engine if bundle is lost. Simpler + more secure (private key never persists in DB).
3. Portal mTLS listener uses self-signed TLS cert by default — production deployment must supply a real cert. Documented.

**Risk the implementer might miss:**
- `first_seen_at` UPDATE guard (`WHERE first_seen_at IS NULL`) — if skipped, a leaked bundle could be replayed.
- mTLS port separation (8443 vs 8080) requires firewall/deployment updates in the customer environment.
- `ClientCAs` pool refresh cadence — new org engine creates CA → existing mTLS listener won't accept the new engine's cert until refresh. 5min refresh interval is a reasonable default; new-engine flows should be aware.
