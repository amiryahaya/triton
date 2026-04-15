# Onboarding Phase 4 — Credentials + Secret Push Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Users define credential profiles in the portal UI with matcher rules (group, OS, CIDR, tags). Secrets are encrypted in the browser to the owning engine's X25519 public key, POSTed as opaque ciphertext to the portal, forwarded to the engine, decrypted, re-encrypted with the engine's local master key, and stored in a SQLite keystore on the engine. Portal never holds plaintext. A "test against N hosts" probe exercises the credential against real hosts and reports per-host success.

**Architecture:** Three cryptographic layers.
- Layer 1 (transport): browser → portal over HTTPS (existing TLS to 8080).
- Layer 2 (end-to-end): browser encrypts secret to engine's X25519 pubkey (X25519-ECDH + HKDF-SHA256 + ChaCha20-Poly1305); portal is strictly a courier of opaque bytes.
- Layer 3 (at rest): engine decrypts Layer 2, re-encrypts with its local master key derived from the Phase 2 `TRITON_PORTAL_CA_ENCRYPTION_KEY`-analog on the engine side, and stores in SQLite.

Test-probe uses the same job-pull pattern as Phase 3 discovery: portal queues a `credential_tests` row, engine long-polls `/api/v1/engine/credential-tests/poll`, resolves host list already attached to the test job by the portal, runs per-host SSH/WinRM probes, submits results.

**Tech Stack:** Go 1.25 (`crypto/ecdh` for X25519, `golang.org/x/crypto/chacha20poly1305`, `golang.org/x/crypto/hkdf`, `modernc.org/sqlite` or `mattn/go-sqlite3` for engine keystore), browser: `@noble/curves@1.7.0` + `@noble/ciphers@1.0.0` via esm.sh CDN import.

**Spec:** `docs/plans/2026-04-14-onboarding-design.md` §6 step 4 (Credentials), §7 security decisions, §8.1 (`credentials.profiles` table), §9 (`/credentials/push`, `/engines/{id}/pubkey`).

---

## Prerequisites

- [ ] Phase 3 merged to `main` (PR #56). Confirm: `git log main --grep "onboarding phase 3"`.
- [ ] Engine gateway on port 8443 mounts `/api/v1/engine/*` (Phase 2). New credential routes live there.
- [ ] `engines.id` + `inventory_hosts` schema stable. Migration v19 head.

---

## File Map

**Create:**
- `pkg/server/credentials/types.go` — Profile, Matcher, TestJob, TestResult
- `pkg/server/credentials/store.go` — Store interface
- `pkg/server/credentials/postgres.go` — PostgresStore
- `pkg/server/credentials/postgres_test.go` — integration tests
- `pkg/server/credentials/matcher.go` — resolve matcher → host IDs, tested independently
- `pkg/server/credentials/matcher_test.go` — unit tests for matcher logic
- `pkg/server/credentials/handlers_admin.go` — `/api/v1/manage/credentials/*` + `/engines/{id}/encryption-pubkey`
- `pkg/server/credentials/handlers_gateway.go` — `/api/v1/engine/credentials/*` + `/credential-tests/*`
- `pkg/server/credentials/handlers_test.go` — handler tests
- `pkg/server/credentials/routes.go` — MountAdminRoutes + MountGatewayRoutes
- `pkg/engine/crypto/sealedbox.go` — X25519 + HKDF + ChaCha20-Poly1305 wrapper (portable between portal admin decrypt path if ever needed and engine decrypt path)
- `pkg/engine/crypto/sealedbox_test.go`
- `pkg/engine/keystore/keystore.go` — SQLite-backed secret store
- `pkg/engine/keystore/keystore_test.go`
- `pkg/engine/credentials/handler.go` — engine-side "credential received from portal" processor
- `pkg/engine/credentials/handler_test.go`
- `pkg/engine/credentials/probe.go` — SSH/WinRM probes for test-against-N-hosts
- `pkg/engine/credentials/probe_test.go`
- `pkg/engine/credentials/test_worker.go` — polling loop for credential-test jobs
- `pkg/engine/credentials/test_worker_test.go`
- `pkg/server/ui/dist/manage/crypto.js` — client-side encryption helper (imports noble libs)

**Modify:**
- `pkg/store/migrations.go` — append Version 20 (credentials_profiles + credential_tests tables + engines.encryption_pubkey column)
- `pkg/server/engine/store.go` + `postgres.go` — add `SetEncryptionPubkey(ctx, engineID, pubkey) error`
- `pkg/server/engine/handlers_gateway.go` — add `POST /encryption-pubkey` (mTLS) so engine can register its X25519 pubkey
- `pkg/engine/client/client.go` — add `SubmitEncryptionPubkey`, `PollCredentialPush`, `PollCredentialTest`, `SubmitCredentialTest`
- `pkg/engine/loop/loop.go` — start CredentialTestWorker alongside DiscoveryWorker
- `cmd/triton-engine/main.go` — wire keystore + credential handler + test worker
- `cmd/server.go` + `cmd/server_engine.go` — mount credentials admin + gateway routes
- `pkg/server/ui/dist/manage/index.html` — add Credentials nav link
- `pkg/server/ui/dist/manage/app.js` — add `#/credentials`, `#/credentials/new`, `#/credentials/{id}` routes
- `pkg/server/ui/dist/manage/style.css` — form styling (minimal)

---

### Task 1: Migration v20 — credentials schema + engine encryption pubkey

Append to `pkg/store/migrations.go` as the next positional element:

```go
`
ALTER TABLE engines ADD COLUMN encryption_pubkey BYTEA;

CREATE TABLE credentials_profiles (
    id            UUID PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id     UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    auth_type     TEXT NOT NULL CHECK (auth_type IN ('ssh-password', 'ssh-key', 'winrm-password', 'bootstrap-admin')),
    matcher       JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_ref    UUID NOT NULL UNIQUE,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_tested_at TIMESTAMPTZ,
    UNIQUE (org_id, name)
);

CREATE INDEX idx_credentials_profiles_org    ON credentials_profiles(org_id);
CREATE INDEX idx_credentials_profiles_engine ON credentials_profiles(engine_id);

CREATE TABLE credential_tests (
    id             UUID PRIMARY KEY,
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id      UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    profile_id     UUID NOT NULL REFERENCES credentials_profiles(id) ON DELETE CASCADE,
    host_ids       UUID[] NOT NULL,
    status         TEXT NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled')),
    error          TEXT,
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ
);

CREATE INDEX idx_credential_tests_engine_queue
    ON credential_tests(engine_id, requested_at)
    WHERE status = 'queued';

CREATE TABLE credential_test_results (
    test_id      UUID NOT NULL REFERENCES credential_tests(id) ON DELETE CASCADE,
    host_id      UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
    success      BOOLEAN NOT NULL,
    latency_ms   INTEGER,
    error        TEXT,
    probed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (test_id, host_id)
);
`,
```

Verify: `make db-up && psql ... -c "\dt credentials_profiles credential_tests credential_test_results"` shows all three, and `\d engines` shows the new `encryption_pubkey` column.

Commit: `feat(store): credentials_profiles + credential_tests + engine.encryption_pubkey (v20)`

---

### Task 2: Engine-side encryption keypair + submission

**Files:**
- Create: `pkg/engine/crypto/sealedbox.go` + test
- Modify: `pkg/engine/client/client.go` — add `SubmitEncryptionPubkey`
- Modify: `cmd/triton-engine/main.go` — on startup, generate or load X25519 keypair, submit pubkey to portal
- Modify: `pkg/server/engine/handlers_gateway.go` — add handler for `POST /api/v1/engine/encryption-pubkey` (mTLS)
- Modify: `pkg/server/engine/store.go` + `postgres.go` — add `SetEncryptionPubkey`

**Crypto scheme:** X25519 + HKDF-SHA256 + ChaCha20-Poly1305. Sealed-box-style one-way: sender derives an ephemeral keypair, does ECDH with recipient's static pubkey, HKDF-expands to 32-byte AEAD key, encrypts. Ciphertext layout: `ephemeral_pubkey (32) || nonce (12) || ciphertext_and_tag`.

`pkg/engine/crypto/sealedbox.go`:

```go
// Package crypto provides sealed-box style encryption: a sender encrypts
// to a recipient's static X25519 public key without needing a reply channel.
// Used for browser→engine credential delivery and any other portal→engine
// one-way secret hand-off.
package crypto

import (
    "crypto/ecdh"
    "crypto/rand"
    "fmt"
    "io"

    "golang.org/x/crypto/chacha20poly1305"
    "golang.org/x/crypto/hkdf"
)

// SealedBoxOverhead is the number of bytes added to the plaintext by Seal:
// 32 (ephemeral pub) + 12 (nonce) + 16 (Poly1305 tag).
const SealedBoxOverhead = 32 + 12 + 16

const hkdfInfo = "triton/sealedbox/v1"

// GenerateKeypair returns a fresh X25519 static keypair.
func GenerateKeypair() (priv *ecdh.PrivateKey, pub []byte, err error) {
    c := ecdh.X25519()
    priv, err = c.GenerateKey(rand.Reader)
    if err != nil {
        return nil, nil, err
    }
    return priv, priv.PublicKey().Bytes(), nil
}

// Seal encrypts plaintext to recipientPub. Output layout: ephPub || nonce || ct.
func Seal(recipientPub []byte, plaintext []byte) ([]byte, error) {
    c := ecdh.X25519()
    recipient, err := c.NewPublicKey(recipientPub)
    if err != nil {
        return nil, fmt.Errorf("parse recipient pubkey: %w", err)
    }
    ephPriv, err := c.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }
    shared, err := ephPriv.ECDH(recipient)
    if err != nil {
        return nil, err
    }
    key, err := deriveKey(shared, ephPriv.PublicKey().Bytes(), recipientPub)
    if err != nil {
        return nil, err
    }
    aead, err := chacha20poly1305.New(key)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    ct := aead.Seal(nil, nonce, plaintext, nil)
    out := make([]byte, 0, 32+len(nonce)+len(ct))
    out = append(out, ephPriv.PublicKey().Bytes()...)
    out = append(out, nonce...)
    out = append(out, ct...)
    return out, nil
}

// Open decrypts a sealed box using the recipient's static private key.
func Open(recipientPriv *ecdh.PrivateKey, sealed []byte) ([]byte, error) {
    if len(sealed) < 32+12+16 {
        return nil, fmt.Errorf("sealed box too short")
    }
    ephPub := sealed[:32]
    nonce := sealed[32:44]
    ct := sealed[44:]

    c := ecdh.X25519()
    eph, err := c.NewPublicKey(ephPub)
    if err != nil {
        return nil, err
    }
    shared, err := recipientPriv.ECDH(eph)
    if err != nil {
        return nil, err
    }
    key, err := deriveKey(shared, ephPub, recipientPriv.PublicKey().Bytes())
    if err != nil {
        return nil, err
    }
    aead, err := chacha20poly1305.New(key)
    if err != nil {
        return nil, err
    }
    return aead.Open(nil, nonce, ct, nil)
}

func deriveKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
    salt := append(append([]byte{}, ephPub...), recipientPub...)
    r := hkdf.New(newSHA256, shared, salt, []byte(hkdfInfo))
    key := make([]byte, 32)
    if _, err := io.ReadFull(r, key); err != nil {
        return nil, err
    }
    return key, nil
}

var newSHA256 = sha256New // expose for testing via package variable; see hash.go

// pkg/engine/crypto/hash.go:
//   package crypto
//   import "crypto/sha256"
//   import "hash"
//   func sha256New() hash.Hash { return sha256.New() }
```

Tests:
- `TestSealedBox_RoundTrip` — generate keypair, Seal a 100-byte message, Open, assert equality
- `TestSealedBox_WrongRecipient_Fails` — gen two keypairs, Seal to A, Open with B → error
- `TestSealedBox_TamperedCiphertext_Fails` — flip a byte in the ct portion, Open → error
- `TestSealedBox_EmptyPlaintext_RoundTrips`

Client method in `pkg/engine/client/client.go`:

```go
// SubmitEncryptionPubkey registers the engine's X25519 public key with the
// portal. Idempotent — portal stores the most recent submission.
func (c *Client) SubmitEncryptionPubkey(ctx context.Context, pubkey []byte) error {
    body := map[string]string{"pubkey": base64.StdEncoding.EncodeToString(pubkey)}
    return c.postJSON(ctx, "/api/v1/engine/encryption-pubkey", body, nil)
}
```

Engine `main.go` flow:
1. Generate keypair on startup (in-memory, no on-disk private key persistence — on restart we generate a new one and re-submit)
2. After enroll succeeds, call `SubmitEncryptionPubkey`
3. Hold the private key in a singleton accessible to the credential handler

Store extension in `pkg/server/engine/postgres.go`:

```go
func (s *PostgresStore) SetEncryptionPubkey(ctx context.Context, engineID uuid.UUID, pubkey []byte) error {
    _, err := s.pool.Exec(ctx,
        `UPDATE engines SET encryption_pubkey = $2 WHERE id = $1`,
        engineID, pubkey,
    )
    return err
}

func (s *PostgresStore) GetEncryptionPubkey(ctx context.Context, engineID uuid.UUID) ([]byte, error) {
    var pk []byte
    err := s.pool.QueryRow(ctx,
        `SELECT encryption_pubkey FROM engines WHERE id = $1`,
        engineID,
    ).Scan(&pk)
    return pk, err
}
```

Gateway handler in `pkg/server/engine/handlers_gateway.go`:

```go
func (h *GatewayHandlers) SubmitEncryptionPubkey(w http.ResponseWriter, r *http.Request) {
    eng := EngineFromContext(r.Context())
    if eng == nil {
        http.Error(w, "missing engine context", http.StatusInternalServerError)
        return
    }
    var body struct{ Pubkey string `json:"pubkey"` }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    raw, err := base64.StdEncoding.DecodeString(body.Pubkey)
    if err != nil || len(raw) != 32 {
        http.Error(w, "invalid pubkey", http.StatusBadRequest)
        return
    }
    if err := h.Store.SetEncryptionPubkey(r.Context(), eng.ID, raw); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}
```

Mount in `MountGatewayRoutes`: `r.Post("/encryption-pubkey", h.SubmitEncryptionPubkey)`.

Commit: `feat(engine): X25519 sealed-box primitive + pubkey registration handshake`

---

### Task 3: Credentials domain types + Store + matcher

**Files:**
- Create: `pkg/server/credentials/types.go`, `store.go`, `postgres.go`, `postgres_test.go`
- Create: `pkg/server/credentials/matcher.go`, `matcher_test.go`

Types:

```go
package credentials

import (
    "encoding/json"
    "time"

    "github.com/google/uuid"
)

type AuthType string

const (
    AuthSSHPassword    AuthType = "ssh-password"
    AuthSSHKey         AuthType = "ssh-key"
    AuthWinRMPassword  AuthType = "winrm-password"
    AuthBootstrapAdmin AuthType = "bootstrap-admin"
)

type Matcher struct {
    GroupIDs []uuid.UUID       `json:"group_ids,omitempty"`
    OS       string            `json:"os,omitempty"`
    CIDR     string            `json:"cidr,omitempty"`
    Tags     map[string]string `json:"tags,omitempty"`
}

type Profile struct {
    ID           uuid.UUID  `json:"id"`
    OrgID        uuid.UUID  `json:"org_id"`
    EngineID     uuid.UUID  `json:"engine_id"`
    Name         string     `json:"name"`
    AuthType     AuthType   `json:"auth_type"`
    Matcher      Matcher    `json:"matcher"`
    SecretRef    uuid.UUID  `json:"secret_ref"`
    CreatedBy    uuid.UUID  `json:"created_by"`
    CreatedAt    time.Time  `json:"created_at"`
    LastTestedAt *time.Time `json:"last_tested_at,omitempty"`
}

// TestJob is a pending "test credentials against N hosts" job.
type TestJob struct {
    ID          uuid.UUID  `json:"id"`
    OrgID       uuid.UUID  `json:"org_id"`
    EngineID    uuid.UUID  `json:"engine_id"`
    ProfileID   uuid.UUID  `json:"profile_id"`
    HostIDs     []uuid.UUID `json:"host_ids"`
    Status      string     `json:"status"`
    Error       string     `json:"error,omitempty"`
    RequestedAt time.Time  `json:"requested_at"`
    ClaimedAt   *time.Time `json:"claimed_at,omitempty"`
    CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type TestResult struct {
    TestID    uuid.UUID `json:"test_id"`
    HostID    uuid.UUID `json:"host_id"`
    Success   bool      `json:"success"`
    LatencyMs int       `json:"latency_ms"`
    Error     string    `json:"error,omitempty"`
    ProbedAt  time.Time `json:"probed_at"`
}
```

Store interface:

```go
type Store interface {
    // Admin-side profile CRUD
    CreateProfile(ctx context.Context, p Profile) (Profile, error)
    GetProfile(ctx context.Context, orgID, id uuid.UUID) (Profile, error)
    ListProfiles(ctx context.Context, orgID uuid.UUID) ([]Profile, error)
    DeleteProfile(ctx context.Context, orgID, id uuid.UUID) error

    // Test jobs
    CreateTestJob(ctx context.Context, t TestJob) (TestJob, error)
    GetTestJob(ctx context.Context, orgID, id uuid.UUID) (TestJob, error)
    ListTestResults(ctx context.Context, testID uuid.UUID) ([]TestResult, error)
    ClaimNextTest(ctx context.Context, engineID uuid.UUID) (TestJob, bool, error)
    InsertTestResults(ctx context.Context, results []TestResult) error
    FinishTestJob(ctx context.Context, id uuid.UUID, status, errMsg string) error
    ReclaimStaleTests(ctx context.Context, cutoff time.Time) error

    // Engine encryption pubkey lookup (for admin encryption-pubkey endpoint)
    GetEngineEncryptionPubkey(ctx context.Context, engineID uuid.UUID) ([]byte, error)
}
```

PostgresStore follows Phase 3 discovery patterns. `ClaimNextTest` uses `FOR UPDATE SKIP LOCKED`. `FinishTestJob` uses the same terminal-state guard as Phase 3's `FinishJob` fix. `GetEngineEncryptionPubkey` delegates to a `SELECT encryption_pubkey FROM engines WHERE id = $1`.

`matcher.go` — stand-alone pure function:

```go
// ResolveMatcher returns the subset of candidate hosts that match the
// profile's matcher. Pure function — no DB access. Callers fetch hosts
// first (e.g., via inventory.Store.ListHosts) and pass them in.
func ResolveMatcher(m Matcher, hosts []HostSummary) []uuid.UUID {
    out := []uuid.UUID{}
    for _, h := range hosts {
        if !matchOne(m, h) { continue }
        out = append(out, h.ID)
    }
    return out
}

type HostSummary struct {
    ID        uuid.UUID
    GroupID   uuid.UUID
    Address   net.IP
    OS        string
    TagKVs    map[string]string
}

func matchOne(m Matcher, h HostSummary) bool {
    if len(m.GroupIDs) > 0 {
        in := false
        for _, g := range m.GroupIDs { if g == h.GroupID { in = true; break } }
        if !in { return false }
    }
    if m.OS != "" && m.OS != h.OS { return false }
    if m.CIDR != "" {
        _, cidr, err := net.ParseCIDR(m.CIDR)
        if err != nil || !cidr.Contains(h.Address) { return false }
    }
    for k, v := range m.Tags {
        if h.TagKVs[k] != v { return false }
    }
    return true
}
```

Matcher tests cover: empty matcher matches all, group filter, OS filter, CIDR filter, single tag filter, multi-tag AND semantics, CIDR with invalid syntax returns no matches (not an error).

Integration tests for PostgresStore (in `postgres_test.go`, `//go:build integration`):
- `TestCredentials_CreateListDelete` — round-trip
- `TestCredentials_UniqueNamePerOrg_Conflict`
- `TestCredentials_CreateTestJob_AndClaim`
- `TestCredentials_FinishTestJob_TerminalGuard` — finish twice, second returns sentinel `ErrTestAlreadyTerminal`
- `TestCredentials_ReclaimStaleTests`
- `TestCredentials_MatcherJSONBRoundtrip` — create profile with complex matcher, Get back, assert JSON equal

Commit in two batches:
- `feat(credentials): domain types, Store interface, matcher resolver`
- `feat(credentials): PostgresStore with single-claim test jobs + terminal guard`

---

### Task 4: Admin handlers — profile CRUD + test probe + encryption-pubkey endpoint

**Files:**
- Create: `pkg/server/credentials/handlers_admin.go`, `handlers_test.go`, `routes.go`

Endpoints (under `/api/v1/manage/credentials/*`, JWT-auth):

- `GET /engines/{engine_id}/encryption-pubkey` — public within the tenant; returns base64 pubkey. 404 if engine has no pubkey yet.

  **Path decision:** put this under `/api/v1/manage/engines/{id}/encryption-pubkey` instead of under credentials — it's an engine property, not a credential. Add a mount in `pkg/server/engine/routes.go` or a tiny shim in the credentials routes that calls the engine store. **Pick: extend engine admin routes** to keep engine-related data in one place.

  So: `GET /api/v1/manage/engines/{id}/encryption-pubkey` — returns `{"pubkey": "base64..."}`.

- `POST /api/v1/manage/credentials/` — body `{name, auth_type, engine_id, matcher, encrypted_secret (base64)}`. Creates profile row, forwards ciphertext to engine via a gateway-side push (see Task 5). Returns profile JSON.
- `GET /api/v1/manage/credentials/` — list
- `GET /api/v1/manage/credentials/{id}` — get
- `DELETE /api/v1/manage/credentials/{id}` — delete profile + tell engine to purge secret
- `POST /api/v1/manage/credentials/{id}/test` — body `{max_hosts: 3}` — portal resolves matcher, picks up to N hosts, creates test job for the owning engine. Returns test job.
- `GET /api/v1/manage/credentials/tests/{id}` — get test job + results

**Flow for `POST /credentials/`:**

1. Decode body. Validate auth_type is one of the four. Validate engine_id belongs to org.
2. Check engine has a registered encryption pubkey — if not, 409 "engine encryption key not yet registered".
3. Generate `secret_ref = uuid.v7`. Insert profile row with matcher as JSONB.
4. Forward the ciphertext to the engine by **inserting a pending secret delivery record** — see Task 5. Alternative: portal directly calls a credentials-push API on the engine, but since portal→engine is pull-only (mTLS gateway is always engine-initiated), we need a pull mechanism too.

**Design decision:** treat secret delivery as its own job type. Add a `credential_deliveries` table (or reuse `credential_tests` by adding a `kind` column — cleaner to add a dedicated table).

Actually — **simpler**: embed the ciphertext directly on the profile row as a new nullable column `pending_ciphertext BYTEA`, and the engine polls for any credential_profiles where `engine_id = self AND pending_ciphertext IS NOT NULL`, fetches + decrypts + stores + calls "clear pending" to NULL the column. This avoids a second table for deliveries.

**Update migration v20:** add `pending_ciphertext BYTEA` column to `credentials_profiles`.

```sql
-- Adjust migration v20:
ALTER TABLE credentials_profiles ADD COLUMN pending_ciphertext BYTEA;
```

Actually since migration v20 is new in this phase, amend the migration definition in Task 1 to include `pending_ciphertext BYTEA` rather than issuing a v21. Re-open Task 1 migration for this.

Same pattern for delete: add column `pending_delete BOOLEAN NOT NULL DEFAULT FALSE`. On delete, portal sets the flag; engine polls, sees flag, purges secret from keystore, then portal removes the row (or engine calls an "ack-delete" gateway endpoint).

**Wait — simpler still:** move secret delivery to a `credential_deliveries` table after all. Cleaner separation, easier to reason about transitions. Add to migration v20:

```sql
CREATE TABLE credential_deliveries (
    id              UUID PRIMARY KEY,
    profile_id      UUID NOT NULL REFERENCES credentials_profiles(id) ON DELETE CASCADE,
    engine_id       UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('push', 'delete')),
    ciphertext      BYTEA,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'claimed', 'acked', 'failed')),
    error           TEXT,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at      TIMESTAMPTZ,
    acked_at        TIMESTAMPTZ
);

CREATE INDEX idx_credential_deliveries_engine_queue
    ON credential_deliveries(engine_id, requested_at)
    WHERE status = 'queued';
```

**Amend Task 1 to include this table.** The admin `CreateProfile` handler inserts the profile row AND a `credential_deliveries` row of kind=`push` with the ciphertext, in a single transaction. `DeleteProfile` inserts a kind=`delete` row (without ciphertext) and then lets the engine ack before the portal physically removes the profile, OR deletes the profile immediately and relies on cascade to clean up. **Simpler: delete immediately; rely on `credential_deliveries` kind=`delete` retained after profile cascade deletion** — but FK cascade removes the delete row too. So use a soft-delete or separate lifecycle.

**Final choice (keeping v20 small):**
- Profile is created directly; a credential_deliveries row of kind=push is added in the same tx. Engine polls, fetches ciphertext, stores, acks.
- Profile delete: portal inserts a `credential_deliveries` row of kind=delete with `profile_id = the_id` **before** deleting the profile row, and commits both in a single tx. FK on the delivery uses `ON DELETE RESTRICT` so the delivery can outlive the profile... no wait, if we want delivery row to survive profile deletion, the FK should be removed or SET NULL.

**Simplest viable:**
1. Delivery row has `profile_id` but **no FK constraint** (or `ON DELETE SET NULL` with the column nullable). Engine uses `secret_ref` to identify which keystore entry to purge (portal includes `secret_ref` in the delivery payload, not just profile_id).
2. Portal sends delivery with `{kind: "delete", secret_ref}` — engine purges by secret_ref.

Add `secret_ref UUID NOT NULL` to `credential_deliveries`. Drop the FK on `profile_id` (just index). That way deletes survive profile removal.

**Final migration v20 — merge everything in Task 1:**

```sql
ALTER TABLE engines ADD COLUMN encryption_pubkey BYTEA;

CREATE TABLE credentials_profiles (
    id            UUID PRIMARY KEY,
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id     UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    auth_type     TEXT NOT NULL CHECK (auth_type IN ('ssh-password', 'ssh-key', 'winrm-password', 'bootstrap-admin')),
    matcher       JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_ref    UUID NOT NULL UNIQUE,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_tested_at TIMESTAMPTZ,
    UNIQUE (org_id, name)
);

CREATE INDEX idx_credentials_profiles_org    ON credentials_profiles(org_id);
CREATE INDEX idx_credentials_profiles_engine ON credentials_profiles(engine_id);

CREATE TABLE credential_deliveries (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id       UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    profile_id      UUID,    -- nullable because delete-kind can outlive the profile
    secret_ref      UUID NOT NULL,
    auth_type       TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('push', 'delete')),
    ciphertext      BYTEA,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'claimed', 'acked', 'failed')),
    error           TEXT,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at      TIMESTAMPTZ,
    acked_at        TIMESTAMPTZ
);

CREATE INDEX idx_credential_deliveries_engine_queue
    ON credential_deliveries(engine_id, requested_at)
    WHERE status = 'queued';

CREATE TABLE credential_tests (
    id             UUID PRIMARY KEY,
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id      UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    profile_id     UUID NOT NULL REFERENCES credentials_profiles(id) ON DELETE CASCADE,
    host_ids       UUID[] NOT NULL,
    status         TEXT NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled')),
    error          TEXT,
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at     TIMESTAMPTZ,
    completed_at   TIMESTAMPTZ
);

CREATE INDEX idx_credential_tests_engine_queue
    ON credential_tests(engine_id, requested_at)
    WHERE status = 'queued';

CREATE TABLE credential_test_results (
    test_id      UUID NOT NULL REFERENCES credential_tests(id) ON DELETE CASCADE,
    host_id      UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
    success      BOOLEAN NOT NULL,
    latency_ms   INTEGER,
    error        TEXT,
    probed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (test_id, host_id)
);
```

**Extend Store interface with delivery methods:**

```go
CreateDelivery(ctx context.Context, d Delivery) (Delivery, error)
ClaimNextDelivery(ctx context.Context, engineID uuid.UUID) (Delivery, bool, error)
AckDelivery(ctx context.Context, id uuid.UUID, errMsg string) error
ReclaimStaleDeliveries(ctx context.Context, cutoff time.Time) error
```

Where `Delivery` is:

```go
type DeliveryKind string
const (
    DeliveryPush   DeliveryKind = "push"
    DeliveryDelete DeliveryKind = "delete"
)

type Delivery struct {
    ID         uuid.UUID
    OrgID      uuid.UUID
    EngineID   uuid.UUID
    ProfileID  *uuid.UUID
    SecretRef  uuid.UUID
    AuthType   AuthType
    Kind       DeliveryKind
    Ciphertext []byte
    Status     string
}
```

**Handler for `POST /credentials/`:**

```go
func (h *AdminHandlers) CreateProfile(w http.ResponseWriter, r *http.Request) {
    var body struct {
        Name            string    `json:"name"`
        AuthType        AuthType  `json:"auth_type"`
        EngineID        uuid.UUID `json:"engine_id"`
        Matcher         Matcher   `json:"matcher"`
        EncryptedSecret string    `json:"encrypted_secret"` // base64
    }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil { /* 400 */ }
    ct, err := base64.StdEncoding.DecodeString(body.EncryptedSecret)
    if err != nil || len(ct) < SealedBoxOverhead { /* 400 */ }

    claims := server.ClaimsFromContext(r.Context())
    orgID, _ := uuid.Parse(claims.Org)
    userID, _ := uuid.Parse(claims.Sub)

    // Verify engine belongs to org and has pubkey registered.
    pubkey, err := h.Store.GetEngineEncryptionPubkey(r.Context(), body.EngineID)
    if err != nil || len(pubkey) == 0 {
        http.Error(w, "engine has not registered encryption key; wait for it to come online", http.StatusConflict)
        return
    }

    profile := Profile{
        ID:        uuid.Must(uuid.NewV7()),
        OrgID:     orgID,
        EngineID:  body.EngineID,
        Name:      body.Name,
        AuthType:  body.AuthType,
        Matcher:   body.Matcher,
        SecretRef: uuid.Must(uuid.NewV7()),
        CreatedBy: userID,
    }
    // Single tx: insert profile + insert delivery row.
    if err := h.Store.CreateProfileWithDelivery(r.Context(), profile, ct); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    h.Audit.Record(r.Context(), "credentials.profile.create", profile.ID.String(),
        map[string]any{"name": profile.Name, "auth_type": string(profile.AuthType)})
    writeJSON(w, http.StatusCreated, profile)
}
```

`Store.CreateProfileWithDelivery` does both inserts atomically.

**DeleteProfile:**

```go
// Atomic: delete profile row + enqueue a delivery row of kind='delete'.
// The delete delivery survives because it has no FK back to profile_id (nullable).
func (h *AdminHandlers) DeleteProfile(w http.ResponseWriter, r *http.Request) {
    // Resolve orgID + id
    // Get profile to capture engine_id + secret_ref + auth_type
    // h.Store.DeleteProfileWithDelivery(ctx, orgID, id)
}
```

`Store.DeleteProfileWithDelivery` runs `DELETE FROM credentials_profiles ...` + `INSERT INTO credential_deliveries (... kind='delete', ciphertext=NULL, secret_ref, auth_type ...)` in one tx.

**Test endpoint `POST /credentials/{id}/test`:**

```go
func (h *AdminHandlers) StartTest(w http.ResponseWriter, r *http.Request) {
    // Resolve profile
    // Fetch host summaries via h.InventoryStore.ListHostsForMatcher
    //   (new method: SELECT hosts joined with tags, returning HostSummary-shaped rows)
    // Call ResolveMatcher(profile.Matcher, hosts) → []uuid.UUID
    // Cap at body.MaxHosts (default 3)
    // Call h.Store.CreateTestJob
    // Return job
}
```

New inventory method `ListHostSummaries(ctx, orgID) ([]credentials.HostSummary, error)` joins hosts with tags.

- [ ] Handler tests covering: create happy-path, engine without pubkey → 409, matcher invalid → 400, officer cannot create → 403, owner can delete → 204, officer cannot delete → 403, start test picks up to N hosts + returns job, list profiles scoped to org.

Commit: `feat(credentials): admin handlers — profile CRUD + test probe`

---

### Task 5: Gateway handlers — credential delivery + test worker poll/submit

**Endpoints (under `/api/v1/engine/credentials/*` and `/api/v1/engine/credential-tests/*`, mTLS):**

- `GET /credentials/deliveries/poll` — long-poll for next queued delivery (push or delete)
- `POST /credentials/deliveries/{id}/ack` — body `{error: "..."}` — engine acks success or reports failure
- `GET /credential-tests/poll` — long-poll for next queued test job
- `POST /credential-tests/{id}/submit` — body `{results: [...], error: "..."}` — submit per-host results

Pattern mirrors Phase 3 discovery gateway handlers. Use the same `engine.EngineFromContext` for tenant scoping.

For delivery poll response, the engine needs enough info to decrypt + store:

```json
{
  "id": "uuid",
  "kind": "push|delete",
  "secret_ref": "uuid",
  "profile_id": "uuid",
  "auth_type": "ssh-password",
  "ciphertext_b64": "..."  // present only for kind=push
}
```

Commit: `feat(credentials): gateway handlers — delivery poll/ack + test poll/submit`

---

### Task 6: Engine-side keystore (SQLite)

**Files:**
- Create: `pkg/engine/keystore/keystore.go`, `keystore_test.go`

SQLite-backed store at `$TRITON_ENGINE_KEYSTORE_PATH` (default `/var/lib/triton-engine/keystore.db`). Schema:

```sql
CREATE TABLE IF NOT EXISTS secrets (
    secret_ref TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    auth_type  TEXT NOT NULL,
    payload    BLOB NOT NULL,  -- ChaCha20-Poly1305 ciphertext
    nonce      BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
```

```go
type Keystore struct {
    db        *sql.DB
    masterKey []byte // 32 bytes, from env TRITON_ENGINE_KEYSTORE_KEY
}

func Open(path string, masterKey []byte) (*Keystore, error)
func (k *Keystore) Put(ctx context.Context, secretRef, profileID, authType string, plaintext []byte) error
func (k *Keystore) Get(ctx context.Context, secretRef string) (authType string, plaintext []byte, err error)
func (k *Keystore) Delete(ctx context.Context, secretRef string) error
func (k *Keystore) List(ctx context.Context) ([]SecretMeta, error)
```

`Put` re-encrypts with ChaCha20-Poly1305 using the master key + fresh random 12-byte nonce. `Get` decrypts. Master key comes from env `TRITON_ENGINE_KEYSTORE_KEY` (hex 64). If unset, engine logs WARNING and derives a key from the engine's X25519 private key material (for dev — real deployments set the env var).

Tests cover: round-trip put/get, delete, idempotent put (overwrites), tamper detection (flip a byte in payload).

Use `modernc.org/sqlite` to stay CGO-free (matches the rest of the codebase which avoids cgo).

Commit: `feat(engine): SQLite-backed keystore with ChaCha20-Poly1305 at-rest encryption`

---

### Task 7: Engine-side credential handler + test worker

**Files:**
- Create: `pkg/engine/credentials/handler.go`, `probe.go`, `test_worker.go` + tests

`Handler` polls `/credentials/deliveries/poll`, processes each:

```go
type Handler struct {
    Client     *client.Client
    Keystore   *keystore.Keystore
    PrivateKey *ecdh.PrivateKey // engine's X25519 static private
}

func (h *Handler) Run(ctx context.Context) {
    for {
        if ctx.Err() != nil { return }
        d, err := h.Client.PollCredentialDelivery(ctx)
        if err != nil { /* backoff */ continue }
        if d == nil { continue }

        var ackErr string
        if d.Kind == "push" {
            plaintext, err := trcrypto.Open(h.PrivateKey, d.Ciphertext)
            if err != nil {
                ackErr = "decrypt failed: " + err.Error()
            } else {
                if err := h.Keystore.Put(ctx, d.SecretRef, d.ProfileID, d.AuthType, plaintext); err != nil {
                    ackErr = "keystore put failed: " + err.Error()
                }
                // Zero out plaintext
                for i := range plaintext { plaintext[i] = 0 }
            }
        } else { // delete
            if err := h.Keystore.Delete(ctx, d.SecretRef); err != nil {
                ackErr = "keystore delete failed: " + err.Error()
            }
        }
        _ = h.Client.AckCredentialDelivery(ctx, d.ID, ackErr)
    }
}
```

`probe.go` — runs SSH or WinRM probe given creds + host:

```go
type ProbeResult struct {
    Success   bool
    LatencyMs int
    Error     string
}

func (p *Prober) Probe(ctx context.Context, authType string, secret map[string]string, host HostTarget) ProbeResult
```

For SSH: `ssh.Dial("tcp", host+":22", cfg)` with cfg built from auth_type (password or key). Close on success. Latency from time before Dial to after handshake.

For WinRM: use `masterzen/winrm` or `github.com/packer-community/winrmcp`. MVP can skip WinRM probes with a "WinRM probe not implemented" error — document.

For bootstrap-admin: treat as SSH password probe.

`test_worker.go` — polling loop analogous to discovery worker. Polls `/credential-tests/poll`, resolves each host_id to an `HostTarget` (engine needs the address + port — portal should include these in the test-job payload). For each host, runs `Prober.Probe` with the secret looked up from Keystore by profile_id → secret_ref. Collects per-host results, submits.

**Update test-job wire format** to include resolved host targets:

```json
{
  "id": "...",
  "profile_id": "...",
  "secret_ref": "...",
  "auth_type": "ssh-password",
  "hosts": [
    {"id": "...", "address": "10.0.0.1", "port": 22}
  ]
}
```

Portal-side `ClaimNextTest` query must join `inventory_hosts` and return address+port. Minor Store interface change.

Commit (two commits recommended):
- `feat(engine): credential delivery handler — decrypt + keystore + ack`
- `feat(engine): credential test worker + SSH probe`

---

### Task 8: Client extension

**File:** `pkg/engine/client/client.go`

Add:
- `SubmitEncryptionPubkey` (Task 2)
- `PollCredentialDelivery(ctx) (*Delivery, error)` — returns nil on 204
- `AckCredentialDelivery(ctx, id, errMsg) error`
- `PollCredentialTest(ctx) (*TestJob, error)`
- `SubmitCredentialTest(ctx, testID, results, errMsg) error`

Tests with httptest (TLS server + InsecureSkipVerify). Pattern matches Phase 2 + 3 tests.

Commit: `feat(engine/client): credential delivery + test methods`

---

### Task 9: Loop integration + main.go

**Files:**
- Modify: `pkg/engine/loop/loop.go` — add `CredentialHandler` + `CredentialTestWorker` fields to `Config`; start after enroll
- Modify: `cmd/triton-engine/main.go` — construct keystore, generate X25519 keypair, submit pubkey, construct handlers

```go
// main.go excerpt
ks, err := keystore.Open(os.Getenv("TRITON_ENGINE_KEYSTORE_PATH"), loadMasterKey())
if err != nil { log.Fatal(err) }

priv, pub, err := trcrypto.GenerateKeypair()
if err != nil { log.Fatal(err) }

// After enroll succeeds, client submits pubkey.
// Wire this into loop.Config.OnEnrolled callback.

credHandler := &credentials.Handler{
    Client: c, Keystore: ks, PrivateKey: priv,
}
testWorker := &credentials.TestWorker{
    Client: c, Keystore: ks, Prober: &credentials.Prober{},
}
cfg := loop.Config{
    DiscoveryWorker:          discoveryWorker,
    CredentialHandler:        credHandler,
    CredentialTestWorker:     testWorker,
    OnEnrolled: func(ctx context.Context) {
        _ = c.SubmitEncryptionPubkey(ctx, pub)
    },
}
```

Extend `loop.Config` with `OnEnrolled func(ctx context.Context)` called after the first successful enroll. Loop invokes it right before starting the heartbeat loop and workers.

Commit: `feat(engine): loop wiring — OnEnrolled callback + credential workers`

---

### Task 10: Portal server wiring

**File:** `cmd/server.go`, `cmd/server_engine.go`

Mount admin routes at `/api/v1/manage/credentials/*` (JWT) and `/api/v1/manage/engines/{id}/encryption-pubkey` (JWT). Mount gateway routes at `/api/v1/engine/credentials/*` + `/api/v1/engine/credential-tests/*` on the 8443 mTLS listener.

Also construct and start a `StaleReaper` analogue for credential_tests + credential_deliveries (background sweep every 5min reclaims stale `claimed`/`running` entries older than 15min).

Commit: `feat(server): wire credentials admin + gateway routes + stale reaper`

---

### Task 11: Management UI — credentials page

**Files:**
- Modify: `pkg/server/ui/dist/manage/index.html` — add Credentials nav
- Modify: `pkg/server/ui/dist/manage/app.js` — add routes `#/credentials`, `#/credentials/new`, `#/credentials/{id}`
- Create: `pkg/server/ui/dist/manage/crypto.js`

`crypto.js`:

```javascript
// crypto.js — browser-side X25519 + HKDF + ChaCha20-Poly1305 sealed-box
// matching pkg/engine/crypto/sealedbox.go format.
// Loads @noble/curves + @noble/ciphers from esm.sh (no build step).
import { x25519 } from 'https://esm.sh/@noble/curves@1.7.0/ed25519';
import { hkdf } from 'https://esm.sh/@noble/hashes@1.7.0/hkdf';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.7.0/sha256';
import { chacha20poly1305 } from 'https://esm.sh/@noble/ciphers@1.0.0/chacha';
import { randomBytes } from 'https://esm.sh/@noble/hashes@1.7.0/utils';

export async function sealTo(recipientPubB64, plaintext) {
    const recipientPub = base64Decode(recipientPubB64);
    const ephPriv = x25519.utils.randomPrivateKey();
    const ephPub = x25519.getPublicKey(ephPriv);
    const shared = x25519.getSharedSecret(ephPriv, recipientPub);

    const salt = new Uint8Array(ephPub.length + recipientPub.length);
    salt.set(ephPub, 0);
    salt.set(recipientPub, ephPub.length);

    const key = hkdf(sha256, shared, salt, 'triton/sealedbox/v1', 32);
    const nonce = randomBytes(12);
    const aead = chacha20poly1305(key, nonce);
    const ct = aead.encrypt(plaintext);

    const out = new Uint8Array(ephPub.length + nonce.length + ct.length);
    out.set(ephPub, 0);
    out.set(nonce, ephPub.length);
    out.set(ct, ephPub.length + nonce.length);
    return base64Encode(out);
}

function base64Encode(bytes) { return btoa(String.fromCharCode(...bytes)); }
function base64Decode(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
```

`app.js` additions:

```javascript
import { sealTo } from './crypto.js'; // note: needs <script type="module" src="app.js">

async function renderNewCredential(el) {
    // Fetch engines, groups; render form with:
    //   name, auth_type select, engine select, matcher fields (group_ids multi-select, os select, cidr, tags)
    //   username, password/private_key textarea (auth_type-conditional)
    //   "Create and push" button
    // On submit:
    //   1. Fetch /api/v1/manage/engines/{engine_id}/encryption-pubkey → {pubkey}
    //   2. Build secret plaintext JSON: {username, password} or {username, private_key, passphrase}
    //   3. encoded = new TextEncoder().encode(JSON.stringify(secret))
    //   4. ct = await sealTo(pubkey, encoded)
    //   5. POST /api/v1/manage/credentials/ with {name, auth_type, engine_id, matcher, encrypted_secret: ct}
}
```

**Note:** `app.js` currently loads as a classic script. Changing to ESM (`<script type="module">`) may break other code. Simpler: put credentials-specific code in a new `crypto.js` file and use dynamic import: `const { sealTo } = await import('./crypto.js');`.

Credentials list view, detail view with "Test against N hosts" button → shows per-host results table.

Commit: `feat(ui): credentials management page with in-browser sealed-box encryption`

---

### Task 12: End-to-end + PR + review

- [ ] `go build ./...` clean
- [ ] `make lint` 0 issues
- [ ] Unit tests across `pkg/server/credentials/`, `pkg/engine/crypto/`, `pkg/engine/keystore/`, `pkg/engine/credentials/`, `pkg/engine/client/`
- [ ] Integration tests: `pkg/server/credentials/` + updated `pkg/server/engine/` (for `GetEncryptionPubkey`)
- [ ] Push branch, open PR
- [ ] Dispatch code-reviewer — focus: crypto correctness, race conditions (delivery + test + reaper), SQL injection, matcher CIDR safety, keystore master key handling
- [ ] Address Critical + Important findings

---

## Self-Review Checklist

**Spec coverage:**
- Profile CRUD with matcher ✓
- Browser-side encryption to engine pubkey (never plaintext at portal) ✓
- Engine keystore (AES-256-GCM per spec — **deviation: ChaCha20-Poly1305** — both AEADs with 256-bit keys; ChaCha is more portable + matches Phase 2's crypto choice). Document as deviation.
- "Test against N hosts" probe ✓
- Engine pubkey endpoint ✓

**Placeholder scan:** Version 20 is a real number. TLS config, master key loading, and the noble library CDN URLs are all specific. No TODO placeholders.

**Type consistency:** `AuthType`, `Profile`, `Matcher`, `TestJob`, `TestResult`, `Delivery` consistent across types/store/postgres/handlers. `SecretRef` is `uuid.UUID` on portal side, `string` on engine side (SQLite TEXT), converted at the wire boundary. `Engine.EncryptionPubkey` is `[]byte` everywhere (BYTEA / raw bytes / hex in JSON).

**Explicit deviations from spec:**
1. Engine keystore uses ChaCha20-Poly1305 instead of AES-256-GCM. Both AEADs with 256-bit keys. ChaCha is better on ARM / no-AES-NI, matches Phase 2 choice, removes an import. No security downgrade.
2. Engine X25519 private key is in-memory only — regenerated + re-submitted on every engine restart. Secrets in the keystore are still recoverable because the keystore master key is separate from the X25519 private. But pending `push` deliveries submitted before the restart become undecryptable on the next startup. **Mitigation:** engine ACKs failed push with error — portal flags the delivery as failed, user retries. Document.
3. WinRM probe deferred — returns "not implemented" error with a clear message. SSH probe only for MVP.
4. Secret delivery uses a dedicated `credential_deliveries` table rather than embedding ciphertext on the profile row. Cleaner transitions, clearer audit, one extra table to migrate.

**Risks the implementer might miss:**
- `credential_deliveries.profile_id` is intentionally nullable + FK-less so `delete` rows outlive their profile. Integration tests must assert this survives profile delete.
- Engine must zero-out plaintext after put — Go's GC doesn't zero memory.
- Loop must invoke `OnEnrolled` exactly once. If enroll retries succeed on attempt 3, the callback runs once.
- `crypto.js` uses dynamic ESM import — ensure the portal serves with correct `Content-Type: application/javascript` MIME (esm.sh handles CORS for the noble CDN).
