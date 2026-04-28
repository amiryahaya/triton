# Host Credential Management with HashiCorp Vault — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store SSH and WinRM credentials in HashiCorp Vault; assign them to hosts; auto-pass them to port survey scan jobs and into the scanner subprocess.

**Architecture:** Manage server owns all Vault writes (thin `net/http` wrapper, no SDK). Credentials are host properties — set once, inherited by all port survey jobs. Scanner fetches secrets at runtime via a Worker API proxy; it never holds a Vault token.

**Tech Stack:** Go 1.25, pgx/v5, chi, Vue 3 + Pinia, TypeScript. No Vault SDK — thin `net/http` Vault client only.

---

## File Structure

**New package `pkg/manageserver/credentials/`:**

| File | Responsibility |
|---|---|
| `types.go` | `Credential`, `AuthType` constants, `SecretPayload` |
| `store.go` | `Store` interface + sentinel errors |
| `postgres.go` | Postgres `Store` implementation |
| `vault.go` | Vault KV v2 HTTP client — Write/Read/Delete; AppRole + token auth |
| `vault_test.go` | Unit tests with mock HTTP server |
| `postgres_test.go` | Unit tests for postgres store |
| `handlers_admin.go` | `AdminHandlers`: List, Create, Delete + helpers |
| `handlers_admin_test.go` | Handler unit tests |
| `worker_handler.go` | `WorkerHandler`: GetSecret |
| `worker_handler_test.go` | Worker handler unit tests |
| `routes.go` | Mount admin + worker routes |

**Modified files:**

| File | Change |
|---|---|
| `pkg/managestore/migrations.go` | Migration v16: `manage_credentials` table + alter `manage_hosts` |
| `pkg/manageserver/hosts/types.go` | Add `CredentialsRef *uuid.UUID`, `AccessPort int` |
| `pkg/manageserver/hosts/postgres.go` | `GetHostBasic` returns `accessPort int`; read/write new columns |
| `pkg/manageserver/hosts/handlers_admin.go` | Accept `credentials_ref`, `access_port` in Create/Update |
| `pkg/manageserver/scanjobs/worker_handlers.go` | `HostsStore` interface updated; `WorkerHostResp` gets `AccessPort` |
| `pkg/manageserver/scanjobs/postgres.go` | `EnqueuePortSurvey` pulls `credentials_ref` from host row via JOIN |
| `pkg/manageserver/server.go` | Wire credential routes; pass `VaultClient` from env |
| `pkg/manageserver/config.go` | Add Vault env fields |
| `pkg/scanrunner/scanner.go` | `Target` gets `Credential *CredentialSecret`, `AccessPort int` |
| `pkg/scanrunner/client.go` | Add `CredentialSecret` type + `GetCredential()` method |
| `pkg/scanrunner/runner.go` | Fetch + pass credential when `ClaimResp.CredentialsRef != nil` |

**New frontend files (`web/apps/manage-portal/src/`):**

| File | Responsibility |
|---|---|
| `stores/credentials.ts` | Pinia store: `list`, `create`, `remove` |
| `views/Credentials.vue` | List page: table, delete with in-use guard |
| `views/modals/CredentialForm.vue` | Create modal: dynamic fields per auth type |

**Modified frontend files:**

| File | Change |
|---|---|
| `web/packages/api-client/src/manageServer.types.ts` | Add `Credential`, `CreateCredentialReq`; extend `Host` |
| `web/packages/api-client/src/manageServer.ts` | Add `listCredentials`, `createCredential`, `deleteCredential` |
| `web/apps/manage-portal/src/router.ts` | Add `/inventory/credentials` route |
| `web/apps/manage-portal/src/nav.ts` | Add Credentials nav item under Inventory |
| `web/apps/manage-portal/src/views/modals/HostForm.vue` | Credential picker + Access Port field |
| `web/apps/manage-portal/src/stores/hosts.ts` | Include `credentials_ref`, `access_port` in update |

---

## Task 1: Migration v16 — credentials table + host columns

**Files:**
- Modify: `pkg/managestore/migrations.go`

- [ ] **Step 1: Write the failing test**

Add to `pkg/managestore/postgres_test.go` (or create if absent), build-tagged `integration`:

```go
//go:build integration

func TestMigrationV16_CredentialsSchema(t *testing.T) {
    pool := testPool(t)
    ctx := context.Background()
    if err := Migrate(ctx, pool); err != nil {
        t.Fatalf("migrate: %v", err)
    }
    // manage_credentials table must exist
    var exists bool
    err := pool.QueryRow(ctx,
        `SELECT EXISTS (
           SELECT 1 FROM information_schema.tables
           WHERE table_name = 'manage_credentials'
         )`).Scan(&exists)
    if err != nil || !exists {
        t.Fatalf("manage_credentials table not found: %v", err)
    }
    // manage_hosts must have credentials_ref + access_port
    row := pool.QueryRow(ctx,
        `SELECT credentials_ref, access_port FROM manage_hosts LIMIT 0`)
    if err := row.Scan(); err != nil && !errors.Is(err, pgx.ErrNoRows) {
        t.Fatalf("manage_hosts missing new columns: %v", err)
    }
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
go test -v -tags integration -run TestMigrationV16 ./pkg/managestore/...
```
Expected: FAIL — manage_credentials table not found.

- [ ] **Step 3: Add migration v16 to `pkg/managestore/migrations.go`**

Append after the existing v15 entry:

```go
// Version 16: Host credentials vault — manage_credentials table + credential columns on hosts.
`CREATE TABLE IF NOT EXISTS manage_credentials (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL,
    name        TEXT        NOT NULL,
    auth_type   TEXT        NOT NULL CHECK (auth_type IN ('ssh-key', 'ssh-password', 'winrm-password')),
    vault_path  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_manage_credentials_tenant ON manage_credentials(tenant_id);

ALTER TABLE manage_hosts
  ADD COLUMN IF NOT EXISTS credentials_ref UUID REFERENCES manage_credentials(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS access_port     INT  NOT NULL DEFAULT 22;`,
```

- [ ] **Step 4: Run test to confirm it passes**

```bash
go test -v -tags integration -run TestMigrationV16 ./pkg/managestore/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/managestore/migrations.go pkg/managestore/postgres_test.go
git commit -m "feat(credentials): migration v16 — manage_credentials table + host columns"
```

---

## Task 2: Vault client — Write, Read, Delete; AppRole + token auth

**Files:**
- Create: `pkg/manageserver/credentials/vault.go`
- Create: `pkg/manageserver/credentials/vault_test.go`

- [ ] **Step 1: Write the failing tests**

Create `pkg/manageserver/credentials/vault_test.go`:

```go
package credentials

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func mockVaultServer(t *testing.T) (*httptest.Server, *[]string) {
    t.Helper()
    var calls []string
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        calls = append(calls, r.Method+" "+r.URL.Path)
        switch {
        case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]any{
                "auth": map[string]any{
                    "client_token":   "s.test-token",
                    "lease_duration": 3600,
                },
            })
        case r.Method == http.MethodPut && r.URL.Path == "/v1/secret/data/triton/t1/credentials/c1":
            w.WriteHeader(http.StatusOK)
            json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
        case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/triton/t1/credentials/c1":
            w.Header().Set("Content-Type", "application/json")
            json.NewEncoder(w).Encode(map[string]any{
                "data": map[string]any{
                    "data": map[string]any{
                        "username": "ubuntu",
                        "password": "secret",
                    },
                },
            })
        case r.Method == http.MethodDelete && r.URL.Path == "/v1/secret/data/triton/t1/credentials/c1":
            w.WriteHeader(http.StatusNoContent)
        default:
            http.NotFound(w, r)
        }
    }))
    t.Cleanup(srv.Close)
    return srv, &calls
}

func TestVaultClient_TokenAuth_WriteReadDelete(t *testing.T) {
    srv, calls := mockVaultServer(t)
    c := &VaultClient{
        addr:  srv.URL,
        mount: "secret",
        http:  &http.Client{Timeout: 5 * time.Second},
        token: "s.static",
    }
    ctx := context.Background()
    payload := SecretPayload{Username: "ubuntu", Password: "secret"}
    if err := c.Write(ctx, "triton/t1/credentials/c1", payload); err != nil {
        t.Fatalf("Write: %v", err)
    }
    got, err := c.Read(ctx, "triton/t1/credentials/c1")
    if err != nil {
        t.Fatalf("Read: %v", err)
    }
    if got.Username != "ubuntu" {
        t.Errorf("username: got %q want %q", got.Username, "ubuntu")
    }
    if err := c.Delete(ctx, "triton/t1/credentials/c1"); err != nil {
        t.Fatalf("Delete: %v", err)
    }
    _ = calls
}

func TestVaultClient_AppRoleLogin(t *testing.T) {
    srv, calls := mockVaultServer(t)
    c, err := NewVaultClient(srv.URL, "secret", "", "role-id", "secret-id")
    if err != nil {
        t.Fatalf("NewVaultClient with AppRole: %v", err)
    }
    if c.token != "s.test-token" {
        t.Errorf("token after AppRole login: got %q want %q", c.token, "s.test-token")
    }
    // login call must have been made
    found := false
    for _, call := range *calls {
        if call == "POST /v1/auth/approle/login" {
            found = true
        }
    }
    if !found {
        t.Error("expected AppRole login call")
    }
}

func TestNewVaultClientFromEnv_NilWhenNotConfigured(t *testing.T) {
    c, err := NewVaultClientFromEnv()
    // Neither token nor role_id set → nil client, no error
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if c != nil {
        t.Error("expected nil client when vault not configured")
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test -v -run TestVaultClient ./pkg/manageserver/credentials/...
```
Expected: FAIL — package does not exist yet.

- [ ] **Step 3: Create `pkg/manageserver/credentials/vault.go`**

```go
package credentials

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"
)

// VaultClient is a thin Vault KV v2 HTTP wrapper. No Vault SDK dependency.
type VaultClient struct {
    addr  string
    mount string
    http  *http.Client

    mu          sync.Mutex
    token       string
    tokenExpiry time.Time // zero = never expires (static token mode)

    roleID   string
    secretID string
}

// NewVaultClientFromEnv reads TRITON_VAULT_ADDR, TRITON_VAULT_MOUNT,
// TRITON_VAULT_TOKEN, TRITON_VAULT_ROLE_ID, TRITON_VAULT_SECRET_ID.
// Returns nil (no error) when none are set — callers return 503.
func NewVaultClientFromEnv() (*VaultClient, error) {
    addr := os.Getenv("TRITON_VAULT_ADDR")
    if addr == "" {
        return nil, nil
    }
    mount := os.Getenv("TRITON_VAULT_MOUNT")
    if mount == "" {
        mount = "secret"
    }
    token := os.Getenv("TRITON_VAULT_TOKEN")
    roleID := os.Getenv("TRITON_VAULT_ROLE_ID")
    secretID := os.Getenv("TRITON_VAULT_SECRET_ID")
    return NewVaultClient(addr, mount, token, roleID, secretID)
}

// NewVaultClient constructs a VaultClient. If roleID is set, performs an
// AppRole login immediately. If only token is set, uses it as a static token.
func NewVaultClient(addr, mount, token, roleID, secretID string) (*VaultClient, error) {
    c := &VaultClient{
        addr:     strings.TrimRight(addr, "/"),
        mount:    mount,
        http:     &http.Client{Timeout: 10 * time.Second},
        roleID:   roleID,
        secretID: secretID,
    }
    if roleID != "" {
        if err := c.loginLocked(); err != nil {
            return nil, fmt.Errorf("vault approle login: %w", err)
        }
    } else {
        c.token = token
    }
    return c, nil
}

// loginLocked performs AppRole login. Caller must hold mu OR be in constructor.
func (c *VaultClient) loginLocked() error {
    body, err := json.Marshal(map[string]string{
        "role_id":   c.roleID,
        "secret_id": c.secretID,
    })
    if err != nil {
        return err
    }
    resp, err := c.http.Post(
        c.addr+"/v1/auth/approle/login",
        "application/json",
        bytes.NewReader(body),
    )
    if err != nil {
        return fmt.Errorf("approle login request: %w", err)
    }
    defer resp.Body.Close() //nolint:errcheck
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("approle login: status %d", resp.StatusCode)
    }
    var out struct {
        Auth struct {
            ClientToken   string `json:"client_token"`
            LeaseDuration int    `json:"lease_duration"`
        } `json:"auth"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return fmt.Errorf("decode approle login response: %w", err)
    }
    c.token = out.Auth.ClientToken
    if out.Auth.LeaseDuration > 0 {
        c.tokenExpiry = time.Now().Add(time.Duration(out.Auth.LeaseDuration) * time.Second)
    }
    return nil
}

func (c *VaultClient) authHeader() (string, error) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.roleID != "" && !c.tokenExpiry.IsZero() && time.Now().After(c.tokenExpiry) {
        if err := c.loginLocked(); err != nil {
            return "", fmt.Errorf("vault token renewal: %w", err)
        }
    }
    return c.token, nil
}

func (c *VaultClient) doReq(ctx context.Context, method, urlPath string, body any) (*http.Response, error) {
    tok, err := c.authHeader()
    if err != nil {
        return nil, err
    }
    var r io.Reader
    if body != nil {
        b, err := json.Marshal(body)
        if err != nil {
            return nil, err
        }
        r = bytes.NewReader(b)
    }
    req, err := http.NewRequestWithContext(ctx, method, c.addr+urlPath, r)
    if err != nil {
        return nil, err
    }
    req.Header.Set("X-Vault-Token", tok)
    if body != nil {
        req.Header.Set("Content-Type", "application/json")
    }
    return c.http.Do(req)
}

// kvPath returns the /v1/{mount}/data/{path} URL suffix.
func (c *VaultClient) kvPath(path string) string {
    return fmt.Sprintf("/v1/%s/data/%s", c.mount, path)
}

// Write stores a SecretPayload at the given KV v2 path.
func (c *VaultClient) Write(ctx context.Context, path string, payload SecretPayload) error {
    resp, err := c.doReq(ctx, http.MethodPut, c.kvPath(path), map[string]any{"data": payload})
    if err != nil {
        return fmt.Errorf("vault write: %w", err)
    }
    defer resp.Body.Close() //nolint:errcheck
    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
        return fmt.Errorf("vault write: status %d", resp.StatusCode)
    }
    return nil
}

// Read fetches the latest version of a SecretPayload.
func (c *VaultClient) Read(ctx context.Context, path string) (SecretPayload, error) {
    resp, err := c.doReq(ctx, http.MethodGet, c.kvPath(path), nil)
    if err != nil {
        return SecretPayload{}, fmt.Errorf("vault read: %w", err)
    }
    defer resp.Body.Close() //nolint:errcheck
    if resp.StatusCode == http.StatusNotFound {
        return SecretPayload{}, fmt.Errorf("vault read: not found")
    }
    if resp.StatusCode != http.StatusOK {
        return SecretPayload{}, fmt.Errorf("vault read: status %d", resp.StatusCode)
    }
    var out struct {
        Data struct {
            Data SecretPayload `json:"data"`
        } `json:"data"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return SecretPayload{}, fmt.Errorf("vault read decode: %w", err)
    }
    return out.Data.Data, nil
}

// Delete removes the latest version of the secret at path.
func (c *VaultClient) Delete(ctx context.Context, path string) error {
    resp, err := c.doReq(ctx, http.MethodDelete, c.kvPath(path), nil)
    if err != nil {
        return fmt.Errorf("vault delete: %w", err)
    }
    defer resp.Body.Close() //nolint:errcheck
    if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
        return fmt.Errorf("vault delete: status %d", resp.StatusCode)
    }
    return nil
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
go test -v -run TestVaultClient ./pkg/manageserver/credentials/...
```
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/credentials/vault.go pkg/manageserver/credentials/vault_test.go
git commit -m "feat(credentials): VaultClient — KV v2 Write/Read/Delete, AppRole + token auth"
```

---

## Task 3: Types, Store interface, and Postgres implementation

**Files:**
- Create: `pkg/manageserver/credentials/types.go`
- Create: `pkg/manageserver/credentials/store.go`
- Create: `pkg/manageserver/credentials/postgres.go`
- Create: `pkg/manageserver/credentials/postgres_test.go`

- [ ] **Step 1: Create `types.go`**

```go
package credentials

import (
    "time"

    "github.com/google/uuid"
)

type AuthType string

const (
    AuthTypeSSHKey      AuthType = "ssh-key"
    AuthTypeSSHPassword AuthType = "ssh-password"
    AuthTypeWinRM       AuthType = "winrm-password"
)

// Credential is the DB metadata row. Secret material never appears here.
type Credential struct {
    ID         uuid.UUID `json:"id"`
    TenantID   uuid.UUID `json:"tenant_id"`
    Name       string    `json:"name"`
    AuthType   AuthType  `json:"auth_type"`
    VaultPath  string    `json:"vault_path"`
    InUseCount int       `json:"in_use_count"`
    CreatedAt  time.Time `json:"created_at"`
}

// SecretPayload is the JSON structure stored in Vault.
// Omitempty fields are skipped when not applicable to the AuthType.
type SecretPayload struct {
    Username   string `json:"username"`
    PrivateKey string `json:"private_key,omitempty"`
    Passphrase string `json:"passphrase,omitempty"`
    Password   string `json:"password,omitempty"`
    UseHTTPS   bool   `json:"use_https,omitempty"`
}
```

- [ ] **Step 2: Create `store.go`**

```go
package credentials

import (
    "context"
    "errors"

    "github.com/google/uuid"
)

var (
    ErrNotFound = errors.New("credentials: not found")
    ErrConflict = errors.New("credentials: name already exists for this tenant")
    ErrInUse    = errors.New("credentials: credential is referenced by one or more hosts")
)

// Store is the Postgres persistence boundary for credential metadata.
type Store interface {
    List(ctx context.Context, tenantID uuid.UUID) ([]Credential, error)
    Get(ctx context.Context, id uuid.UUID) (Credential, error)
    Create(ctx context.Context, c Credential) (Credential, error)
    Delete(ctx context.Context, id uuid.UUID) error
    CountHosts(ctx context.Context, credID uuid.UUID) (int64, error)
}
```

- [ ] **Step 3: Write the failing postgres tests**

Create `pkg/manageserver/credentials/postgres_test.go`:

```go
//go:build integration

package credentials_test

import (
    "context"
    "errors"
    "testing"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/manageserver/credentials"
    "github.com/amiryahaya/triton/pkg/managestore"
)

func testStore(t *testing.T) *credentials.PostgresStore {
    t.Helper()
    pool := testPool(t) // shared helper from the package test suite
    ctx := context.Background()
    if err := managestore.Migrate(ctx, pool); err != nil {
        t.Fatalf("migrate: %v", err)
    }
    return credentials.NewPostgresStore(pool)
}

func TestPostgresStore_CreateAndList(t *testing.T) {
    s := testStore(t)
    ctx := context.Background()
    tenantID := uuid.New()
    credID := uuid.New()
    vaultPath := "secret/data/triton/" + tenantID.String() + "/credentials/" + credID.String()
    cred := credentials.Credential{
        ID:        credID,
        TenantID:  tenantID,
        Name:      "prod-ssh",
        AuthType:  credentials.AuthTypeSSHKey,
        VaultPath: vaultPath,
    }
    created, err := s.Create(ctx, cred)
    if err != nil {
        t.Fatalf("Create: %v", err)
    }
    if created.ID != credID {
        t.Errorf("id: got %v want %v", created.ID, credID)
    }

    list, err := s.List(ctx, tenantID)
    if err != nil {
        t.Fatalf("List: %v", err)
    }
    if len(list) != 1 || list[0].ID != credID {
        t.Errorf("List: got %d items, want 1 with id %v", len(list), credID)
    }
}

func TestPostgresStore_NameConflict(t *testing.T) {
    s := testStore(t)
    ctx := context.Background()
    tenantID := uuid.New()
    cred := credentials.Credential{
        ID: uuid.New(), TenantID: tenantID, Name: "dupe",
        AuthType:  credentials.AuthTypeSSHPassword,
        VaultPath: "secret/data/triton/t/c1",
    }
    if _, err := s.Create(ctx, cred); err != nil {
        t.Fatalf("first Create: %v", err)
    }
    cred2 := cred
    cred2.ID = uuid.New()
    cred2.VaultPath = "secret/data/triton/t/c2"
    if _, err := s.Create(ctx, cred2); !errors.Is(err, credentials.ErrConflict) {
        t.Errorf("duplicate name: want ErrConflict, got %v", err)
    }
}

func TestPostgresStore_Get_NotFound(t *testing.T) {
    s := testStore(t)
    if _, err := s.Get(context.Background(), uuid.New()); !errors.Is(err, credentials.ErrNotFound) {
        t.Errorf("want ErrNotFound, got %v", err)
    }
}

func TestPostgresStore_Delete(t *testing.T) {
    s := testStore(t)
    ctx := context.Background()
    tenantID := uuid.New()
    cred := credentials.Credential{
        ID: uuid.New(), TenantID: tenantID, Name: "to-delete",
        AuthType:  credentials.AuthTypeSSHKey,
        VaultPath: "secret/data/triton/t/c",
    }
    if _, err := s.Create(ctx, cred); err != nil {
        t.Fatalf("Create: %v", err)
    }
    if err := s.Delete(ctx, cred.ID); err != nil {
        t.Fatalf("Delete: %v", err)
    }
    if _, err := s.Get(ctx, cred.ID); !errors.Is(err, credentials.ErrNotFound) {
        t.Errorf("after delete: want ErrNotFound, got %v", err)
    }
}

func TestPostgresStore_CountHosts(t *testing.T) {
    s := testStore(t)
    ctx := context.Background()
    // A fresh credential with no host assignments must count 0.
    tenantID := uuid.New()
    cred := credentials.Credential{
        ID: uuid.New(), TenantID: tenantID, Name: "unused",
        AuthType:  credentials.AuthTypeSSHKey,
        VaultPath: "secret/data/triton/t/c",
    }
    if _, err := s.Create(ctx, cred); err != nil {
        t.Fatalf("Create: %v", err)
    }
    n, err := s.CountHosts(ctx, cred.ID)
    if err != nil {
        t.Fatalf("CountHosts: %v", err)
    }
    if n != 0 {
        t.Errorf("CountHosts: got %d want 0", n)
    }
}
```

- [ ] **Step 4: Run tests to confirm they fail**

```bash
go test -v -tags integration -run TestPostgresStore ./pkg/manageserver/credentials/...
```
Expected: FAIL — `PostgresStore` type does not exist.

- [ ] **Step 5: Create `postgres.go`**

```go
package credentials

import (
    "context"
    "errors"
    "fmt"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgconn"
    "github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore implements Store against manage_credentials.
type PostgresStore struct {
    pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
    return &PostgresStore{pool: pool}
}

var _ Store = (*PostgresStore)(nil)

func isUniqueViolation(err error) bool {
    var e *pgconn.PgError
    return errors.As(err, &e) && e.Code == "23505"
}

const credSelectCols = `c.id, c.tenant_id, c.name, c.auth_type, c.vault_path, c.created_at,
    (SELECT COUNT(*) FROM manage_hosts h WHERE h.credentials_ref = c.id) AS in_use_count`

func scanCred(row pgx.Row) (Credential, error) {
    var c Credential
    err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.AuthType, &c.VaultPath, &c.CreatedAt, &c.InUseCount)
    return c, err
}

func (s *PostgresStore) List(ctx context.Context, tenantID uuid.UUID) ([]Credential, error) {
    rows, err := s.pool.Query(ctx,
        `SELECT `+credSelectCols+` FROM manage_credentials c WHERE c.tenant_id = $1 ORDER BY c.name`,
        tenantID,
    )
    if err != nil {
        return nil, fmt.Errorf("list credentials: %w", err)
    }
    defer rows.Close()
    var out []Credential
    for rows.Next() {
        c, err := scanCred(rows)
        if err != nil {
            return nil, fmt.Errorf("scan credential: %w", err)
        }
        out = append(out, c)
    }
    if err := rows.Err(); err != nil {
        return nil, err
    }
    if out == nil {
        out = []Credential{}
    }
    return out, nil
}

func (s *PostgresStore) Get(ctx context.Context, id uuid.UUID) (Credential, error) {
    c, err := scanCred(s.pool.QueryRow(ctx,
        `SELECT `+credSelectCols+` FROM manage_credentials c WHERE c.id = $1`,
        id,
    ))
    if errors.Is(err, pgx.ErrNoRows) {
        return Credential{}, ErrNotFound
    }
    if err != nil {
        return Credential{}, fmt.Errorf("get credential: %w", err)
    }
    return c, nil
}

func (s *PostgresStore) Create(ctx context.Context, c Credential) (Credential, error) {
    row := s.pool.QueryRow(ctx,
        `INSERT INTO manage_credentials (id, tenant_id, name, auth_type, vault_path)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING `+credSelectCols,
        c.ID, c.TenantID, c.Name, string(c.AuthType), c.VaultPath,
    )
    created, err := scanCred(row)
    if isUniqueViolation(err) {
        return Credential{}, ErrConflict
    }
    if err != nil {
        return Credential{}, fmt.Errorf("create credential: %w", err)
    }
    return created, nil
}

func (s *PostgresStore) Delete(ctx context.Context, id uuid.UUID) error {
    tag, err := s.pool.Exec(ctx,
        `DELETE FROM manage_credentials WHERE id = $1`, id,
    )
    if err != nil {
        return fmt.Errorf("delete credential: %w", err)
    }
    if tag.RowsAffected() == 0 {
        return ErrNotFound
    }
    return nil
}

func (s *PostgresStore) CountHosts(ctx context.Context, credID uuid.UUID) (int64, error) {
    var n int64
    err := s.pool.QueryRow(ctx,
        `SELECT COUNT(*) FROM manage_hosts WHERE credentials_ref = $1`, credID,
    ).Scan(&n)
    return n, err
}
```

- [ ] **Step 6: Run tests to confirm they pass**

```bash
go test -v -tags integration -run TestPostgresStore ./pkg/manageserver/credentials/...
```
Expected: PASS (5 tests).

- [ ] **Step 7: Commit**

```bash
git add pkg/manageserver/credentials/types.go pkg/manageserver/credentials/store.go \
        pkg/manageserver/credentials/postgres.go pkg/manageserver/credentials/postgres_test.go
git commit -m "feat(credentials): types, Store interface, Postgres implementation"
```

---

## Task 4: Admin handlers — List, Create, Delete

**Files:**
- Create: `pkg/manageserver/credentials/handlers_admin.go`
- Create: `pkg/manageserver/credentials/handlers_admin_test.go`

- [ ] **Step 1: Write the failing handler tests**

Create `pkg/manageserver/credentials/handlers_admin_test.go`:

```go
package credentials_test

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/manageserver/credentials"
)

// stubStore is a test double for credentials.Store.
type stubStore struct {
    items      map[uuid.UUID]credentials.Credential
    hostCounts map[uuid.UUID]int64
}

func newStubStore() *stubStore {
    return &stubStore{
        items:      map[uuid.UUID]credentials.Credential{},
        hostCounts: map[uuid.UUID]int64{},
    }
}

func (s *stubStore) List(_ interface{}, tenantID uuid.UUID) ([]credentials.Credential, error) {
    var out []credentials.Credential
    for _, c := range s.items {
        if c.TenantID == tenantID {
            out = append(out, c)
        }
    }
    return out, nil
}
func (s *stubStore) Get(_ interface{}, id uuid.UUID) (credentials.Credential, error) {
    c, ok := s.items[id]
    if !ok {
        return credentials.Credential{}, credentials.ErrNotFound
    }
    return c, nil
}
func (s *stubStore) Create(_ interface{}, c credentials.Credential) (credentials.Credential, error) {
    s.items[c.ID] = c
    return c, nil
}
func (s *stubStore) Delete(_ interface{}, id uuid.UUID) error {
    delete(s.items, id)
    return nil
}
func (s *stubStore) CountHosts(_ interface{}, id uuid.UUID) (int64, error) {
    return s.hostCounts[id], nil
}

// stubVault is a test double for VaultWriter/Reader/Deleter.
type stubVault struct{ written, deleted []string }
func (v *stubVault) Write(_ interface{}, path string, _ credentials.SecretPayload) error {
    v.written = append(v.written, path); return nil
}
func (v *stubVault) Read(_ interface{}, path string) (credentials.SecretPayload, error) {
    return credentials.SecretPayload{Username: "u"}, nil
}
func (v *stubVault) Delete(_ interface{}, path string) error {
    v.deleted = append(v.deleted, path); return nil
}

func newHandlers(store credentials.Store, vault credentials.VaultRW) *credentials.AdminHandlers {
    return credentials.NewAdminHandlers(store, vault, "secret")
}

func jsonBody(t *testing.T, v any) *bytes.Buffer {
    t.Helper()
    b, _ := json.Marshal(v)
    return bytes.NewBuffer(b)
}

func TestAdminHandlers_List(t *testing.T) {
    store := newStubStore()
    tenantID := uuid.New()
    store.items[uuid.New()] = credentials.Credential{ID: uuid.New(), TenantID: tenantID, Name: "x", AuthType: credentials.AuthTypeSSHKey}
    h := newHandlers(store, &stubVault{})
    r := httptest.NewRequest(http.MethodGet, "/", nil)
    r = r.WithContext(credentials.WithTenantID(r.Context(), tenantID))
    w := httptest.NewRecorder()
    h.List(w, r)
    if w.Code != http.StatusOK {
        t.Errorf("status: got %d want %d", w.Code, http.StatusOK)
    }
}

func TestAdminHandlers_Create_SSHKey(t *testing.T) {
    h := newHandlers(newStubStore(), &stubVault{})
    tenantID := uuid.New()
    body := map[string]any{
        "name": "prod", "auth_type": "ssh-key",
        "username": "ubuntu", "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----",
    }
    r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, body))
    r = r.WithContext(credentials.WithTenantID(r.Context(), tenantID))
    w := httptest.NewRecorder()
    h.Create(w, r)
    if w.Code != http.StatusCreated {
        t.Errorf("Create ssh-key: status %d, body: %s", w.Code, w.Body.String())
    }
}

func TestAdminHandlers_Create_MissingPrivateKey(t *testing.T) {
    h := newHandlers(newStubStore(), &stubVault{})
    tenantID := uuid.New()
    body := map[string]any{"name": "x", "auth_type": "ssh-key", "username": "u"}
    r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, body))
    r = r.WithContext(credentials.WithTenantID(r.Context(), tenantID))
    w := httptest.NewRecorder()
    h.Create(w, r)
    if w.Code != http.StatusBadRequest {
        t.Errorf("missing private_key: status %d want 400", w.Code)
    }
}

func TestAdminHandlers_Create_InvalidPEM(t *testing.T) {
    h := newHandlers(newStubStore(), &stubVault{})
    tenantID := uuid.New()
    body := map[string]any{"name": "x", "auth_type": "ssh-key", "username": "u", "private_key": "not-pem"}
    r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, body))
    r = r.WithContext(credentials.WithTenantID(r.Context(), tenantID))
    w := httptest.NewRecorder()
    h.Create(w, r)
    if w.Code != http.StatusBadRequest {
        t.Errorf("invalid PEM: status %d want 400", w.Code)
    }
}

func TestAdminHandlers_Delete_InUse(t *testing.T) {
    store := newStubStore()
    id := uuid.New()
    store.items[id] = credentials.Credential{ID: id}
    store.hostCounts[id] = 2
    h := newHandlers(store, &stubVault{})
    r := httptest.NewRequest(http.MethodDelete, "/"+id.String(), nil)
    r = credentials.WithURLParam(r, "id", id.String())
    w := httptest.NewRecorder()
    h.Delete(w, r)
    if w.Code != http.StatusConflict {
        t.Errorf("delete in-use: status %d want 409", w.Code)
    }
}

func TestAdminHandlers_Delete_VaultNil_Returns503(t *testing.T) {
    h := credentials.NewAdminHandlers(newStubStore(), nil, "secret")
    r := httptest.NewRequest(http.MethodPost, "/", jsonBody(t, map[string]any{}))
    r = r.WithContext(credentials.WithTenantID(r.Context(), uuid.New()))
    w := httptest.NewRecorder()
    h.Create(w, r)
    if w.Code != http.StatusServiceUnavailable {
        t.Errorf("nil vault: status %d want 503", w.Code)
    }
}
```

- [ ] **Step 2: Run to confirm fail**

```bash
go test -v -run TestAdminHandlers ./pkg/manageserver/credentials/...
```
Expected: FAIL — `AdminHandlers` type does not exist.

- [ ] **Step 3: Create `handlers_admin.go`**

```go
package credentials

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "log"
    "net/http"
    "strings"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/manageserver/internal/limits"
)

type tenantKey struct{}

// WithTenantID injects a tenant UUID into the context. Used by tests.
// Production code uses injectInstanceOrg middleware in server.go.
func WithTenantID(ctx context.Context, id uuid.UUID) context.Context {
    return context.WithValue(ctx, tenantKey{}, id)
}

func tenantFromCtx(ctx context.Context) (uuid.UUID, bool) {
    id, ok := ctx.Value(tenantKey{}).(uuid.UUID)
    return id, ok
}

// WithURLParam injects a chi URL param into the request for tests.
func WithURLParam(r *http.Request, key, val string) *http.Request {
    rctx := chi.NewRouteContext()
    rctx.URLParams.Add(key, val)
    return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// VaultRW is the narrow vault surface AdminHandlers needs.
type VaultRW interface {
    Write(ctx context.Context, path string, payload SecretPayload) error
    Delete(ctx context.Context, path string) error
}

// AdminHandlers serves POST /admin/credentials and DELETE /admin/credentials/{id}.
type AdminHandlers struct {
    store Store
    vault VaultRW
    mount string
}

func NewAdminHandlers(store Store, vault VaultRW, mount string) *AdminHandlers {
    return &AdminHandlers{store: store, vault: vault, mount: mount}
}

func (h *AdminHandlers) vaultPath(tenantID, credID uuid.UUID) string {
    return fmt.Sprintf("%s/data/triton/%s/credentials/%s", h.mount, tenantID, credID)
}

type createReq struct {
    Name       string   `json:"name"`
    AuthType   AuthType `json:"auth_type"`
    Username   string   `json:"username"`
    PrivateKey string   `json:"private_key"`
    Passphrase string   `json:"passphrase"`
    Password   string   `json:"password"`
    UseHTTPS   bool     `json:"use_https"`
}

func (req createReq) validate() error {
    if strings.TrimSpace(req.Name) == "" {
        return errors.New("name is required")
    }
    if req.Username == "" {
        return errors.New("username is required")
    }
    switch req.AuthType {
    case AuthTypeSSHKey:
        if req.PrivateKey == "" {
            return errors.New("private_key is required for ssh-key")
        }
        if !strings.Contains(req.PrivateKey, "-----BEGIN") {
            return errors.New("private_key must be PEM format")
        }
    case AuthTypeSSHPassword, AuthTypeWinRM:
        if req.Password == "" {
            return errors.New("password is required")
        }
    default:
        return fmt.Errorf("auth_type must be one of ssh-key|ssh-password|winrm-password")
    }
    return nil
}

func (req createReq) toPayload() SecretPayload {
    p := SecretPayload{Username: req.Username}
    switch req.AuthType {
    case AuthTypeSSHKey:
        p.PrivateKey = req.PrivateKey
        p.Passphrase = req.Passphrase
    case AuthTypeSSHPassword:
        p.Password = req.Password
    case AuthTypeWinRM:
        p.Password = req.Password
        p.UseHTTPS = req.UseHTTPS
    }
    return p
}

// List returns all credentials for the current tenant.
func (h *AdminHandlers) List(w http.ResponseWriter, r *http.Request) {
    tenantID, ok := tenantFromCtx(r.Context())
    if !ok {
        writeErr(w, http.StatusServiceUnavailable, "tenant not set")
        return
    }
    list, err := h.store.List(r.Context(), tenantID)
    if err != nil {
        internalErr(w, r, err, "list credentials")
        return
    }
    writeJSON(w, http.StatusOK, list)
}

// Create validates, writes to Vault, then inserts the DB row.
func (h *AdminHandlers) Create(w http.ResponseWriter, r *http.Request) {
    if h.vault == nil {
        writeErr(w, http.StatusServiceUnavailable, "vault not configured")
        return
    }
    r.Body = http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)
    var req createReq
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeErr(w, http.StatusBadRequest, "invalid JSON body")
        return
    }
    if err := req.validate(); err != nil {
        writeErr(w, http.StatusBadRequest, err.Error())
        return
    }
    tenantID, ok := tenantFromCtx(r.Context())
    if !ok {
        writeErr(w, http.StatusServiceUnavailable, "tenant not set")
        return
    }
    credID := uuid.New()
    vaultPath := h.vaultPath(tenantID, credID)

    if err := h.vault.Write(r.Context(), vaultPath, req.toPayload()); err != nil {
        log.Printf("credentials: vault write: %v", err)
        writeErr(w, http.StatusBadGateway, "vault write failed")
        return
    }

    created, err := h.store.Create(r.Context(), Credential{
        ID:        credID,
        TenantID:  tenantID,
        Name:      strings.TrimSpace(req.Name),
        AuthType:  req.AuthType,
        VaultPath: vaultPath,
    })
    if errors.Is(err, ErrConflict) {
        // Vault secret was written — attempt cleanup (best-effort).
        _ = h.vault.Delete(r.Context(), vaultPath)
        writeErr(w, http.StatusConflict, "credential name already exists")
        return
    }
    if err != nil {
        _ = h.vault.Delete(r.Context(), vaultPath)
        internalErr(w, r, err, "create credential")
        return
    }
    writeJSON(w, http.StatusCreated, created)
}

// Delete blocks when the credential is in use, then removes Vault + DB.
func (h *AdminHandlers) Delete(w http.ResponseWriter, r *http.Request) {
    id, err := uuid.Parse(chi.URLParam(r, "id"))
    if err != nil {
        writeErr(w, http.StatusBadRequest, "invalid credential id")
        return
    }
    cred, err := h.store.Get(r.Context(), id)
    if errors.Is(err, ErrNotFound) {
        writeErr(w, http.StatusNotFound, "credential not found")
        return
    }
    if err != nil {
        internalErr(w, r, err, "get credential for delete")
        return
    }
    n, err := h.store.CountHosts(r.Context(), id)
    if err != nil {
        internalErr(w, r, err, "count hosts for credential")
        return
    }
    if n > 0 {
        writeErr(w, http.StatusConflict, fmt.Sprintf("credential in use by %d host(s)", n))
        return
    }
    if h.vault != nil {
        if err := h.vault.Delete(r.Context(), cred.VaultPath); err != nil {
            log.Printf("credentials: vault delete %s: %v (proceeding with DB delete)", cred.VaultPath, err)
        }
    }
    if err := h.store.Delete(r.Context(), id); err != nil {
        internalErr(w, r, err, "delete credential")
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
    writeJSON(w, status, map[string]string{"error": msg})
}

func internalErr(w http.ResponseWriter, r *http.Request, err error, op string) {
    log.Printf("credentials: %s: %s %s: %v", op, r.Method, r.URL.Path, err)
    writeErr(w, http.StatusInternalServerError, "internal server error")
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
go test -v -run TestAdminHandlers ./pkg/manageserver/credentials/...
```
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/credentials/handlers_admin.go pkg/manageserver/credentials/handlers_admin_test.go
git commit -m "feat(credentials): admin handlers — List, Create, Delete with vault+db orchestration"
```

---

## Task 5: Worker handler — GetSecret proxies Vault to scanner

**Files:**
- Create: `pkg/manageserver/credentials/worker_handler.go`
- Create: `pkg/manageserver/credentials/worker_handler_test.go`

- [ ] **Step 1: Write the failing tests**

Create `pkg/manageserver/credentials/worker_handler_test.go`:

```go
package credentials_test

import (
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/manageserver/credentials"
)

type stubReader struct {
    payload credentials.SecretPayload
    err     error
}
func (r *stubReader) Read(_ interface{}, _ string) (credentials.SecretPayload, error) {
    return r.payload, r.err
}

func TestWorkerHandler_GetSecret_OK(t *testing.T) {
    store := newStubStore()
    id := uuid.New()
    store.items[id] = credentials.Credential{
        ID:        id,
        VaultPath: "secret/data/triton/t/c",
    }
    vault := &stubReader{payload: credentials.SecretPayload{Username: "ubuntu", Password: "pw"}}
    h := credentials.NewWorkerHandler(store, vault)

    r := httptest.NewRequest(http.MethodGet, "/"+id.String(), nil)
    r = credentials.WithURLParam(r, "id", id.String())
    w := httptest.NewRecorder()
    h.GetSecret(w, r)
    if w.Code != http.StatusOK {
        t.Errorf("status: got %d want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
    }
}

func TestWorkerHandler_GetSecret_NotFound(t *testing.T) {
    h := credentials.NewWorkerHandler(newStubStore(), &stubReader{})
    r := httptest.NewRequest(http.MethodGet, "/"+uuid.New().String(), nil)
    r = credentials.WithURLParam(r, "id", uuid.New().String())
    w := httptest.NewRecorder()
    h.GetSecret(w, r)
    if w.Code != http.StatusNotFound {
        t.Errorf("not found: status %d want 404", w.Code)
    }
}
```

- [ ] **Step 2: Run to confirm fail**

```bash
go test -v -run TestWorkerHandler ./pkg/manageserver/credentials/...
```
Expected: FAIL — `WorkerHandler` type does not exist.

- [ ] **Step 3: Create `worker_handler.go`**

```go
package credentials

import (
    "context"
    "encoding/json"
    "errors"
    "log"
    "net/http"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

// VaultReader is the narrow vault surface the worker handler needs.
type VaultReader interface {
    Read(ctx context.Context, path string) (SecretPayload, error)
}

// WorkerHandler serves GET /worker/credentials/{id}.
type WorkerHandler struct {
    store Store
    vault VaultReader
}

func NewWorkerHandler(store Store, vault VaultReader) *WorkerHandler {
    return &WorkerHandler{store: store, vault: vault}
}

// GetSecret looks up the credential metadata, fetches the secret from Vault,
// and returns the SecretPayload to the scanner subprocess.
func (h *WorkerHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
    id, err := uuid.Parse(chi.URLParam(r, "id"))
    if err != nil {
        http.Error(w, "invalid credential id", http.StatusBadRequest)
        return
    }
    cred, err := h.store.Get(r.Context(), id)
    if errors.Is(err, ErrNotFound) {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    if err != nil {
        log.Printf("credentials: worker get: %v", err)
        http.Error(w, "internal server error", http.StatusInternalServerError)
        return
    }
    secret, err := h.vault.Read(r.Context(), cred.VaultPath)
    if err != nil {
        log.Printf("credentials: vault read %s: %v", cred.VaultPath, err)
        http.Error(w, "vault unavailable", http.StatusBadGateway)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(secret)
}
```

- [ ] **Step 4: Run tests**

```bash
go test -v -run TestWorkerHandler ./pkg/manageserver/credentials/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/credentials/worker_handler.go pkg/manageserver/credentials/worker_handler_test.go
git commit -m "feat(credentials): WorkerHandler — GetSecret proxies Vault secret to scanner"
```

---

## Task 6: Routes + server wiring

**Files:**
- Create: `pkg/manageserver/credentials/routes.go`
- Modify: `pkg/manageserver/config.go`
- Modify: `pkg/manageserver/server.go`

- [ ] **Step 1: Create `routes.go`**

```go
package credentials

import (
    "github.com/go-chi/chi/v5"

    "github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// MountAdminRoutes wires admin credential routes onto r.
// r must already be authenticated + tenant-scoped.
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
    r.Get("/", h.List)
    r.Post("/", h.Create)
    r.Delete("/{id}", h.Delete)
}

// MountWorkerRoutes wires the worker credential route onto r.
// r must already be protected by WorkerKeyAuth middleware.
func MountWorkerRoutes(r chi.Router, h *WorkerHandler) {
    r.Get("/credentials/{id}", h.GetSecret)
}

// CredentialsStore is the narrow Store surface scanjobs worker needs.
// Satisfying the interface proves VaultReader + Store both compile correctly.
var _ scanjobs.CredentialsStore = (Store)(nil)
```

Wait — `scanjobs.CredentialsStore` does not exist yet. Remove that var and instead confirm compilation by running the build:

```go
package credentials

import "github.com/go-chi/chi/v5"

// MountAdminRoutes wires credential admin routes. r must be authenticated + tenant-scoped.
func MountAdminRoutes(r chi.Router, h *AdminHandlers) {
    r.Get("/", h.List)
    r.Post("/", h.Create)
    r.Delete("/{id}", h.Delete)
}

// MountWorkerRoutes wires the worker GetSecret route.
func MountWorkerRoutes(r chi.Router, h *WorkerHandler) {
    r.Get("/credentials/{id}", h.GetSecret)
}
```

- [ ] **Step 2: Update `pkg/manageserver/config.go` — add Vault fields**

Append to the `Config` struct, after `ReportLicenseToken`:

```go
// VaultAddr is the base URL of the HashiCorp Vault instance, e.g.
// https://vault.internal:8200. Read from TRITON_VAULT_ADDR.
VaultAddr string

// VaultMount is the KV v2 mount path (default: "secret").
// Read from TRITON_VAULT_MOUNT.
VaultMount string

// VaultToken is a static Vault token. Read from TRITON_VAULT_TOKEN.
// Prefer AppRole (VaultRoleID + VaultSecretID) for production.
VaultToken string

// VaultRoleID and VaultSecretID are the AppRole credentials.
// Read from TRITON_VAULT_ROLE_ID + TRITON_VAULT_SECRET_ID.
VaultRoleID  string
VaultSecretID string
```

- [ ] **Step 3: Update `pkg/manageserver/server.go` — wire credential routes**

In the `Server` struct, add a `credVault` field after `agentsGateway`:

```go
credVault   *credentials.VaultClient
credAdmin   *credentials.AdminHandlers
credWorker  *credentials.WorkerHandler
credStore   *credentials.PostgresStore
```

In the `New()` function, after constructing `hostsStore`:

```go
import "github.com/amiryahaya/triton/pkg/manageserver/credentials"

// Vault client — nil when not configured; handlers return 503 gracefully.
vaultMount := cfg.VaultMount
if vaultMount == "" {
    vaultMount = "secret"
}
var vaultClient *credentials.VaultClient
if cfg.VaultAddr != "" {
    var vaultErr error
    vaultClient, vaultErr = credentials.NewVaultClient(
        cfg.VaultAddr, vaultMount, cfg.VaultToken, cfg.VaultRoleID, cfg.VaultSecretID,
    )
    if vaultErr != nil {
        log.Printf("manageserver: vault init: %v (credential API will return 503)", vaultErr)
        vaultClient = nil
    }
}
credStore := credentials.NewPostgresStore(pool)
```

Then set on `srv` (inside `srv := &Server{...}` or after):
```go
srv.credStore  = credStore
srv.credVault  = vaultClient
srv.credAdmin  = credentials.NewAdminHandlers(credStore, vaultClient, vaultMount)
srv.credWorker = credentials.NewWorkerHandler(credStore, vaultClient)
```

In `buildRouter()`, inside the `/api/v1/admin` route group, add:
```go
r.Route("/credentials", func(r chi.Router) { credentials.MountAdminRoutes(r, s.credAdmin) })
```

In the worker API section (inside `if s.cfg.WorkerKey != ""`):
```go
credentials.MountWorkerRoutes(r, s.credWorker)
```

- [ ] **Step 4: Confirm it compiles**

```bash
go build ./pkg/manageserver/...
```
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/credentials/routes.go pkg/manageserver/config.go pkg/manageserver/server.go
git commit -m "feat(credentials): wire credential routes into admin + worker API"
```

---

## Task 7: Host model + API — add credentials_ref and access_port

**Files:**
- Modify: `pkg/manageserver/hosts/types.go`
- Modify: `pkg/manageserver/hosts/postgres.go`
- Modify: `pkg/manageserver/hosts/handlers_admin.go`

- [ ] **Step 1: Write the failing test**

Add to the hosts admin handler test file (create `pkg/manageserver/hosts/handlers_admin_test.go` if absent, or add to existing):

```go
func TestHostHandler_CredentialsRefRoundTrip(t *testing.T) {
    // This is a compile-time check that Host has the new fields.
    var h hosts.Host
    credID := uuid.New()
    h.CredentialsRef = &credID
    h.AccessPort = 2222
    if h.AccessPort != 2222 {
        t.Error("AccessPort not settable")
    }
}
```

- [ ] **Step 2: Run to confirm fail**

```bash
go test -v -run TestHostHandler_CredentialsRef ./pkg/manageserver/hosts/...
```
Expected: FAIL — `Host` has no field `CredentialsRef`.

- [ ] **Step 3: Update `types.go`**

In `pkg/manageserver/hosts/types.go`, add two fields to `Host`:

```go
type Host struct {
    ID             uuid.UUID  `json:"id"`
    Hostname       string     `json:"hostname,omitempty"`
    IP             string     `json:"ip"`
    Tags           []tags.Tag `json:"tags"`
    OS             string     `json:"os,omitempty"`
    LastSeenAt     *time.Time `json:"last_seen_at,omitempty"`
    CreatedAt      time.Time  `json:"created_at"`
    UpdatedAt      time.Time  `json:"updated_at"`
    CredentialsRef *uuid.UUID `json:"credentials_ref,omitempty"`
    AccessPort     int        `json:"access_port"`
}
```

- [ ] **Step 4: Update `postgres.go` — extend select cols + scan + write**

Update `hostSelectCols`:
```go
const hostSelectCols = `id, hostname, host(ip)::text, os, last_seen_at, created_at, updated_at, credentials_ref, access_port`
```

Update `scanHost` to scan the two new fields:
```go
func scanHost(row pgx.Row) (Host, error) {
    var h Host
    var hostname *string
    var ip *string
    if err := row.Scan(&h.ID, &hostname, &ip, &h.OS, &h.LastSeenAt, &h.CreatedAt, &h.UpdatedAt,
        &h.CredentialsRef, &h.AccessPort); err != nil {
        return Host{}, err
    }
    if hostname != nil {
        h.Hostname = *hostname
    }
    if ip != nil {
        h.IP = *ip
    }
    h.Tags = []tags.Tag{}
    return h, nil
}
```

Update `Create` to include the new columns:
```go
row := s.pool.QueryRow(ctx,
    `INSERT INTO manage_hosts (hostname, ip, os, last_seen_at, credentials_ref, access_port)
     VALUES ($1, $2::inet, $3, $4, $5, $6)
     RETURNING id, created_at, updated_at, credentials_ref, access_port`,
    hostnameArg(h.Hostname), ipArg(h.IP), h.OS, h.LastSeenAt,
    h.CredentialsRef, h.AccessPort,
)
// Scan: id, created_at, updated_at, credentials_ref, access_port
if err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt, &h.CredentialsRef, &h.AccessPort); err != nil {
    ...
}
```

Update `Update`:
```go
row := s.pool.QueryRow(ctx,
    `UPDATE manage_hosts
     SET hostname = $1, ip = $2::inet, os = $3, last_seen_at = $4,
         credentials_ref = $5, access_port = $6, updated_at = NOW()
     WHERE id = $7
     RETURNING id, created_at, updated_at, credentials_ref, access_port`,
    hostnameArg(h.Hostname), ipArg(h.IP), h.OS, h.LastSeenAt,
    h.CredentialsRef, h.AccessPort, h.ID,
)
if err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt, &h.CredentialsRef, &h.AccessPort); err != nil {
    ...
}
```

Update `GetHostBasic` to also return access_port (change signature):
```go
func (s *PostgresStore) GetHostBasic(ctx context.Context, id uuid.UUID) (hostname, ip string, accessPort int, err error) {
    var hn, ipv *string
    err = s.pool.QueryRow(ctx,
        `SELECT hostname, host(ip)::text, access_port FROM manage_hosts WHERE id = $1`, id,
    ).Scan(&hn, &ipv, &accessPort)
    if errors.Is(err, pgx.ErrNoRows) {
        return "", "", 0, ErrNotFound
    }
    if err != nil {
        return "", "", 0, fmt.Errorf("get host basic: %w", err)
    }
    if hn != nil {
        hostname = *hn
    }
    if ipv != nil {
        ip = *ipv
    }
    return hostname, ip, accessPort, nil
}
```

Also update `BulkCreate` to pass the new fields to the INSERT (same as Create pattern above).

- [ ] **Step 5: Update `handlers_admin.go` — accept new fields in request body**

Add to `hostRequestBody`:
```go
type hostRequestBody struct {
    Hostname       string     `json:"hostname"`
    IP             string     `json:"ip"`
    OS             string     `json:"os"`
    LastSeenAt     *time.Time `json:"last_seen_at"`
    TagIDs         []uuid.UUID `json:"tag_ids"`
    Tags           []string   `json:"tags"`
    CredentialsRef *uuid.UUID `json:"credentials_ref"`
    AccessPort     *int       `json:"access_port"`
}
```

Update `toHost()`:
```go
func (b hostRequestBody) toHost() Host {
    h := Host{
        Hostname:       strings.TrimSpace(b.Hostname),
        IP:             strings.TrimSpace(b.IP),
        OS:             b.OS,
        LastSeenAt:     b.LastSeenAt,
        CredentialsRef: b.CredentialsRef,
        AccessPort:     22,
    }
    if b.AccessPort != nil {
        h.AccessPort = *b.AccessPort
    }
    return h
}
```

- [ ] **Step 6: Fix HostsStore interface in scanjobs**

In `pkg/manageserver/scanjobs/worker_handlers.go`, update:
```go
type HostsStore interface {
    GetHostBasic(ctx context.Context, id uuid.UUID) (hostname, ip string, accessPort int, err error)
}
```

And update `WorkerHostResp`:
```go
type WorkerHostResp struct {
    ID         uuid.UUID `json:"id"`
    Hostname   string    `json:"hostname"`
    IP         string    `json:"ip"`
    AccessPort int       `json:"access_port"`
}
```

Update `GetHost` handler body:
```go
hostname, ip, accessPort, err := h.hostsStore.GetHostBasic(r.Context(), id)
...
_ = json.NewEncoder(w).Encode(WorkerHostResp{ID: id, Hostname: hostname, IP: ip, AccessPort: accessPort})
```

- [ ] **Step 7: Confirm build**

```bash
go build ./pkg/manageserver/...
```
Expected: no errors.

- [ ] **Step 8: Run existing host tests**

```bash
go test -v -run TestHostHandler ./pkg/manageserver/hosts/...
```
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add pkg/manageserver/hosts/types.go pkg/manageserver/hosts/postgres.go \
        pkg/manageserver/hosts/handlers_admin.go \
        pkg/manageserver/scanjobs/worker_handlers.go
git commit -m "feat(credentials): add credentials_ref + access_port to hosts; update worker host API"
```

---

## Task 8: Port survey auto-fill credentials_ref from host

**Files:**
- Modify: `pkg/manageserver/scanjobs/postgres.go`

- [ ] **Step 1: Write the failing test**

Add to `pkg/manageserver/scanjobs/postgres_ext_test.go`:

```go
//go:build integration

func TestEnqueuePortSurvey_InheritsCredentialsRef(t *testing.T) {
    pool := testPool(t)
    ctx := context.Background()
    if err := managestore.Migrate(ctx, pool); err != nil {
        t.Fatalf("migrate: %v", err)
    }

    // Create a credential row to reference.
    tenantID := uuid.New()
    credID := uuid.New()
    _, err := pool.Exec(ctx,
        `INSERT INTO manage_credentials (id, tenant_id, name, auth_type, vault_path)
         VALUES ($1, $2, 'test-cred', 'ssh-key', 'secret/data/triton/t/c')`,
        credID, tenantID,
    )
    if err != nil {
        t.Fatalf("insert credential: %v", err)
    }

    // Create a host with credentials_ref set.
    hostID := uuid.New()
    _, err = pool.Exec(ctx,
        `INSERT INTO manage_hosts (id, hostname, ip, credentials_ref, access_port)
         VALUES ($1, 'web-01', '10.0.0.1', $2, 22)`,
        hostID, credID,
    )
    if err != nil {
        t.Fatalf("insert host: %v", err)
    }

    store := scanjobs.NewPostgresStore(pool)
    jobs, err := store.EnqueuePortSurvey(ctx, scanjobs.PortSurveyEnqueueReq{
        TenantID: tenantID,
        HostIDs:  []uuid.UUID{hostID},
        Profile:  scanjobs.ProfileStandard,
    })
    if err != nil {
        t.Fatalf("EnqueuePortSurvey: %v", err)
    }
    if len(jobs) != 1 {
        t.Fatalf("expected 1 job, got %d", len(jobs))
    }
    if jobs[0].CredentialsRef == nil || *jobs[0].CredentialsRef != credID {
        t.Errorf("credentials_ref: got %v want %v", jobs[0].CredentialsRef, credID)
    }
}
```

- [ ] **Step 2: Run to confirm fail**

```bash
go test -v -tags integration -run TestEnqueuePortSurvey_Inherits ./pkg/manageserver/scanjobs/...
```
Expected: FAIL — `credentials_ref` is NULL in inserted job.

- [ ] **Step 3: Update `EnqueuePortSurvey` in `postgres.go`**

Replace the inner loop INSERT with a JOIN that pulls `credentials_ref` from the host row:

```go
for _, hid := range req.HostIDs {
    row := tx.QueryRow(ctx,
        `INSERT INTO manage_scan_jobs
           (tenant_id, host_id, profile, job_type, scheduled_at, port_override, credentials_ref)
         SELECT $1, $2, $3, 'port_survey', $4, $5, h.credentials_ref
         FROM manage_hosts h WHERE h.id = $2
         RETURNING `+jobSelectCols,
        req.TenantID, hid, string(req.Profile), req.ScheduledAt, portOverride,
    )
    j, err := scanJob(row)
    if err != nil {
        return nil, fmt.Errorf("insert port survey job for host %s: %w", hid, err)
    }
    out = append(out, j)
}
```

- [ ] **Step 4: Run test to confirm pass**

```bash
go test -v -tags integration -run TestEnqueuePortSurvey_Inherits ./pkg/manageserver/scanjobs/...
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/manageserver/scanjobs/postgres.go pkg/manageserver/scanjobs/postgres_ext_test.go
git commit -m "feat(credentials): EnqueuePortSurvey inherits credentials_ref from host via JOIN"
```

---

## Task 9: Scanner client + runner — fetch and pass credential

**Files:**
- Modify: `pkg/scanrunner/scanner.go`
- Modify: `pkg/scanrunner/client.go`
- Modify: `pkg/scanrunner/runner.go`

- [ ] **Step 1: Write the failing test**

Add to `pkg/scanrunner/runner_test.go` (or create):

```go
package scanrunner_test

import (
    "context"
    "testing"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/pkg/scanrunner"
)

type stubScanner struct {
    gotTarget scanrunner.Target
}

func (s *stubScanner) Scan(ctx context.Context, t scanrunner.Target, emit func(scanrunner.Finding)) error {
    s.gotTarget = t
    return nil
}

func TestRunOne_PassesCredential(t *testing.T) {
    credID := uuid.New()
    // This test only checks the compile-time shape — Target must have Credential field.
    target := scanrunner.Target{
        IP:      "10.0.0.1",
        Profile: "standard",
        Credential: &scanrunner.CredentialSecret{
            Username: "ubuntu",
            Password: "pw",
        },
        AccessPort: 22,
    }
    if target.Credential == nil {
        t.Error("Credential field is nil")
    }
    _ = credID
}
```

- [ ] **Step 2: Run to confirm fail**

```bash
go test -v -run TestRunOne_PassesCredential ./pkg/scanrunner/...
```
Expected: FAIL — `Target` has no field `Credential`.

- [ ] **Step 3: Update `scanner.go` — add fields to Target**

In `pkg/scanrunner/scanner.go`, add to the `Target` struct:

```go
// Credential is populated when the job has a credentials_ref.
// Nil means unauthenticated scan only.
Credential *CredentialSecret

// AccessPort is the SSH/WinRM port to use for authenticated connections.
// Defaults to 22; WinRM uses 5985/5986 as determined by the credential.
AccessPort int
```

- [ ] **Step 4: Add `CredentialSecret` type + `GetCredential` to `client.go`**

Add to `pkg/scanrunner/client.go`:

```go
// CredentialSecret is the scanner-side view of a credential secret.
// Field names match the Vault JSON payload.
type CredentialSecret struct {
    Username   string `json:"username"`
    PrivateKey string `json:"private_key,omitempty"`
    Passphrase string `json:"passphrase,omitempty"`
    Password   string `json:"password,omitempty"`
    UseHTTPS   bool   `json:"use_https,omitempty"`
}

// GetCredential fetches the secret for a credential by ID.
func (c *ManageClient) GetCredential(ctx context.Context, id uuid.UUID) (CredentialSecret, error) {
    resp, err := c.req(ctx, http.MethodGet, fmt.Sprintf("/api/v1/worker/credentials/%s", id), nil)
    if err != nil {
        return CredentialSecret{}, err
    }
    defer resp.Body.Close() //nolint:errcheck
    if resp.StatusCode != http.StatusOK {
        return CredentialSecret{}, fmt.Errorf("get credential: status %d", resp.StatusCode)
    }
    var sec CredentialSecret
    err = json.NewDecoder(resp.Body).Decode(&sec)
    return sec, err
}
```

Also update `HostInfo` to include `AccessPort`:
```go
type HostInfo struct {
    ID         uuid.UUID `json:"id"`
    Hostname   string    `json:"hostname"`
    IP         string    `json:"ip"`
    AccessPort int       `json:"access_port"`
}
```

- [ ] **Step 5: Update `runner.go` — fetch credential and set on Target**

In `RunOne`, between Step 2 (resolve host) and Step 3 (heartbeat), insert:

```go
// Step 2b: Fetch credential if assigned.
var cred *CredentialSecret
if claim.CredentialsRef != nil {
    secret, err := manage.GetCredential(ctx, *claim.CredentialsRef)
    if err != nil {
        return fail(fmt.Errorf("runner: get credential %s: %w", *claim.CredentialsRef, err))
    }
    cred = &secret
}
```

Then update the Target construction:
```go
target := Target{
    IP:           host.IP,
    Profile:      claim.Profile,
    PortOverride: claim.PortOverride,
    Credential:   cred,
    AccessPort:   host.AccessPort,
}
```

- [ ] **Step 6: Run tests**

```bash
go test -v -run TestRunOne ./pkg/scanrunner/...
```
Expected: PASS.

```bash
go build ./...
```
Expected: no errors.

- [ ] **Step 7: Commit**

```bash
git add pkg/scanrunner/scanner.go pkg/scanrunner/client.go pkg/scanrunner/runner.go \
        pkg/scanrunner/runner_test.go
git commit -m "feat(credentials): scanner target gains Credential + AccessPort; runner fetches secret"
```

---

## Task 10: Frontend API client — types + methods

**Files:**
- Modify: `web/packages/api-client/src/manageServer.types.ts`
- Modify: `web/packages/api-client/src/manageServer.ts`

- [ ] **Step 1: Add types to `manageServer.types.ts`**

After the `UpdateHostReq` interface, add:

```ts
export type CredentialAuthType = 'ssh-key' | 'ssh-password' | 'winrm-password';

export interface Credential {
  id: string;
  tenant_id: string;
  name: string;
  auth_type: CredentialAuthType;
  vault_path: string;
  in_use_count: number;
  created_at: string;
}

export interface CreateCredentialReq {
  name: string;
  auth_type: CredentialAuthType;
  username: string;
  private_key?: string;
  passphrase?: string;
  password?: string;
  use_https?: boolean;
}
```

Extend `Host` with the two new fields:
```ts
export interface Host {
  id: string;
  hostname?: string;
  ip: string;
  tags: Tag[];
  os?: string;
  last_seen_at?: string;
  created_at: string;
  updated_at: string;
  credentials_ref?: string;
  access_port: number;
}
```

Extend `UpdateHostReq`:
```ts
export interface UpdateHostReq {
  ip: string;
  hostname?: string;
  os?: string;
  credentials_ref?: string | null;
  access_port?: number;
}
```

Add `Credential` and `CreateCredentialReq` to the barrel export in `web/packages/api-client/src/index.ts`.

- [ ] **Step 2: Add methods to `manageServer.ts`**

In `createManageApi`, add after the hosts methods:

```ts
import type {
  ...
  Credential, CreateCredentialReq,
} from './manageServer.types';

// Credentials
listCredentials: () => http.get<Credential[]>('/v1/admin/credentials/'),
createCredential: (req: CreateCredentialReq) => http.post<Credential>('/v1/admin/credentials/', req),
deleteCredential: (id: string) => http.del<void>(`/v1/admin/credentials/${id}`),
```

- [ ] **Step 3: Confirm TypeScript compiles**

```bash
cd web && npm run typecheck 2>&1 | head -30
```
Expected: no errors (or only pre-existing unrelated ones).

- [ ] **Step 4: Commit**

```bash
git add web/packages/api-client/src/manageServer.types.ts \
        web/packages/api-client/src/manageServer.ts
git commit -m "feat(credentials): API client types — Credential, CreateCredentialReq; extend Host"
```

---

## Task 11: Credentials Pinia store + Credentials.vue + CredentialForm.vue

**Files:**
- Create: `web/apps/manage-portal/src/stores/credentials.ts`
- Create: `web/apps/manage-portal/src/views/Credentials.vue`
- Create: `web/apps/manage-portal/src/views/modals/CredentialForm.vue`

- [ ] **Step 1: Create `stores/credentials.ts`**

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { Credential, CreateCredentialReq } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useCredentialsStore = defineStore('credentials', () => {
  const items = ref<Credential[]>([]);
  const loading = ref(false);

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listCredentials(); }
    catch (e) { useToast().error({ title: 'Failed to load credentials', description: String(e) }); }
    finally { loading.value = false; }
  }

  async function create(req: CreateCredentialReq) {
    const c = await useApiClient().get().createCredential(req);
    items.value.push(c);
    return c;
  }

  async function remove(id: string) {
    await useApiClient().get().deleteCredential(id);
    items.value = items.value.filter(x => x.id !== id);
  }

  return { items, loading, fetch, create, remove };
});
```

- [ ] **Step 2: Create `views/modals/CredentialForm.vue`**

```vue
<script setup lang="ts">
import { ref, computed } from 'vue';
import type { CredentialAuthType, CreateCredentialReq } from '@triton/api-client';
import { TModal, TSelect } from '@triton/ui';
import { useCredentialsStore } from '../../stores/credentials';

const emit = defineEmits<{ (e: 'close'): void }>();
const store = useCredentialsStore();

const name = ref('');
const authType = ref<CredentialAuthType>('ssh-key');
const username = ref('');
const privateKey = ref('');
const passphrase = ref('');
const password = ref('');
const useHttps = ref(false);
const saving = ref(false);
const error = ref('');

const authOptions = [
  { value: 'ssh-key',      label: 'SSH Key' },
  { value: 'ssh-password', label: 'SSH Password' },
  { value: 'winrm-password', label: 'WinRM Password' },
];

const pemValid = computed(() => {
  if (authType.value !== 'ssh-key') return true;
  return privateKey.value.includes('-----BEGIN');
});

async function submit() {
  error.value = '';
  if (!name.value.trim()) { error.value = 'Name is required'; return; }
  if (!username.value.trim()) { error.value = 'Username is required'; return; }
  if (authType.value === 'ssh-key' && !pemValid.value) {
    error.value = 'Private key must be in PEM format'; return;
  }

  const req: CreateCredentialReq = {
    name: name.value.trim(),
    auth_type: authType.value,
    username: username.value.trim(),
  };
  if (authType.value === 'ssh-key') {
    req.private_key = privateKey.value;
    if (passphrase.value) req.passphrase = passphrase.value;
  } else {
    req.password = password.value;
    if (authType.value === 'winrm-password') req.use_https = useHttps.value;
  }

  saving.value = true;
  try {
    await store.create(req);
    emit('close');
  } catch (e: any) {
    error.value = e?.message ?? String(e);
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <TModal title="Add Credential" @close="$emit('close')">
    <div class="form-body">
      <label>Name
        <input v-model="name" placeholder="prod-ssh-key" />
      </label>
      <label>Type
        <TSelect v-model="authType" :options="authOptions" />
      </label>
      <label>Username
        <input v-model="username" placeholder="ubuntu" />
      </label>

      <template v-if="authType === 'ssh-key'">
        <label>Private Key (PEM)
          <textarea v-model="privateKey" rows="6"
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
          <span v-if="privateKey && !pemValid" class="form-error">
            Must be PEM format (-----BEGIN …)
          </span>
        </label>
        <label>Passphrase (optional)
          <input v-model="passphrase" type="password" />
        </label>
      </template>

      <template v-else>
        <label>Password
          <input v-model="password" type="password" />
        </label>
        <label v-if="authType === 'winrm-password'" class="checkbox-row">
          <input v-model="useHttps" type="checkbox" />
          Use HTTPS (port 5986)
        </label>
      </template>

      <p v-if="error" class="form-error">{{ error }}</p>
    </div>
    <template #footer>
      <button class="btn-secondary" @click="$emit('close')">Cancel</button>
      <button class="btn-primary" :disabled="saving" @click="submit">
        {{ saving ? 'Saving…' : 'Save to Vault' }}
      </button>
    </template>
  </TModal>
</template>
```

- [ ] **Step 3: Create `views/Credentials.vue`**

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useCredentialsStore } from '../stores/credentials';
import { useToast } from '@triton/ui';
import CredentialForm from './modals/CredentialForm.vue';

const store = useCredentialsStore();
const toast = useToast();
const showForm = ref(false);

onMounted(() => store.fetch());

const authTypeLabel: Record<string, string> = {
  'ssh-key': 'SSH Key',
  'ssh-password': 'SSH Password',
  'winrm-password': 'WinRM Password',
};

async function remove(id: string, inUseCount: number) {
  if (inUseCount > 0) {
    toast.error({
      title: 'Credential in use',
      description: `Unassign from all ${inUseCount} host(s) before deleting.`,
    });
    return;
  }
  if (!confirm('Delete this credential? This also removes it from Vault.')) return;
  try {
    await store.remove(id);
    toast.success({ title: 'Deleted' });
  } catch (e: any) {
    toast.error({ title: 'Delete failed', description: String(e) });
  }
}
</script>

<template>
  <div class="page">
    <div class="page-header">
      <h1>Credentials</h1>
      <button class="btn-primary" @click="showForm = true">+ Add Credential</button>
    </div>

    <div v-if="store.loading" class="loading">Loading…</div>
    <table v-else class="data-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Hosts</th>
          <th>Created</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="store.items.length === 0">
          <td colspan="5" class="empty">No credentials yet.</td>
        </tr>
        <tr v-for="c in store.items" :key="c.id">
          <td>{{ c.name }}</td>
          <td><span class="badge">{{ authTypeLabel[c.auth_type] ?? c.auth_type }}</span></td>
          <td>{{ c.in_use_count }}</td>
          <td>{{ new Date(c.created_at).toLocaleDateString() }}</td>
          <td>
            <button class="btn-danger-sm" @click="remove(c.id, c.in_use_count)">Delete</button>
          </td>
        </tr>
      </tbody>
    </table>

    <CredentialForm v-if="showForm" @close="showForm = false; store.fetch()" />
  </div>
</template>
```

- [ ] **Step 4: Confirm TypeScript compiles**

```bash
cd web && npm run typecheck 2>&1 | head -20
```
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add web/apps/manage-portal/src/stores/credentials.ts \
        web/apps/manage-portal/src/views/Credentials.vue \
        web/apps/manage-portal/src/views/modals/CredentialForm.vue
git commit -m "feat(credentials): Credentials.vue + CredentialForm.vue + credentials store"
```

---

## Task 12: HostForm — credential picker + Access Port field

**Files:**
- Modify: `web/apps/manage-portal/src/views/modals/HostForm.vue`
- Modify: `web/apps/manage-portal/src/stores/hosts.ts`

- [ ] **Step 1: Update `stores/hosts.ts` — include credentials_ref + access_port in update**

In the `update` function, change the `UpdateHostReq` spread to pass through the new fields:

```ts
async function update(id: string, req: UpdateHostReq & { tag_ids?: string[] }) {
  const api = useApiClient().get();
  const { tag_ids, ...hostFields } = req;
  // hostFields now includes credentials_ref + access_port from UpdateHostReq
  let h = await api.updateHost(id, hostFields);
  if (tag_ids !== undefined) {
    h = await api.setHostTags(id, tag_ids);
  }
  const i = items.value.findIndex(x => x.id === id);
  if (i >= 0) items.value[i] = h;
  return h;
}
```

No other changes needed in the store — the type change in `UpdateHostReq` propagates automatically.

- [ ] **Step 2: Update `HostForm.vue` — add credential picker and access port**

Locate the existing `HostForm.vue` at `web/apps/manage-portal/src/views/modals/HostForm.vue`.

Add import and store usage at the top of `<script setup>`:

```ts
import { useCredentialsStore } from '../../stores/credentials';

const credStore = useCredentialsStore();
onMounted(() => credStore.fetch());

const credentialsRef = ref<string | null>(props.host?.credentials_ref ?? null);
const accessPort = ref<number>(props.host?.access_port ?? 22);

// Pre-fill access_port when a winrm credential is selected.
watch(credentialsRef, (id) => {
  if (!id) { accessPort.value = 22; return; }
  const cred = credStore.items.find(c => c.id === id);
  if (!cred) return;
  if (cred.auth_type === 'winrm-password') accessPort.value = 5985;
  else accessPort.value = 22;
});
```

Add to the form submit payload:
```ts
const payload = {
  ...existing fields...,
  credentials_ref: credentialsRef.value ?? undefined,
  access_port: accessPort.value,
};
```

Add to the form template (before the save button):

```vue
<label>Credential
  <select v-model="credentialsRef">
    <option :value="null">— none —</option>
    <option v-for="c in credStore.items" :key="c.id" :value="c.id">
      {{ c.name }} ({{ c.auth_type }})
    </option>
  </select>
</label>

<label>Access Port
  <input v-model.number="accessPort" type="number" min="1" max="65535" />
</label>
```

- [ ] **Step 3: Confirm TypeScript compiles**

```bash
cd web && npm run typecheck 2>&1 | head -20
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add web/apps/manage-portal/src/views/modals/HostForm.vue \
        web/apps/manage-portal/src/stores/hosts.ts
git commit -m "feat(credentials): HostForm — credential picker + access_port field"
```

---

## Task 13: Nav + router — add Credentials page

**Files:**
- Modify: `web/apps/manage-portal/src/nav.ts`
- Modify: `web/apps/manage-portal/src/router.ts`

- [ ] **Step 1: Update `nav.ts` — add Credentials under Inventory**

```ts
{
  label: 'Inventory',
  items: [
    { href: '#/inventory/tags',         label: 'Tags' },
    { href: '#/inventory/hosts',        label: 'Hosts' },
    { href: '#/inventory/credentials',  label: 'Credentials' },
    { href: '#/inventory/agents',       label: 'Agents' },
  ],
},
```

- [ ] **Step 2: Update `router.ts` — add credentials route**

After the agents route, add:
```ts
{ path: '/inventory/credentials', name: 'credentials', component: () => import('./views/Credentials.vue') },
```

- [ ] **Step 3: Build the frontend**

```bash
cd web/apps/manage-portal && npm run build 2>&1 | tail -10
```
Expected: build succeeds with no TypeScript errors.

- [ ] **Step 4: Run full Go build + unit tests**

```bash
cd /path/to/repo && go build ./... && go test ./...
```
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add web/apps/manage-portal/src/nav.ts web/apps/manage-portal/src/router.ts
git commit -m "feat(credentials): add Credentials nav + router route"
```

---

## Self-Review Checklist

The plan covers all spec sections:

| Spec requirement | Task |
|---|---|
| Migration v16 — manage_credentials + host columns | Task 1 |
| VaultClient — AppRole + token auth, Write/Read/Delete | Task 2 |
| Store interface + Postgres (List/Get/Create/Delete/CountHosts) | Task 3 |
| Admin handlers — List/Create/Delete + 503/409/502 paths | Task 4 |
| Worker handler — GetSecret proxies to Vault | Task 5 |
| Routes + server wiring + config Vault env vars | Task 6 |
| Host model + API — credentials_ref + access_port | Task 7 |
| EnqueuePortSurvey inherits credentials_ref from host | Task 8 |
| Scanner client GetCredential + runner fetch + Target | Task 9 |
| Frontend API client types + methods | Task 10 |
| Credentials Pinia store + Credentials.vue + CredentialForm.vue | Task 11 |
| HostForm credential picker + access_port | Task 12 |
| Nav + router | Task 13 |
