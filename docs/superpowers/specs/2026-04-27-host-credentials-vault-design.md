# Host Credential Management with HashiCorp Vault — Design Spec

## Goal

Store SSH and WinRM credentials for managed hosts in HashiCorp Vault. Credentials are a host property: created once in a shared library, assigned to hosts, and automatically used by port survey scan jobs. The manage server is the sole Vault writer; scanners fetch secrets through the Worker API at scan time.

## Architecture

```
Operator → Credentials page → Manage Server → Vault KV v2 (write)
triton-portscan → Worker API → Manage Server → Vault KV v2 (read)
```

Triton never stores secret material in its own database. Only credential metadata (name, auth type, Vault path) lives in Postgres. The Vault path is the source of truth for the actual secret.

### Vault connection

Configured at deployment time via environment variables — no UI, no post-deployment reconfiguration needed.

```
TRITON_VAULT_ADDR          https://vault.internal:8200   (required)
TRITON_VAULT_MOUNT         secret                        (KV v2 mount, default: secret)
TRITON_VAULT_TOKEN         s.xxxx                        (simple token auth)
  — OR —
TRITON_VAULT_ROLE_ID       ...                           (AppRole auth, recommended)
TRITON_VAULT_SECRET_ID     ...
```

AppRole is recommended for production — the `secret_id` can be rotated without redeployment. Token auth is accepted for simpler setups.

If neither token nor AppRole env vars are set, the manage server starts normally but all credential API endpoints return `503 Service Unavailable` with `{"error": "vault not configured"}`.

### Vault secret path

```
{mount}/data/triton/{tenant_id}/credentials/{credential_id}
```

KV v2 requires the `/data/` prefix on write/read paths. The path is stored verbatim in `manage_credentials.vault_path` so it can be constructed once at creation and reused without any string manipulation at read time.

### Secret JSON structure in Vault

All fields are stored; unused fields are omitted when writing (not stored as empty strings). Readers ignore fields they don't need based on `auth_type`.

```json
{
  "username":    "ubuntu",
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "passphrase":  "optional-key-passphrase",
  "password":    "ssh-or-winrm-password",
  "use_https":   false
}
```

## Data Model

### Migration v15: `manage_credentials` table

```sql
CREATE TABLE manage_credentials (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID        NOT NULL,
  name        TEXT        NOT NULL,
  auth_type   TEXT        NOT NULL CHECK (auth_type IN ('ssh-key', 'ssh-password', 'winrm-password')),
  vault_path  TEXT        NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, name)
);
```

Name is unique per tenant — prevents duplicate entries confusing operators.

### Migration v15: `manage_hosts` changes

```sql
ALTER TABLE manage_hosts
  ADD COLUMN credentials_ref UUID REFERENCES manage_credentials(id),
  ADD COLUMN access_port     INT  NOT NULL DEFAULT 22;
```

`credentials_ref` is nullable — hosts without credentials assigned run port survey scans without SSH/WinRM access. `access_port` defaults to 22; operators change it only for hosts on non-standard ports.

## Credential Types

| Type | Vault fields used | Access port default |
|---|---|---|
| `ssh-key` | username, private_key (PEM only), passphrase (optional) | 22 |
| `ssh-password` | username, password | 22 |
| `winrm-password` | username, password, use_https | 5985 (HTTP) or 5986 (HTTPS) |

**SSH key format:** PEM only (`-----BEGIN OPENSSH PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`). PPK (PuTTY format) is not supported — operators must convert with `puttygen key.ppk -O private-openssh -o key.pem`.

**WinRM HTTPS:** When `use_https: true`, the scanner connects on port 5986 (ignoring `access_port`). When `false`, connects on `access_port` (default 5985 for WinRM credentials).

**Credentials are immutable after creation.** To rotate a secret, delete the credential and recreate it. This keeps the audit trail clean — no partial updates, no version confusion.

## API

### Admin API — credential CRUD

All endpoints require JWT auth and are tenant-scoped.

**List credentials**
```
GET /api/v1/admin/credentials
```
Response: array of `{ id, name, auth_type, vault_path, in_use_count, created_at }`. `in_use_count` is the number of hosts referencing this credential — shown in the UI to inform deletion decisions.

**Create credential**
```
POST /api/v1/admin/credentials
Body: { name, auth_type, username, private_key?, passphrase?, password?, use_https? }
```
1. Validate fields per `auth_type` (username always required; private_key required for ssh-key; password required for ssh-password and winrm-password).
2. Generate `credential_id = uuid.New()`.
3. Construct `vault_path = {mount}/data/triton/{tenant_id}/credentials/{credential_id}`.
4. Write secret JSON to Vault.
5. Insert row into `manage_credentials`.
6. Return `201 Created` with metadata (no secret fields).

If Vault write fails, do not insert the DB row — return `502 Bad Gateway`.

**Delete credential**
```
DELETE /api/v1/admin/credentials/{id}
```
1. Count hosts referencing this credential.
2. If count > 0, return `409 Conflict` with `{"error": "credential in use by N hosts"}`. Operator must unassign from all hosts first.
3. Delete from Vault.
4. Delete DB row.

If Vault delete fails, still delete the DB row — a dangling Vault secret is safe (no path reference remains).

### Worker API — secret fetch for scanner

Requires `X-Worker-Key` authentication (same as existing Worker API).

**Fetch credential secret**
```
GET /api/v1/worker/credentials/{id}
```
1. Look up `manage_credentials` by `id` (no tenant scoping — worker key grants access across tenants).
2. Fetch secret from Vault at `vault_path`.
3. Return `{ username, private_key?, passphrase?, password?, use_https? }`.

Returns `404` if credential not found in DB, `502` if Vault fetch fails.

### Host API changes

`POST /api/v1/admin/hosts` and `PUT /api/v1/admin/hosts/{id}` accept two new optional fields:
```json
{ "credentials_ref": "uuid-or-null", "access_port": 22 }
```

`GET /api/v1/admin/hosts` and `GET /api/v1/admin/hosts/{id}` include `credentials_ref` and `access_port` in the response.

## User Flow

### Step 1 — Create credentials (Credentials page)

Operator navigates to **Inventory → Credentials** (new nav item, below Hosts).

The page shows a table of existing credentials: name, type, number of hosts using it, created date, delete action. An **Add Credential** button opens a modal (`CredentialForm.vue`).

The form fields change based on selected auth type:
- **SSH Key**: Name, Username, Private Key (textarea, PEM), Passphrase (optional)
- **SSH Password**: Name, Username, Password
- **WinRM Password**: Name, Username, Password, Use HTTPS toggle

Submitting writes to Vault via the Admin API and closes the modal.

### Step 2 — Assign credential to host (Hosts page)

The existing **Hosts** table gains a **Credential** column showing a badge (credential name) or "—" for unassigned.

The existing **Host edit modal** (`HostForm.vue`) gains two new fields at the bottom:
- **Credential** — dropdown populated from `GET /api/v1/admin/credentials`. Shows name + type. Includes a "— none —" option.
- **Access Port** — number input, default pre-filled as 22 when an SSH credential is selected, 5985 when WinRM is selected.

Saving updates `credentials_ref` and `access_port` on the host row.

### Step 3 — Port survey scan (automatic)

No change to the scan creation flow. When a port survey job is dispatched:
1. `manage_scan_jobs` row carries `credentials_ref` copied from the host.
2. `triton-portscan` receives `credentials_ref` UUID in `ClaimResp`.
3. Scanner calls `GET /api/v1/worker/credentials/{id}` to fetch the secret.
4. Scanner uses the credential to authenticate SSH/WinRM connections during the scan.
5. If `credentials_ref` is nil, scanner proceeds without authentication (unauthenticated port scan only).

## Package Structure

**New package: `pkg/manageserver/credentials/`**

| File | Responsibility |
|---|---|
| `types.go` | `Credential` struct, `AuthType` constants, `SecretPayload` struct |
| `store.go` | `Store` interface: `List`, `Get`, `Create`, `Delete`, `CountHosts` |
| `postgres.go` | Postgres implementation of Store |
| `vault.go` | Vault KV v2 client: `Write`, `Read`, `Delete`; AppRole + token auth |
| `handlers_admin.go` | `AdminHandlers`: `List`, `Create`, `Delete` |
| `worker_handler.go` | `WorkerHandler`: `GetSecret` |
| `routes.go` | Mount admin + worker routes |

**Modified files:**

| File | Change |
|---|---|
| `pkg/manageserver/hosts/types.go` | Add `CredentialsRef *uuid.UUID`, `AccessPort int` to `Host` |
| `pkg/manageserver/hosts/handlers_admin.go` | Accept + persist new fields |
| `pkg/manageserver/hosts/postgres.go` | Read/write `credentials_ref`, `access_port` |
| `pkg/manageserver/scanjobs/handlers_admin.go` | On `EnqueuePortSurvey`, look up the host row and set `credentials_ref` from `host.credentials_ref` — any client-supplied `credentials_ref` in the request body is ignored |
| `pkg/manageserver/server.go` | Wire credential routes; init Vault client from env |
| `pkg/manageserver/config.go` | Add `VaultAddr`, `VaultMount`, `VaultToken`, `VaultRoleID`, `VaultSecretID` |
| `pkg/scanrunner/client.go` | Add `GetCredential(ctx, id)` method |
| `pkg/scanrunner/runner.go` | Fetch + pass credential when `ClaimResp.CredentialsRef != nil` |
| `managestore/migrations.go` | Migration v15: `manage_credentials` table + host columns |

**New frontend files (`web/apps/manage-portal/src/`):**

| File | Responsibility |
|---|---|
| `views/Credentials.vue` | Credentials list page: table, delete with in-use guard |
| `views/modals/CredentialForm.vue` | Create modal: dynamic fields per auth type |
| `stores/credentials.ts` | Pinia store: `list`, `create`, `remove` |
| `router.ts` | Add `/inventory/credentials` route |
| `nav.ts` | Add Credentials nav item under Inventory |

**Modified frontend files:**

| File | Change |
|---|---|
| `views/modals/HostForm.vue` | Add Credential picker + Access Port field |
| `stores/hosts.ts` | Include `credentials_ref`, `access_port` in create/update |

## Vault Client Design

The Vault client (`vault.go`) is a thin HTTP wrapper — no Vault SDK dependency (avoids a large transitive dependency tree). It uses the standard `net/http` client with a 10s timeout.

**Auth strategy:**
1. On startup, check env vars: if `TRITON_VAULT_ROLE_ID` is set, use AppRole login to obtain a token. Cache the token; re-login when it expires (check `auth.lease_duration`).
2. If only `TRITON_VAULT_TOKEN` is set, use it directly (no renewal — operator manages rotation).
3. If neither is set, Vault client is nil; handlers return 503.

**KV v2 paths:**
- Write: `PUT {addr}/v1/{mount}/data/{path}` with body `{"data": {...}}`
- Read: `GET {addr}/v1/{mount}/data/{path}`
- Delete: `DELETE {addr}/v1/{mount}/data/{path}` (deletes latest version only; metadata retained)

## Error Handling

| Scenario | Response |
|---|---|
| Vault not configured | `503` — `vault not configured` |
| Vault unreachable on create | `502` — DB row not written |
| Vault unreachable on delete | Delete DB row anyway; log warning |
| Vault unreachable on secret fetch | `502` — scanner retries via job heartbeat timeout |
| Credential in use on delete | `409` — `credential in use by N hosts` |
| Credential not found | `404` |
| Invalid PEM on ssh-key create | `400` — `private_key must be PEM format` |

## Testing

**Unit tests:**
- `vault.go` — mock HTTP server for Write/Read/Delete; AppRole login flow
- `postgres.go` — standard store tests; `CountHosts` returns correct reference count
- `handlers_admin.go` — 400 on invalid body; 409 on delete with hosts; 503 when vault nil
- `worker_handler.go` — 404 on missing credential; 502 on vault error
- `hosts/handlers_admin.go` — `credentials_ref` and `access_port` round-trip

**Integration tests** (`//go:build integration`):
- `TestCreateCredential_WritesToVault` — requires a live Vault (skip if `TRITON_TEST_VAULT_ADDR` unset)
- `TestDeleteCredential_BlockedByHostReference`
- `TestGetSecret_ProxiesToVault`

**Frontend:**
- `CredentialForm.vue` — fields change on auth type switch; PEM validation inline
- `HostForm.vue` — credential picker populates from store; access port pre-fills correctly
