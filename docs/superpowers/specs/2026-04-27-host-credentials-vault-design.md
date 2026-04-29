# Host Credential Management with HashiCorp Vault — Design Spec

## Goal

Store SSH credentials for managed hosts in HashiCorp Vault. Credentials are a host property: created once in a shared library, assigned to hosts, and automatically used by port survey scan jobs. The manage server is the sole Vault writer; scanners fetch secrets through the Worker API at scan time.

> **WinRM deferred:** `winrm-password` credential type and `connection_type = 'winrm'` are reserved in the schema but carry no scanning implementation. WinRM rejected with `422` at the API layer until implemented.

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
  "password":    "ssh-password"
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

### Migration v15: `manage_credentials` updated schema

```sql
ALTER TABLE manage_credentials
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
```

### Migration v19: `manage_hosts` connection model

```sql
-- Rename access_port → port (generic field; SSH default 22)
ALTER TABLE manage_hosts RENAME COLUMN access_port TO port;

-- Connection type: how Triton reaches this host
-- 'winrm' is reserved in schema but rejected at API layer until scanning is implemented
ALTER TABLE manage_hosts
  ADD COLUMN IF NOT EXISTS connection_type TEXT NOT NULL DEFAULT 'ssh'
    CHECK (connection_type IN ('ssh', 'ssh_bastion', 'winrm', 'agent')),
  ADD COLUMN IF NOT EXISTS bastion_host_id UUID REFERENCES manage_hosts(id) ON DELETE SET NULL;
```

`credentials_ref` is nullable — hosts without credentials run unauthenticated port scans only. `port` defaults to 22; operators override only for non-standard SSH ports.

## Credential Types

| Type | Vault fields | Used with `connection_type` | Port default |
|---|---|---|---|
| `ssh-key` | username, private_key (PEM), passphrase? | `ssh`, `ssh_bastion` | 22 |
| `ssh-password` | username, password | `ssh`, `ssh_bastion` | 22 |
| `winrm-password` | username, password | `winrm` (reserved — deferred) | — |

**SSH key format:** PEM only (`-----BEGIN OPENSSH PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`). PPK (PuTTY format) is not supported — operators must convert with `puttygen key.ppk -O private-openssh -o key.pem`.

**Connection type and credential type must be consistent.** The API validates this:
- `connection_type = 'ssh'` or `'ssh_bastion'` → credential `auth_type` must be `ssh-key` or `ssh-password`
- `connection_type = 'agent'` → `credentials_ref` must be null
- `connection_type = 'winrm'` → rejected with `422 Unprocessable Entity` (scanning not yet implemented)

**Credentials are mutable.** Secret rotation is supported via `PUT /api/v1/admin/credentials/{id}` which writes a new Vault version at the same path. The credential ID and all host references stay unchanged — no unassignment required. Vault KV v2 retains the previous version; operators can roll back via the Vault UI if needed.

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
Body: { name, auth_type, username, private_key?, passphrase?, password? }
```
1. Validate fields per `auth_type` (username always required; private_key required for ssh-key; password required for ssh-password and winrm-password).
2. Generate `credential_id = uuid.New()`.
3. Construct `vault_path = {mount}/data/triton/{tenant_id}/credentials/{credential_id}`.
4. Write secret JSON to Vault.
5. Insert row into `manage_credentials`.
6. Return `201 Created` with metadata (no secret fields).

If Vault write fails, do not insert the DB row — return `502 Bad Gateway`.

**Update credential (rotation)**
```
PUT /api/v1/admin/credentials/{id}
Body: { username, private_key?, passphrase?, password? }
```
Writes a new version to the existing Vault path. The credential ID, name, auth_type, and all host references are unchanged. `updated_at` is bumped on the DB row. Returns `200 OK` with updated metadata.

Vault KV v2 retains the previous version automatically — rollback via Vault CLI/UI if needed. `name` and `auth_type` are not updatable; create a new credential to change those.

**Delete credential**
```
DELETE /api/v1/admin/credentials/{id}
```
1. Count hosts referencing this credential.
2. If count > 0, return `409 Conflict` with `{"error": "credential in use by N hosts"}`. Operator must unassign from all hosts first.
3. Delete from Vault (all versions).
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
3. Return `{ username, private_key?, passphrase?, password? }`.

Returns `404` if credential not found in DB, `502` if Vault fetch fails.

### Host API changes

`POST /api/v1/admin/hosts` and `PUT /api/v1/admin/hosts/{id}` accept:
```json
{
  "credentials_ref": "uuid-or-null",
  "port": 22,
  "connection_type": "ssh",
  "bastion_host_id": "uuid-or-null"
}
```

Validation rules:
- `connection_type` must be one of `ssh`, `ssh_bastion`, `agent` (`winrm` rejected with 422)
- `connection_type = 'ssh_bastion'` requires `bastion_host_id` (must reference an `ssh`-type host with a credential)
- `connection_type = 'agent'` requires `credentials_ref = null`
- When `credentials_ref` is set, the credential `auth_type` must be `ssh-key` or `ssh-password` (only SSH credentials are currently supported)

`GET /api/v1/admin/hosts` and `GET /api/v1/admin/hosts/{id}` include all four fields in the response.

## User Flow

### Step 1 — Create credentials (Credentials page)

Operator navigates to **Inventory → Credentials** (new nav item, below Hosts).

The page shows a table of existing credentials: name, type, number of hosts using it, created date, delete action. An **Add Credential** button opens a modal (`CredentialForm.vue`).

The form fields change based on selected auth type:
- **SSH Key**: Name, Username, Private Key (textarea, PEM), Passphrase (optional)
- **SSH Password**: Name, Username, Password

A credential can be updated (rotated) via an **Edit** action that opens a pre-filled form — name and type are read-only, only secret fields are editable.

Submitting a create writes to Vault via the Admin API and closes the modal. Submitting an edit writes a new Vault version.

### Step 2 — Assign credential to host (Hosts page)

The existing **Hosts** table gains a **Credential** and **Type** column.

The existing **Host edit modal** (`HostForm.vue`) gains new fields:
- **Connection Type** — selector: Direct SSH / SSH via Bastion / Agent
- **Bastion Host** — dropdown (visible only when SSH via Bastion selected); lists SSH-type hosts that have a credential
- **Credential** — dropdown populated from `GET /api/v1/admin/credentials`, filtered to SSH types. Hidden when Agent is selected.
- **Port** — number input. Auto-fills to 22. Editable. Hidden when Agent is selected.

Saving updates `connection_type`, `credentials_ref`, `port`, and `bastion_host_id` on the host row.

### Step 3 — Port survey scan (automatic)

No change to the scan creation flow. When a port survey job is dispatched:
1. `manage_scan_jobs` row carries `credentials_ref` copied from the host.
2. `triton-portscan` receives `credentials_ref` UUID in `ClaimResp`.
3. Scanner calls `GET /api/v1/worker/credentials/{id}` to fetch the secret.
4. Scanner uses the credential to authenticate the SSH connection during the scan.
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
| `pkg/manageserver/hosts/types.go` | Add `CredentialsRef`, `Port`, `ConnectionType`, `BastionHostID` to `Host`; `ConnectionType` constants |
| `pkg/manageserver/hosts/handlers_admin.go` | Accept + validate new fields; cross-validate credential type vs connection type |
| `pkg/manageserver/hosts/postgres.go` | Read/write `credentials_ref`, `port`, `connection_type`, `bastion_host_id` |
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
- `vault.go` — mock HTTP server for Write/Read/Delete/Update; AppRole login + renewal flow
- `postgres.go` — standard store tests; `CountHosts` returns correct reference count
- `handlers_admin.go` — 400 on invalid body; 409 on delete with hosts; 503 when vault nil; 200 on update (rotation)
- `handlers_admin.go` — cross-validation: winrm connection_type returns 422; agent host rejects credentials_ref
- `worker_handler.go` — 404 on missing credential; 502 on vault error
- `hosts/handlers_admin.go` — `credentials_ref`, `port`, `connection_type`, `bastion_host_id` round-trip

**Integration tests** (`//go:build integration`):
- `TestCreateCredential_WritesToVault` — requires a live Vault (skip if `TRITON_TEST_VAULT_ADDR` unset)
- `TestUpdateCredential_WritesNewVaultVersion` — rotation; old version accessible in Vault history
- `TestDeleteCredential_BlockedByHostReference`
- `TestGetSecret_ProxiesToVault`
- `TestHostConnectionType_Validation` — ssh_bastion requires bastion_host_id; agent rejects credentials_ref

**E2E tests** (`test/e2e/credentials.spec.js`):
- Vault dev container started automatically by manage test server via podman
- Create, update (rotate), delete credential flows
- HostForm: connection type selector; credential filtered by type; port auto-fill
- `CredentialForm.vue` — fields change on auth type switch; PEM validation inline; edit pre-fills read-only type

**Frontend:**
- `CredentialForm.vue` — fields change on auth type switch; PEM validation inline
- `HostForm.vue` — credential picker populates from store; access port pre-fills correctly

---

## Host Connection Types (Architecture Extension)

> **Status:** Design decided, not yet implemented. Captures decisions made 2026-04-29 for the next planning cycle.

### Problem

The current model assumes all hosts are reachable directly over SSH. Enterprise environments have three distinct connectivity patterns that require different handling:

1. **Direct SSH** — server is directly reachable from the Manage Server. Current behaviour.
2. **SSH via bastion** — server is in a private network segment. Manage Server SSHes to a hardened bastion (jump host), which proxies onward to the target. Required for air-gapped segments, DMZs, and most hardened enterprise networks.
3. **Agent-managed** — host has no listening SSH port (laptops, workstations, locked-down VMs). A `triton-agent` binary installed on the endpoint initiates an outbound connection to the Manage Server and receives scan tasks. No inbound ports required.

### Data Model Change

```sql
-- Migration v{N}: connection_type + bastion on manage_hosts
ALTER TABLE manage_hosts
  ADD COLUMN connection_type TEXT NOT NULL DEFAULT 'ssh'
    CHECK (connection_type IN ('ssh', 'ssh_bastion', 'agent')),
  ADD COLUMN bastion_host_id UUID REFERENCES manage_hosts(id);
```

`bastion_host_id` is only meaningful when `connection_type = 'ssh_bastion'`. It references another host row that is itself reachable directly (`connection_type = 'ssh'`). The bastion host must have a credential assigned.

### Connection Type Behaviour

| Type | SSH credential | Bastion | How scan reaches host |
|---|---|---|---|
| `ssh` | required | — | Direct TCP connect to `ip:ssh_port` |
| `ssh_bastion` | required | required | SSH ProxyJump: Manage Server → bastion → target |
| `agent` | — | — | Agent initiates outbound WebSocket/HTTPS to Manage Server; scan runs locally on endpoint |

For `ssh_bastion`, the scanner uses SSH `ProxyJump` (equivalent to `ssh -J bastion user@target`). The bastion credential and the target credential are fetched separately from Vault; the bastion is authenticated first, then the tunnel to the target is opened.

### Agent-Managed Hosts

`triton-agent` is already a binary in the Triton portfolio. For agent-managed hosts the flow is:

```
Endpoint (laptop/workstation)
  └── triton-agent (installed as OS service)
        ├── outbound HTTPS → Manage Server (poll for tasks)
        ├── runs scan locally
        └── pushes results → Manage Server
```

No inbound port is needed on the endpoint. The agent is the initiator. The Manage Server needs a reachable public or VPN endpoint.

Agent-managed hosts auto-register on first check-in — they appear in the host inventory without needing to be added manually or discovered via CIDR scan. The agent sends `hostname`, `ip`, `os` at registration time.

### Agent Deployment Methods

Enterprise IT deploys `triton-agent` at scale via standard tooling — no per-machine manual install:

**GPO (Windows, domain-joined machines only)**
- Requires Active Directory (on-premise or Azure AD hybrid)
- IT admin creates an MSI installer and pushes it via a Group Policy startup script or Software Installation policy
- Machines apply the policy on boot or within the default 90-minute refresh cycle
- Zero end-user interaction

**Microsoft Intune (Windows + macOS, cloud MDM)**
- Part of Microsoft 365 / Entra ID — no on-premise AD required
- Windows: deploy `.msi`/`.exe` as a managed app or run a PowerShell script
- macOS: deploy `.pkg` or run a shell script on enrolled devices
- Works for both corporate-owned and BYOD devices
- Best choice for organisations with remote/hybrid workforces

**Jamf (macOS + iOS focused)**
- Most common MDM in Apple-heavy enterprises, often paired with Intune for Windows
- Deploy `triton-agent.pkg` to computer groups; policies run at enrollment or on schedule
- Jamf Pro supports full scripting and remote commands

**Ansible / Chef / Puppet (Linux primarily)**
- Organisations already running orchestration tools can add a `triton-agent` role/cookbook
- Agent binary dropped + systemd unit installed in a single play

**Manual install (fallback)**
- Single-line install script for ad-hoc or small environments:
  ```
  curl -fsSL https://manage.example.com/agent/install.sh | sudo bash
  ```
  Script downloads the correct binary for the platform, installs as a system service, and registers with the Manage Server using a one-time enrollment token.

### Enrollment Token Flow

To prevent unauthorised agents from registering, each deployment uses a short-lived enrollment token generated by the Manage Server:

```
Manage Server Admin UI
  └── Generate enrollment token (valid 24h, single-use or N-use)
        └── Embed in GPO/MDM script / install command
              └── Agent presents token on first check-in → registered
```

Token is invalidated after use (or expiry). Subsequent check-ins use the agent's registered identity (UUID + shared secret issued at enrollment).

### UI Changes (future sprint)

- `HostForm.vue` — `connection_type` selector: SSH / SSH via Bastion / Agent
- When `ssh_bastion` selected: second dropdown "Bastion host" (filtered to `connection_type=ssh` hosts)
- When `agent` selected: credential and SSH port fields hidden; read-only "Agent last seen" timestamp shown
- `Hosts.vue` table — connection type badge per row (SSH / Bastion / Agent)
- New Manage Server admin page: **Enrollment Tokens** — generate, list active, revoke
