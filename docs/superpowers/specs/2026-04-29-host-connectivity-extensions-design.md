# Host Connectivity Extensions — Design Spec

## Goal

Extend Triton's host connectivity model beyond direct SSH to support two enterprise patterns:

1. **SSH via Bastion** — target host is in a private network; a hardened jump host (bastion) proxies the SSH connection.
2. **Agent-managed** — target host has no SSH port open (laptop, workstation, locked-down VM); a `triton-agent` binary installed on the endpoint initiates an outbound connection to the Manage Server and runs scans locally.

Both features share the same `connection_type` field added to `manage_hosts`.

---

## Feature 1: SSH via Bastion

### How It Works

```
Manage Server
  └── SSH → Bastion host (port 22, public/VPN-reachable)
               └── SSH ProxyJump → Target host (port 22, private network only)
```

The target host still has SSH enabled — it is just not directly reachable from the Manage Server. All traffic tunnels through the bastion. This is standard OpenSSH `ProxyJump` behaviour (`ssh -J bastion user@target`).

The bastion itself is a host in Triton's inventory with `connection_type = 'ssh'` and its own credential assigned. The target host has `connection_type = 'ssh_bastion'` and a `bastion_host_id` pointing to the bastion row.

### Data Model

```sql
-- Already planned in migration v{N} (credentials vault sprint):
-- manage_hosts gains connection_type + bastion_host_id

ALTER TABLE manage_hosts
  ADD COLUMN connection_type TEXT NOT NULL DEFAULT 'ssh'
    CHECK (connection_type IN ('ssh', 'ssh_bastion', 'agent')),
  ADD COLUMN bastion_host_id UUID REFERENCES manage_hosts(id);
```

Constraints enforced at the application layer (not DB):
- `bastion_host_id` must be non-null when `connection_type = 'ssh_bastion'`
- `bastion_host_id` must reference a host with `connection_type = 'ssh'` (no chaining bastions)
- The bastion host must have a `credentials_ref` assigned
- The target host must also have its own `credentials_ref` assigned (separate credential)

### Scan Execution Flow

When a port survey job is dispatched for a `ssh_bastion` host:

1. `manage_scan_jobs` row stores: `target_host_id`, `credentials_ref` (target's), `bastion_host_id`, `bastion_credentials_ref` (bastion's) — both populated at enqueue time from the host row.
2. `triton-portscan` claims the job — `ClaimResp` now carries both credential IDs and the bastion's IP/port.
3. Scanner calls `GET /api/v1/worker/credentials/{target_cred_id}` and `GET /api/v1/worker/credentials/{bastion_cred_id}`.
4. Scanner opens SSH connection to bastion using bastion credential.
5. Via the bastion SSH session, opens a proxied TCP connection to the target's `ip:ssh_port`.
6. Authenticates to target using target credential over the proxied connection.
7. Runs scan normally through the tunnel.

### API Changes

**`manage_scan_jobs` table additions:**
```sql
ALTER TABLE manage_scan_jobs
  ADD COLUMN bastion_host_id      UUID REFERENCES manage_hosts(id),
  ADD COLUMN bastion_host_ip      TEXT,
  ADD COLUMN bastion_ssh_port     INT,
  ADD COLUMN bastion_credentials_ref UUID REFERENCES manage_credentials(id);
```

Stored at enqueue time so the scanner doesn't need to re-query the host table — all connectivity info is self-contained in the job row.

**`ClaimResp` additions (Worker API):**
```json
{
  "job_id": "...",
  "host_ip": "10.0.1.50",
  "ssh_port": 22,
  "credentials_ref": "uuid",
  "bastion_ip": "203.0.113.10",
  "bastion_ssh_port": 22,
  "bastion_credentials_ref": "uuid"
}
```

`bastion_ip` and `bastion_credentials_ref` are omitted when `connection_type = 'ssh'`.

**Host CRUD API (`/api/v1/admin/hosts`):**

Accept and return two new optional fields:
```json
{
  "connection_type": "ssh_bastion",
  "bastion_host_id": "uuid"
}
```

Validation:
- `connection_type` must be one of `ssh`, `ssh_bastion`, `agent`
- If `ssh_bastion`, `bastion_host_id` must be provided and must reference a `ssh`-type host
- If `agent`, `bastion_host_id` must be absent; `credentials_ref` must be absent

### UI Changes

**HostForm.vue** — new field "Connection Type" (radio or select):

```
○ Direct SSH        (default)
○ SSH via Bastion
○ Agent-managed
```

When **SSH via Bastion** selected:
- Show "Bastion Host" dropdown — lists only hosts with `connection_type = 'ssh'` that have a credential assigned
- Credential and SSH Port fields remain (for the target)

When **Agent-managed** selected:
- Hide Credential, SSH Port, Bastion Host fields
- Show read-only info box: "This host will appear online once triton-agent checks in."

**Hosts.vue table** — new "Type" badge column:

| Badge | Meaning |
|---|---|
| `SSH` | Direct SSH |
| `Bastion` | SSH via jump host |
| `Agent` | Agent-managed |

---

## Feature 2: Agent-Managed Hosts

### How It Works

```
Laptop / Workstation (no SSH)
  └── triton-agent (installed as OS service)
        ├── registers → POST /api/v1/agent/register   (one-time, uses enrollment token)
        ├── polls     → GET  /api/v1/agent/poll        (long-poll, waits for tasks)
        ├── runs scan locally
        └── posts result → POST /api/v1/agent/result
```

The Manage Server never initiates a connection to the endpoint. The agent initiates all connections outbound over HTTPS (port 443). This works through NAT, home networks, and corporate firewalls without any firewall rule changes on the endpoint side.

The Manage Server must be reachable by the agent — either via a public hostname or over VPN.

### Enrollment Flow

Before an agent can register, an operator generates a short-lived **enrollment token** in the Manage Server UI. The token is embedded in the install command or GPO/MDM script.

```
1. Operator: POST /api/v1/admin/enrollment-tokens
   → { token: "enroll-abc123", expires_at: "+24h", max_uses: 100 }

2. IT embeds token in deployment:
   GPO startup script:
     triton-agent.exe --register --server https://manage.example.com --token enroll-abc123

3. Agent first boot:
   POST /api/v1/agent/register
   Body: { enrollment_token: "enroll-abc123", hostname: "laptop-01", ip: "192.168.1.55", os: "windows" }
   → { agent_id: "uuid", agent_secret: "long-random-hex" }
   Agent saves agent_id + agent_secret to local config (encrypted at rest)

4. Enrollment token use count incremented; invalidated when max_uses reached or expires
```

### Agent Identity & Authentication

After registration, the agent authenticates using `agent_id` + `agent_secret` (HMAC-SHA256 request signing or a simple `Authorization: Bearer {agent_secret}` header — simpler, sufficient for HTTPS-only transport).

The Manage Server stores:
```sql
CREATE TABLE manage_agents (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID        NOT NULL,
  host_id      UUID        REFERENCES manage_hosts(id),  -- linked after registration
  hostname     TEXT        NOT NULL,
  ip           TEXT,
  os           TEXT,
  agent_secret TEXT        NOT NULL,  -- bcrypt hash of the issued secret
  last_seen_at TIMESTAMPTZ,
  enrolled_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status       TEXT        NOT NULL DEFAULT 'pending'  -- pending | active | revoked
);
```

`host_id` is initially NULL — after registration, the Manage Server either:
- Auto-creates a host row (if hostname not already in inventory), or
- Prompts the operator to link the agent to an existing host row (UI flow)

### Auto-Registration vs Manual Link

**Auto-create (default):** Agent check-in creates a new host row with `connection_type = 'agent'`, `hostname`, and `ip` from the agent's self-report. Operator sees the new host in inventory immediately.

**Manual link:** Operator pre-creates a host row with `connection_type = 'agent'` (placeholder, no IP yet). When the agent registers, it matches by hostname and links automatically. Useful when the host is already tracked in inventory before the agent is deployed.

### Long-Poll Protocol

The agent polls the Manage Server for tasks:

```
GET /api/v1/agent/poll
Authorization: Bearer {agent_secret}
X-Agent-ID: {agent_id}
```

Server holds the connection open up to 30 seconds (long-poll). If no task is available, returns `204 No Content`. If a task is dispatched, returns `200 OK` with the task payload:

```json
{
  "task_id": "uuid",
  "type": "scan",
  "profile": "standard",
  "modules": ["certificate", "key", "library"],
  "scan_path": "/",
  "resource_limits": { "max_memory": "512MB", "max_duration": "30m" }
}
```

Agent re-polls immediately after completing a task or after a 30-second timeout. This gives near-real-time task dispatch without persistent connections or WebSockets.

**Heartbeat:** The poll request itself serves as a heartbeat. `last_seen_at` on `manage_agents` is updated on every poll. Hosts not seen in 24h are shown as "offline" in the UI.

### Scan Execution on Agent

1. Agent receives task via long-poll response.
2. Agent runs `triton scan` locally (same binary, same scan engine, same profiles).
3. On completion, agent posts result:

```
POST /api/v1/agent/result
Authorization: Bearer {agent_secret}
X-Agent-ID: {agent_id}
Body: { task_id: "uuid", scan_result: { ... } }  (same JSON structure as normal scan result)
```

4. Manage Server stores the result and links it to the host's scan history.
5. Result flows through the normal report pipeline (same as SSH-initiated scans).

### Enrollment Token API

**Admin API — enrollment tokens:**

```
POST /api/v1/admin/enrollment-tokens
Body: { label: "Q2 laptop rollout", expires_in: "24h", max_uses: 500 }
→ 201: { id, token, label, expires_at, max_uses, use_count }

GET /api/v1/admin/enrollment-tokens
→ 200: [ { id, label, expires_at, max_uses, use_count, status } ]
  status: active | expired | exhausted | revoked

DELETE /api/v1/admin/enrollment-tokens/{id}
→ 204 (revoke — existing registered agents unaffected)
```

Token value is shown only once at creation time (same pattern as API keys). Manage Server stores a bcrypt hash.

### Install Commands

The agent install page (Manage Server UI) auto-generates platform-specific install commands with the enrollment token pre-filled:

**Linux (systemd):**
```bash
curl -fsSL https://manage.example.com/agent/install.sh | \
  sudo TRITON_SERVER=https://manage.example.com \
       TRITON_TOKEN=enroll-abc123 \
       bash
```

**Windows (PowerShell via GPO/Intune):**
```powershell
$env:TRITON_SERVER = "https://manage.example.com"
$env:TRITON_TOKEN  = "enroll-abc123"
Invoke-Expression (Invoke-WebRequest https://manage.example.com/agent/install.ps1).Content
```

**macOS (Jamf policy script):**
```bash
TRITON_SERVER=https://manage.example.com \
TRITON_TOKEN=enroll-abc123 \
/usr/local/bin/triton-agent --register
```

The install script downloads the correct `triton-agent` binary for the platform (from Manage Server's `/agent/download/{os}/{arch}` endpoint), installs it as a system service, and runs the registration handshake.

---

## Data Model Summary

### New tables

```sql
-- Enrollment tokens
CREATE TABLE manage_enrollment_tokens (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID        NOT NULL,
  label      TEXT        NOT NULL,
  token_hash TEXT        NOT NULL,   -- bcrypt of the issued token
  expires_at TIMESTAMPTZ NOT NULL,
  max_uses   INT         NOT NULL DEFAULT 1,
  use_count  INT         NOT NULL DEFAULT 0,
  revoked    BOOL        NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Registered agents
CREATE TABLE manage_agents (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID        NOT NULL,
  host_id      UUID        REFERENCES manage_hosts(id) ON DELETE SET NULL,
  hostname     TEXT        NOT NULL,
  ip           TEXT,
  os           TEXT,
  agent_secret TEXT        NOT NULL,   -- bcrypt hash
  last_seen_at TIMESTAMPTZ,
  enrolled_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status       TEXT        NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'active', 'revoked'))
);
```

### Modified tables

```sql
-- manage_hosts
ALTER TABLE manage_hosts
  ADD COLUMN connection_type TEXT NOT NULL DEFAULT 'ssh'
    CHECK (connection_type IN ('ssh', 'ssh_bastion', 'agent')),
  ADD COLUMN bastion_host_id UUID REFERENCES manage_hosts(id);

-- manage_scan_jobs
ALTER TABLE manage_scan_jobs
  ADD COLUMN bastion_host_id         UUID REFERENCES manage_hosts(id),
  ADD COLUMN bastion_host_ip         TEXT,
  ADD COLUMN bastion_ssh_port        INT,
  ADD COLUMN bastion_credentials_ref UUID REFERENCES manage_credentials(id);
```

---

## Package Structure

### New packages

| Package | Responsibility |
|---|---|
| `pkg/manageserver/agentgateway/` | Agent registration, long-poll, result ingestion |
| `pkg/manageserver/enrollmenttokens/` | Enrollment token CRUD |

### New files in existing packages

| File | Change |
|---|---|
| `pkg/manageserver/hosts/types.go` | Add `ConnectionType`, `BastionHostID` to `Host` |
| `pkg/manageserver/hosts/handlers_admin.go` | Validate connection_type + bastion_host_id |
| `pkg/manageserver/scanjobs/types.go` | Add bastion fields to `ScanJob` |
| `pkg/manageserver/scanjobs/handlers_admin.go` | Populate bastion fields at enqueue |
| `pkg/manageserver/scanjobs/handlers_worker.go` | Include bastion fields in `ClaimResp` |
| `pkg/scanrunner/runner.go` | If `BastinoIP` set, dial via SSH ProxyJump |
| `pkg/manageserver/server.go` | Mount agentgateway + enrollmenttokens routes |

### New frontend files

| File | Responsibility |
|---|---|
| `views/EnrollmentTokens.vue` | List tokens, generate new, revoke |
| `views/AgentHosts.vue` | List agent-managed hosts, show online/offline status |
| `stores/enrollmentTokens.ts` | Pinia store for token CRUD |

### Modified frontend files

| File | Change |
|---|---|
| `views/modals/HostForm.vue` | Connection type selector; conditional bastion picker |
| `views/Hosts.vue` | Connection type badge column |
| `router.ts` | Add `/inventory/enrollment-tokens` route |
| `nav.ts` | Add "Enrollment Tokens" nav item under Inventory |

---

## API Summary

### Agent API (no JWT — uses agent_secret)

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/agent/register` | First-time registration with enrollment token |
| `GET` | `/api/v1/agent/poll` | Long-poll for next task (30s timeout) |
| `POST` | `/api/v1/agent/result` | Submit completed scan result |
| `GET` | `/api/v1/agent/download/{os}/{arch}` | Download triton-agent binary |
| `GET` | `/api/v1/agent/install.sh` | Linux/macOS install script |
| `GET` | `/api/v1/agent/install.ps1` | Windows PowerShell install script |

### Admin API additions

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/admin/enrollment-tokens` | Create enrollment token |
| `GET` | `/api/v1/admin/enrollment-tokens` | List enrollment tokens |
| `DELETE` | `/api/v1/admin/enrollment-tokens/{id}` | Revoke token |
| `GET` | `/api/v1/admin/agents` | List registered agents with status |
| `DELETE` | `/api/v1/admin/agents/{id}` | Revoke agent registration |

---

## Security Considerations

**Bastion:**
- Both credentials are fetched from Vault at scan time — never stored in the job row in plaintext
- SSH host key verification: first connection to bastion stores the host key; subsequent connections verify it (prevents MITM on the bastion hop)
- Bastion cannot chain to another bastion (enforced at API validation)

**Agent:**
- Enrollment tokens are short-lived (24h default) and use-count limited — limits blast radius of a leaked token
- Agent secret is bcrypt-hashed in the DB — Manage Server never stores the plaintext secret
- All agent communication is HTTPS — TLS required; HTTP rejected
- Agent result endpoint validates `task_id` matches an outstanding task for that agent — prevents result injection
- Revoked agents are refused on every poll — no cached session

---

## Testing

### Bastion

- Unit: `runners/runner.go` — mock SSH dialer; verify ProxyJump path taken when `BastinoIP` set
- Unit: `scanjobs/handlers_admin.go` — bastion fields populated correctly at enqueue
- Integration: `TestBastionScan_EndToEnd` — requires two SSH containers (bastion + target); skip if `TRITON_TEST_BASTION` unset

### Agent

- Unit: `agentgateway/register.go` — token hash check; auto-host-create; manual-link by hostname
- Unit: `agentgateway/poll.go` — returns 204 on no task; returns task when enqueued; updates last_seen_at
- Unit: `agentgateway/result.go` — task_id validation; result stored correctly
- Unit: `enrollmenttokens/handlers.go` — expiry check; use_count limit; revoke
- Integration: `TestAgentRegistration_EndToEnd` — real agent binary registers, polls, receives task, submits result
- Integration: `TestEnrollmentToken_MaxUses` — token rejected after max_uses reached
