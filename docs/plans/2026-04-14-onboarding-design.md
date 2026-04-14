# Onboarding — Design Spec

**Date:** 2026-04-14
**Status:** Draft
**Scope:** Zero → first successful scan, ≤20 minutes unassisted
**Out of scope (own design cycles):** scheduling, reporting subscriptions, deployment automation for the portal, licensing model changes

---

## 1. Problem

New customers need to edit YAML inventories by hand, manage per-host credentials separately, and run `triton network-scan` from a CLI. There is no network discovery, no CSV import, no role separation, no remote agent install. A prospect cannot evaluate Triton against their network in a demo slot without an engineer walking them through command lines.

## 2. Goal

A new customer goes from "enrollment email" to "first scan result visible in the UI" in **under 20 minutes**, unassisted, across a 10-host mixed Linux/Windows environment. The experience works for both:
- Security officers who don't touch terminals
- Security engineers who want power-user control

## 3. Architecture overview

Three containers, one customer per org, SaaS-friendly.

```
  CLOUD                                ON-PREM (customer perimeter)

  ┌─ Triton Portal (container) ─┐      ┌─ Triton Engine (container) ─┐
  │ • /manage/* UI              │      │ • discovery (ICMP, TCP-SYN) │
  │ • /reports/* UI             │      │ • agentless scanners        │
  │ • REST API                  │◄─────│ • agent-push orchestrator   │
  │ • Engine Gateway            │ HTTPS│ • local encrypted keystore  │
  │ • PostgreSQL                │ only │   (credential SECRETS)      │
  │   — inventory               │outbd │ • agent gateway (inbound    │
  │   — credential METADATA     │      │   from pushed agents)       │
  │   — findings                │      └──────┬────────┬──────────┬──┘
  │   — audit                   │             │        │          │
  └──────────────┬──────────────┘          SSH│    WinRM│   SSH/NCf│
                 │                            ▼        ▼          ▼
  ┌─ Triton License Server ─────┐         Linux    Windows    Network
  │ (existing, unchanged)       │         hosts    hosts      devices
  └─────────────────────────────┘                  (+agents)
```

**Key properties:**
- Engine ↔ Portal: engine-initiated HTTPS only. No inbound firewall rules at the customer site.
- Credential secrets: live on engine only. Portal holds metadata and match rules; never sees plaintext.
- Agent flow: agents call **back to the engine** (never directly to portal). Customer perimeter stays closed.

## 4. Logical boundaries (10 bounded contexts)

| # | Context | Owns | Depends on |
|---|---|---|---|
| 1 | Identity | users, orgs, roles, sessions, invites | — |
| 2 | Inventory | hosts, groups, tags, CIDRs | Identity |
| 3 | Credentials | profiles + matchers (portal) / secrets (engine) | Identity, Inventory |
| 4 | Jobs | scan job queue, run history | Inventory, Credentials |
| 5 | Engine Gateway | engine enroll, poll-jobs, submit | Jobs, Credentials |
| 6 | Findings | raw results → extracted findings → read-models | Jobs |
| 7 | Reports | dashboards, exports | Findings |
| 8 | Fleet | installed agents, heartbeats, config push | Inventory, Engine Gateway |
| 9 | License | existing license server | — |
| 10 | Audit | write-only audit log | all (consumers only) |

**Dependency rule:** one-way, top-to-bottom. No cycles. Each context is a separate Go package (`pkg/portal/identity`, `pkg/portal/inventory`, …), separate DB schema (`identity.*`, `inventory.*`, …), internal APIs exposed only through its own package boundary.

**Packaging (MVP):** contexts 1-8 inside the portal container. Context 5 has a thin client embedded in the engine. Context 3 secret store lives on the engine. Context 9 unchanged. Future splits (ingestion/query, fleet service, secrets service) are deploy-config changes.

## 5. RBAC model

Three roles, per-org scope.

| Role | Inventory | Credentials | Scans | Reports | Users |
|---|---|---|---|---|---|
| Owner | CRUD | CRUD | trigger + (future) schedule | view | invite, assign roles |
| Engineer | CRUD | CRUD | trigger + (future) schedule | view | — |
| Officer | view | — | trigger on existing groups | view, (future) subscribe | — |

**Decisions baked in:**
- Officers can trigger scans on pre-defined groups (compliance ad-hoc audits)
- Officers cannot see credential secrets or names of bootstrap profiles
- No per-group permissions in MVP (all Engineers see all groups)
- Reuse existing JWT + `internal/auth/sessioncache/` + multi-tenant user model

## 6. Customer journey

**Step 1 — Onboarding wizard (Owner, first login, ~2 min)**
- Org name, timezone, license file upload (deferred redesign per separate brief)
- Invite teammates (skippable) with role selection
- "Download your engine bundle" → signed `.tar.gz` containing engine ID, private key, portal CA (used in Step 2)

**Step 2 — Engine enrollment (Engineer, ~3 min)**
- SCP/USB bundle to any Linux box with network access to target hosts and HTTPS egress to portal
- `podman run -v ./engine-bundle.tar.gz:/etc/triton/bundle triton/engine:latest`
- Engine extracts bundle, establishes mTLS to portal, appears in UI as "Engine X online, N.N.N.N"

**Step 3 — Add hosts (Engineer or Officer, ~5 min)**

Two paths, mixable:

- **CSV upload:** drag file → map columns (hostname, ip, os, group, tags) → dry-run preview (row count, duplicates flagged, group auto-create list) → import. 100 rows ≤3 seconds.
- **Network discovery:** enter CIDRs → pick probes (ICMP default, TCP-SYN on 22/80/443/3389/5985) → engine runs sweep → candidates stream into a table live → user selects rows → "Add N hosts to group prod-web with tags [env:prod, os:linux]"

**Step 4 — Credential profiles (Engineer, ~5 min)**
- "New profile" → name, auth method (ssh-password, ssh-key, winrm-password, bootstrap-admin), matcher rules (group=prod, os=linux, cidr=10.0.0.0/8)
- Secret is entered in the browser UI, encrypted **to the owning engine's public key** (fetched from portal's `/api/v1/engines/{id}/pubkey`), POSTed to portal → portal forwards the opaque ciphertext to the engine → engine decrypts with its private key and stores in local keystore → portal retains only the profile reference. **Portal never holds plaintext**, not even transiently.
- "Test against 3 random matches" button runs a probe (SSH version/uname or WinRM probe) and reports per-host success/failure

**Step 5 — Mode decision (Engineer, 30 sec)**
- Per-group default: **agentless** (ssh/winrm profile match required) OR **agent**
- Per-host override available in the host list
- Agent-mode groups need a bootstrap-admin profile attached

**Step 6 — First scan (Officer or Engineer, ~5 min including scan)**
- "Scan group prod-web now" → confirmation modal → job queued
- Portal streams engine's progress back to the UI (live per-host status, findings count as they arrive)
- On completion: summary card with "312 findings, 8 UNSAFE — view report →"
- Report UI opens on the standard dashboard already shipped (Phase 1-5 analytics)

**Step 7 — Post-scan nudges (non-blocking)**
- "Save this as a weekly schedule?" → takes user to Scheduling (separate project)
- "Email a summary to teammates?" → takes user to Reports subscriptions (separate project)

## 7. Security decisions

### 7.1 Engine enrollment (Q1 = b)

**Model:** pre-provisioned signed bundle, never an HTTPS OTP.

**Bundle format:** signed `.tar.gz` generated by portal when Owner clicks "New engine":
```
engine-<id>.tar.gz
├── engine.json          {engine_id, org_id, portal_url, created_at}
├── engine.key           engine private key (Ed25519)
├── engine.crt           signed by portal's engine-CA
├── portal-ca.crt        portal's root CA for mTLS trust
└── manifest.sig         Ed25519 signature over all above files by portal signing key
```

**Trust model:**
- Portal signs the bundle with an org-scoped signing key (generated on first Owner login, stored in portal KMS)
- Engine verifies `manifest.sig` on startup using the embedded `portal-ca.crt`
- Subsequent engine ↔ portal calls use mTLS with `engine.crt` + `engine.key`
- Bundle can only be used once: portal records `engine_id` as claimed on first successful handshake; a second claim from a different IP fails and emits audit+alert

**Revocation:** Owner clicks "Revoke engine X" → portal blacklists `engine_id` → next poll returns 401. Engine container must be redeployed with a fresh bundle.

### 7.2 Bootstrap admin credential (Q2 = b)

**Model:** admin credentials are stored as a credential profile of type `bootstrap-admin`, reused across agent-push jobs for a group.

**Storage:** same engine keystore as other secrets. Same AES-256-GCM. Key rotation applies equally.

**Usage scope:**
- Only used for agent-push jobs
- Never sent to a host for a regular scan (WinRM/SSH scans use the ordinary credential profiles)
- After the agent on a host is successfully bootstrapped, the bootstrap cred is never used against that host again — subsequent agent-host calls use the per-host agent cert (§7.3)

**Risk:** keystore compromise reveals an admin cred that covers a whole group. Mitigation: customers rotate the bootstrap profile after their fleet is bootstrapped (UI prompts this as a post-onboarding action).

### 7.3 Agent-host mutual auth (Q3 = b)

**Model:** per-host TLS client certificate minted by engine at push time.

**Flow:**
1. Engine generates an Ed25519 keypair for the target host
2. Engine signs a short-lived CSR with its engine cert, producing `agent.crt` + `agent.key` — valid for 90 days
3. Push phase installs the binary + cert + key + engine's CA cert onto the host (SSH SFTP or WinRM file copy)
4. Agent on first startup presents `agent.crt` over mTLS to the engine
5. Engine validates the cert chain (engine is the CA) and records `host_id`
6. Before expiry, agent rotates: calls engine's `/agent/renew` with current cert → gets a new one

**No shared secret ever crosses the wire.** The private key is generated on the engine and pushed alongside the cert — the only point of exposure is the push channel itself (already authenticated by the bootstrap admin credential).

**Compromise model:**
- Stolen agent cert+key: attacker can impersonate the host until rotation (90 days max). Mitigation: the engine tracks last-seen IP; mismatch triggers audit+alert.
- Stolen engine cert+key: attacker can mint rogue agent certs. Mitigation: engine cert is rotated on portal-side revocation (§7.1).

## 8. Data model additions

### 8.1 Portal schemas (PostgreSQL)

New tables (all under their respective schema namespaces).

**`inventory.groups`**
```
id              uuid primary key
org_id          uuid not null references identity.orgs(id)
name            text not null
description     text
created_at      timestamptz
created_by      uuid references identity.users(id)
unique (org_id, name)
```

**`inventory.hosts`**
```
id              uuid primary key
org_id          uuid not null
group_id        uuid not null references inventory.groups(id)
hostname        text
address         inet
os              text  -- linux|windows|macos|cisco-iosxe|juniper-junos
mode            text  -- agentless|agent
engine_id       uuid references engine.engines(id)  -- which engine owns this host
last_scan_id    uuid
last_seen       timestamptz
created_at      timestamptz
unique (org_id, hostname)
```

**`inventory.tags`**
```
host_id         uuid references inventory.hosts(id) on delete cascade
key             text
value           text
primary key (host_id, key)
```

**`inventory.cidrs`** (discovery scope per engine)
```
id              uuid primary key
org_id          uuid not null
engine_id       uuid not null
cidr            cidr not null
label           text
```

**`credentials.profiles`** (portal-side metadata only)
```
id              uuid primary key
org_id          uuid not null
name            text not null
auth_type       text not null  -- ssh-password|ssh-key|winrm-password|bootstrap-admin
matcher         jsonb not null -- {group_id, os, cidr, tag_keys}
owning_engine   uuid not null references engine.engines(id)
secret_ref      text not null  -- engine-local keystore id, opaque to portal
created_at      timestamptz
unique (org_id, name)
```

**`engine.engines`**
```
id              uuid primary key
org_id          uuid not null
label           text not null
public_ip       inet
bundle_issued_at timestamptz
first_seen_at   timestamptz
last_poll_at    timestamptz
status          text  -- enrolled|online|offline|revoked
revoked_at      timestamptz
```

**`jobs.jobs`**
```
id              uuid primary key
org_id          uuid not null
engine_id       uuid not null
group_id        uuid
host_ids        uuid[]
status          text  -- queued|running|completed|failed|cancelled
scan_profile    text
requested_by    uuid references identity.users(id)
requested_at    timestamptz
started_at      timestamptz
completed_at    timestamptz
error           text
```

**`fleet.agents`**
```
id              uuid primary key
host_id         uuid not null references inventory.hosts(id)
cert_fingerprint text not null
installed_at    timestamptz
last_heartbeat  timestamptz
version         text
```

**`identity.roles`** — already exists via multi-tenant work. New enum values: `owner`, `engineer`, `officer`.

### 8.2 Engine-side SQLite schema

**`local.secrets`**
```
id              text primary key  -- referenced by credentials.profiles.secret_ref
profile_id      text not null     -- uuid of portal profile
auth_type       text not null
payload         blob not null     -- AES-256-GCM(ciphertext)
nonce           blob not null
created_at      integer
updated_at      integer
```

## 9. Engine Gateway protocol

All endpoints under `/api/v1/engine/*` on the portal. mTLS-authenticated (cert from the enrollment bundle). Engine is always the client.

| Endpoint | Method | Purpose |
|---|---|---|
| `/enroll` | POST | One-time handshake. Engine presents bundle certificate; portal records `first_seen_at`. 401 on replay. |
| `/jobs/poll` | GET | Long-poll (30s). Returns next queued job for this engine, or 204. |
| `/jobs/{id}/ack` | POST | Engine acknowledges job, moves to `running`. |
| `/jobs/{id}/progress` | POST | Streaming endpoint for per-host progress updates. |
| `/jobs/{id}/submit` | POST | Final scan results (reuses existing scan-submit payload). |
| `/jobs/{id}/fail` | POST | Report job failure with error context. |
| `/credentials/push` | POST | Portal forwards opaque ciphertext (encrypted by the browser to engine's pubkey). Engine decrypts and stores. Portal never decrypts. |
| `/engines/{id}/pubkey` | GET | Public endpoint (no mTLS) returning the engine's public key so a browser can encrypt a new secret before POSTing to the portal. |
| `/credentials/delete` | POST | Portal instructs engine to purge a credential. |
| `/hosts/sync` | GET | Engine pulls inventory updates (new hosts assigned, removed hosts). |
| `/discovery/run` | POST | Portal requests a discovery sweep on specified CIDRs. |
| `/discovery/submit` | POST | Engine submits discovery candidates back. |
| `/agents/enroll` | POST | (engine-internal) agent presents cert, engine confirms + registers with portal via `/hosts/sync`. |

Payload formats: JSON, wire-compatible with existing `pkg/agent` submission path for scan results. Protobuf/gRPC is a post-MVP optimization if bandwidth becomes a concern.

## 10. Agent-push lifecycle

```
  USER CLICKS "PUSH AGENT TO GROUP dmz-win"
        │
        ▼
  Portal → engine: queue job of type "agent_push", host list, bootstrap-admin profile id
        │
        ▼
  Engine:
    for each host:
      1. Resolve bootstrap credential from local keystore
      2. Open transport (SSH for unix, WinRM for windows)
      3. Generate host keypair + CSR, sign with engine cert → agent.crt (90d)
      4. Copy: triton-agent binary, agent.crt, agent.key, engine-ca.crt, config.yaml
      5. Install as service (systemd / Windows SCM)
      6. Start service
      7. Emit progress "installed"
        │
        ▼
  Agent on host: first run
    1. Read config → engine endpoint
    2. mTLS handshake with engine using agent.crt
    3. POST /agents/register → engine records cert_fingerprint
    4. Engine POSTs portal /hosts/sync → mode=agent, cert_fingerprint stored
        │
        ▼
  Portal UI: host row flips from "agentless" to "agent (healthy)"
```

**Failure modes:**
- Transport fails (bad creds, host unreachable): engine reports failure, UI shows per-host error
- Binary push succeeds but agent doesn't register in 60s: engine marks host "agent-install-pending", user can retry
- Rollback: "Uninstall agent" action sends SSH/WinRM removal command using the same bootstrap cred

## 11. What the UI must expose (MVP minimum)

Page-level list, `/manage/*`:

1. **Dashboard** — "X engines online, Y hosts, Z agents, latest scan was N minutes ago"
2. **Engines** — list, enroll-new action, revoke, health
3. **Groups** — tree/flat toggle, create/rename/delete
4. **Hosts** — table with filter by tag/group/OS/mode; CSV import; discovery launcher
5. **Credentials** — profile CRUD with matcher preview ("matches 47 of 52 hosts")
6. **Scans** — "Scan now" button, live job progress, run history
7. **Users & roles** — invite, role change, revoke
8. **Audit** — searchable event log (who did what, when)

`/reports/*` stays as today (Phase 1-5 analytics).

## 12. Risks & mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Engine offline → scans stall silently | medium | high | Portal surfaces engine health prominently on dashboard; Officer-level alert when engine offline >5 min |
| Bundle leaked before first enrollment | low | high | Bundle single-use; Owner must re-generate if lost in transit; audit logs every bundle generation |
| Credential keystore compromise | low | high | Key derivation from bundle-bound master; rotation workflow documented; customers can wipe-and-redeploy engine |
| Agent cert expires unrenewed | medium | medium | 90d validity + renew at 75% → 22d slack; agent missing renewal = engine auto-disables scans + alerts |
| Bootstrap profile misconfigured → push to wrong hosts | medium | high | Matcher preview ("will push to these 47 hosts") + explicit confirmation per-group |
| Multi-tenant data leak between orgs | low | catastrophic | All queries scoped at repository layer by org_id; row-level security policies in PostgreSQL; per-org signing keys for bundles |

## 13. Deferred (explicit backlog)

Own design cycles, not in MVP:
- Scheduling + automation (scan cadence, off-hours windows, job queuing rules)
- Reporting subscriptions (scheduled email, PDF digests, exec summaries)
- License file refactor (pre-provisioned bundle model aligned with engine bundle)
- Deployment automation for the portal itself (Helm chart, Terraform)
- Cloud inventory sync (AWS/Azure/vCenter/AD import)
- SSO / SAML / OIDC
- API tokens per role
- HSM / Vault backend for engine keystore
- Agent auto-update
- Multi-engine routing rules (manual engine assignment per group until a customer asks for more)
- Air-gapped engine (no portal reachability — scans submitted via file transfer)

## 14. Success metric

A new customer going through the happy path:
- t+0min: receives enrollment email, clicks link
- t+2min: Owner finishes wizard, downloads bundle
- t+5min: engine running on a Linux VM inside customer network
- t+10min: inventory populated (CSV of 10 hosts OR discovery sweep)
- t+12min: credential profile defined, tested green against 3 hosts
- t+15min: "Scan now" clicked
- t+18min: first finding appears in report view
- t+20min: scan complete, summary shown

**Measured via:** portal audit log timestamps per org's first 24 hours. Target: p50 ≤20min, p90 ≤45min.
