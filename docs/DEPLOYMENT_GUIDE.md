# Triton Multi-Tenant Deployment Guide

This guide covers deploying Triton's client-server stack in either **single-tenant** (one org, simple) or **multi-tenant** (several orgs, license server + report server + agents) mode. The architecture introduced in Phases 1–4 of the multi-tenant rework and hardened in Phase 5 is the baseline.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Quick Start (Single-Tenant)](#3-quick-start-single-tenant)
4. [Multi-Tenant Deployment](#4-multi-tenant-deployment)
5. [Report Server](#5-report-server)
6. [License Server](#6-license-server)
7. [Agent Deployment](#7-agent-deployment)
8. [Authentication Modes](#8-authentication-modes)
9. [Org Provisioning & Invite Flow](#9-org-provisioning--invite-flow)
10. [Security Configuration](#10-security-configuration)
11. [Production Checklist](#11-production-checklist)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Architecture Overview

Triton in multi-tenant mode runs **three** cooperating services plus PostgreSQL. The split-identity architecture puts superadmins (platform operators) on the license server and org users (customers, their admins, their read-only users) on the report server.

```
                         ┌─────────────────────────┐
                         │      License Server     │
                         │   (pkg/licenseserver)   │
                         │                         │
   superadmin login ────>│  /auth/login            │
   admin API (X-Key) ───>│  /admin/orgs            │
                         │  /admin/superadmins     │
                         │  /admin/licenses        │
                         │                         │
                         │  • Ed25519 JWT signer   │
                         │  • Resend mailer (opt)  │
                         │  • Rate limiter         │
                         └──────────┬──────────────┘
                                    │ cross-server provisioning
                                    │ (POST /api/v1/admin/orgs
                                    │  with X-Triton-Service-Key)
                                    ▼
                         ┌─────────────────────────┐
                         │      Report Server      │
                         │      (pkg/server)       │
                         │                         │
   org login       ────> │  /api/v1/auth/login     │
   org CRUD        ────> │  /api/v1/users          │
   agent submit    ────> │  /api/v1/scans (POST)   │
   web UI          ────> │  /ui/                   │
                         │                         │
                         │  • Independent JWT key  │
                         │  • Optional Mailer      │
                         │  • Rate limiter         │
                         │  • AES-256-GCM at rest  │
                         └──────────┬──────────────┘
                                    │
                         ┌──────────▼──────────────┐
                         │       PostgreSQL        │
                         │   (two schemas / DBs)   │
                         │                         │
                         │  license_*  report_*    │
                         └─────────────────────────┘
```

**Key properties**

- **Split identity.** Superadmins live in the license server; org users live in the report server. They never share a user table. One email address can legitimately exist in both populations (with different passwords) — we treat that as a rare admin/customer overlap, not a bug.
- **Cross-server provisioning.** When a superadmin creates a new org in the license server's admin UI, the license server calls the report server's `POST /api/v1/admin/orgs` endpoint (authenticated with a shared `X-Triton-Service-Key`) to create the matching org row + an initial admin user with `must_change_password=true` + a random temp password.
- **Agent authentication via license token.** Agents ship with a signed Ed25519 license token (obtained via `triton license activate` against the license server). The report server validates the token locally (Ed25519 signature + machine binding) and extracts the org ID from it — no round trip to the license server per scan.
- **Org user authentication via JWT.** Human users log into the report server web UI, get a 24-hour JWT, and every API call carries `Authorization: Bearer <jwt>`. First-login users must rotate their temp password before any data operation succeeds.

**Single-tenant deployment** is a subset: no license server, no superadmins, no web login — you run just PostgreSQL + the report server with an offline license token and your agents use the same token for auth. Use this when one organization owns the whole stack.

---

## 2. Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Podman (or Docker) | Podman 4.0+ / Docker 20.10+ | With compose plugin |
| PostgreSQL | 14+ | Containerized (included) or external |
| Triton enterprise license | — | Required for report server + agent modes |
| Go | 1.25+ | Only if building from source |
| Resend API key | _(optional)_ | For invite emails; fall back to manual credential delivery |

### Install on Ubuntu Server (22.04 / 24.04)

This is the reference deployment target. All examples below use Ubuntu, but Fedora/RHEL and macOS work with minor package-manager differences.

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install Podman + compose
sudo apt install -y podman pipx
pipx install podman-compose

# 3. (Optional) Install Docker instead — all podman commands below work
#    identically with docker. Replace "podman" with "docker" throughout.
# curl -fsSL https://get.docker.com | sudo sh

# 4. Verify
podman --version
podman compose version
```

**Firewall (ufw):**
```bash
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP (reverse proxy)
sudo ufw allow 443/tcp   # HTTPS (reverse proxy)
# Do NOT expose 5435 (PostgreSQL), 8080, or 8081 directly — use a reverse proxy.
sudo ufw enable
```

**Reverse proxy (Caddy — recommended for auto-TLS):**
```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

Create `/etc/caddy/Caddyfile`:
```
reports.example.com {
    reverse_proxy localhost:8080
}

license.example.com {
    reverse_proxy localhost:8081
}
```

```bash
sudo systemctl enable --now caddy
```

Caddy automatically obtains and renews Let's Encrypt TLS certificates for both domains. No manual cert management needed.

### Install on other platforms

**macOS (dev):**
```bash
brew install podman
podman machine init && podman machine start
```

**Fedora/RHEL:**
```bash
sudo dnf install podman pipx
pipx install podman-compose
```

---

## 3. Quick Start (Single-Tenant)

The fastest path to a working Triton report server with PostgreSQL, no multi-tenant complexity:

```bash
git clone https://github.com/amiryahaya/triton.git
cd triton
make container-run
```

This single command:

1. Builds the `triton:local` container image (~10MB)
2. Starts PostgreSQL 18 on port 5435
3. Starts the Triton report server on port 8080 with an offline enterprise license token baked into the build

Open `http://localhost:8080/` in your browser — you'll land on the dashboard directly (no login required because a single-tenant Guard provides the tenant context via the license token).

To stop everything:

```bash
make container-stop
```

**When to use single-tenant mode:** you are the sole operator and the sole organization. Everyone who can reach the server is trusted to see all data. This matches the typical "deploy triton for my own company" use case.

**When to graduate to multi-tenant:** you want to host multiple customers, or you want real user accounts with login / password rotation / per-user read vs admin permissions. See section 4.

---

## 4. Multi-Tenant Deployment

The multi-tenant stack is two independent binaries sharing a PostgreSQL instance (or two separate databases — your call). You can run them on the same host for small deployments or on separate hosts behind a load balancer for larger ones.

**High-level startup order:**

1. PostgreSQL
2. License server (creates its own schema on first connect)
3. Report server (creates its own schema on first connect)
4. Agents (activate against the license server, submit to the report server)

### Ubuntu Server Deployment (step-by-step)

This is the recommended production deployment on a fresh Ubuntu 22.04/24.04 server with Caddy reverse proxy and Let's Encrypt TLS.

**Assumptions:** you have a server with two DNS records pointing at it (`reports.example.com` and `license.example.com`), SSH access, and ports 80/443 open.

```bash
# 1. Install prerequisites (see §2 for details)
sudo apt update && sudo apt upgrade -y
sudo apt install -y podman pipx curl git
pipx install podman-compose

# 2. Create the deployment directory
sudo mkdir -p /opt/triton
cd /opt/triton

# 3. Download the deployment files.
#    Only 3 files are needed: compose.yaml, .env, scripts/init-db.sh.
#
#    Option A — GitHub CLI (works for private repos):
gh release download --repo amiryahaya/triton --pattern "*.tar.gz" --dir /tmp/triton-release || true
#
#    Option B — shallow clone (simplest):
sudo git clone --depth 1 https://github.com/amiryahaya/triton.git /opt/triton
#
#    After cloning, you can remove the .git directory if you don't want
#    git history on the production server:
sudo rm -rf /opt/triton/.git

# 4. Edit .env — fill in production values:
#    Generate secrets:
#      openssl rand -hex 32  (for each key/secret field)
#
#    Required fields to set:
#      TRITON_LICENSE_SERVER_ADMIN_KEY=<random hex>
#      TRITON_LICENSE_SERVER_SIGNING_KEY=<Ed25519 64-byte hex — see §6d>
#      TRITON_LICENSE_SERVER_ADMIN_PASSWORD=<strong password>
#      TRITON_LICENSE_SERVER_REPORT_KEY=<random hex>
#      REPORT_SERVER_SERVICE_KEY=<same value as REPORT_KEY above>
#      REPORT_SERVER_JWT_SIGNING_KEY=<random hex>
#      REPORT_SERVER_TENANT_PUBKEY=<last 32 bytes of signing key>
#      REPORT_SERVER_DATA_ENCRYPTION_KEY=<random hex>
#      TRITON_LICENSE_KEY=<mint via license server after first boot>
#
#    Production URLs:
#      TRITON_LICENSE_SERVER_REPORT_PUBLIC_URL=https://reports.example.com
#      TRITON_LICENSE_SERVER_PUBLIC_URL=https://license.example.com
#      REPORT_SERVER_INVITE_URL=https://reports.example.com/ui/#/login
#      REPORT_SERVER_INVITE_URL_BASE=https://reports.example.com/ui/#/login
#
#    Email (optional):
#      RESEND_API_KEY=re_...
#      RESEND_FROM_EMAIL=noreply@example.com
#      REPORT_SERVER_RESEND_API_KEY=re_...
#      REPORT_SERVER_RESEND_FROM_EMAIL=noreply@example.com
sudo nano .env
sudo chmod 600 .env

# 5. Start the full stack (images are pulled automatically from ghcr.io)
podman compose --profile server --profile license-server up -d

# 6. Verify
curl -s http://localhost:8080/api/v1/health   # report server
curl -s http://localhost:8081/api/v1/health   # license server

# 8. Install Caddy reverse proxy (auto-TLS)
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy

# 9. Configure Caddy
sudo tee /etc/caddy/Caddyfile > /dev/null <<'CADDY'
reports.example.com {
    reverse_proxy localhost:8080
}

license.example.com {
    reverse_proxy localhost:8081
}
CADDY
sudo systemctl restart caddy

# 10. Verify HTTPS
curl -s https://reports.example.com/api/v1/health
curl -s https://license.example.com/api/v1/health
```

**First-time setup after deployment:**

1. Open `https://license.example.com/ui/` — enter the admin key from `.env` (`TRITON_LICENSE_SERVER_ADMIN_KEY`)
2. Create your first organization
3. Create a license (enterprise tier, desired seat count, 365 days)
4. Click **Download bundle** (pick the target platform) or **Copy install command**
5. Ship the bundle/command to the operator — they run `sudo bash install.sh` and the agent is live

**Systemd auto-start (optional):**

Create `/etc/systemd/system/triton-stack.service`:
```ini
[Unit]
Description=Triton Report + License Server Stack
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/triton
ExecStart=/usr/bin/podman compose --profile server --profile license-server up -d
ExecStop=/usr/bin/podman compose --profile server --profile license-server down

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now triton-stack
```

**Compose profile for full stack:**

```bash
# License server + report server + PostgreSQL
podman compose --profile server --profile license-server up -d
```

Profile membership:

| Service | Profile | Default port |
|---------|---------|--------------|
| `postgres` | (default — always started) | 5435 (external) |
| `triton` (report server) | `server` | 8080 |
| `triton-license-server` | `license-server` | 8081 |

`make db-up` starts only PostgreSQL. `make container-run` starts `postgres + triton`. `make container-run-licenseserver` starts `postgres + license server`. For the full multi-tenant stack you need both profiles active.

---

## 5. Report Server

### 5a. Container image

**Build locally:**
```bash
make container-build
# Produces: triton:local
```

**Pull from registry:**
```bash
podman pull ghcr.io/amiryahaya/triton:latest
```

Multi-stage build `golang:1.25` → `scratch`, ~10MB, static binary, includes CA certs and tzdata. Default entrypoint is `/triton`, default command is `server`.

### 5b. Configuration

The report server reads a mix of CLI flags and environment variables. **CLI flags take precedence** over env vars for the settings that support both.

**CLI flags (passed via `triton server --flag`):**

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8080` | Bind address |
| `--db` | `postgres://triton:triton@localhost:5435/triton?sslmode=disable` | PostgreSQL connection URL |
| `--tls-cert` / `--tls-key` | _(none)_ | TLS certificate and key paths |
| `--license-key` | _(none)_ | Enterprise license token |

**Environment variables (read by `cmd/server.go`):**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TRITON_LICENSE_KEY` | Yes | _(none)_ | Enterprise license token (also settable via `--license-key` flag) |
| `REPORT_SERVER_JWT_SIGNING_KEY` | Yes (multi-tenant) | _(none)_ | Hex-encoded Ed25519 seed for signing org-user JWTs. When unset, the `/api/v1/auth/*` and `/api/v1/users` routes are NOT registered (agents-only mode). |
| `REPORT_SERVER_TENANT_PUBKEY` | Yes (multi-tenant) | _(none)_ | Hex-encoded Ed25519 public key (64 chars) for verifying agent license tokens. Must match the license server's signing key public half. |
| `REPORT_SERVER_SERVICE_KEY` | Yes (multi-tenant) | _(none)_ | Shared secret for cross-server provisioning. Must match `TRITON_LICENSE_SERVER_REPORT_KEY` on the license server. When empty, the `/api/v1/admin/*` route group is NOT registered. |
| `REPORT_SERVER_DATA_ENCRYPTION_KEY` | No | _(none)_ | 64-hex-char AES-256-GCM key for at-rest encryption of scan payloads. Malformed values fail startup. |
| `REPORT_SERVER_INVITE_URL` | No | _(none)_ | URL embedded in invite emails (typically the report server login page). |
| `REPORT_SERVER_RESEND_API_KEY` | No | _(none)_ | Resend API key for the invite mailer. |
| `REPORT_SERVER_RESEND_FROM_EMAIL` | No | _(none)_ | From address for invite emails. |
| `REPORT_SERVER_RESEND_FROM_NAME` | No | `Triton Reports` | From name for invite emails. |
| `REPORT_SERVER_SESSION_CACHE_SIZE` | No | `10000` | JWT session cache entries. Set to 0 to disable (with log warning). |
| `REPORT_SERVER_SESSION_CACHE_TTL` | No | `60s` | JWT session cache TTL. Clamped to [5s, 5m]. |
| `REPORT_SERVER_LOGIN_RATE_LIMIT_MAX_ATTEMPTS` | No | `5` | Failed logins before lockout. |
| `REPORT_SERVER_LOGIN_RATE_LIMIT_WINDOW` | No | `15m` | Sliding window for login attempts. |
| `REPORT_SERVER_LOGIN_RATE_LIMIT_LOCKOUT` | No | `15m` | Lockout duration after exceeding max attempts. |
| `REPORT_SERVER_REQUEST_RATE_LIMIT_MAX_REQUESTS` | No | `600` | Per-tenant request throttle. |
| `REPORT_SERVER_REQUEST_RATE_LIMIT_WINDOW` | No | `1m` | Request rate limit window. |

**Note on the `--db` flag:** the report server reads the database URL exclusively as a CLI flag, NOT an env var. In `compose.yaml` this is passed in the `command:` field. Outside compose, pass it directly: `triton server --db "postgres://..."`. There is no `TRITON_DB_URL` env var.

### 5c. At-rest encryption

The report server encrypts scan payloads in PostgreSQL using AES-256-GCM when `REPORT_SERVER_DATA_ENCRYPTION_KEY` is set. The key format is exactly 64 hexadecimal characters (32 bytes). Malformed values cause `server.New` to return an error rather than silently downgrading to plaintext storage — see the Phase 3+4 review H1 fix.

**Generate a key:**
```bash
openssl rand -hex 32
```

**Use it:**
```bash
export REPORT_SERVER_DATA_ENCRYPTION_KEY="0011223344556677...ff"  # your key
triton server --db "$TRITON_DB_URL"
```

**Key rotation:** not yet automated. To rotate today you must `UPDATE scans SET scan_data = pgp_sym_decrypt(scan_data::bytea, old_key) …` manually — this is a known gap, tracked under the Sprint 3 "encryption envelope → bytea" migration.

**Existing plaintext rows:** the encryptor transparently reads both encrypted and plaintext rows during the transition window. Once all rows are encrypted you can flip a check to enforce encrypted-only reads, but that is not the default.

**⚠️ Encryption scope (Analytics Phase 1 onward):** the envelope covers **only** `scans.result_json`. The denormalized `findings` read-model table introduced by Analytics Phase 1 (schema v7) stores columns such as `subject`, `issuer`, `file_path`, `hostname`, `algorithm`, and `not_after` as **plaintext** so they can be used in SQL predicates for the three new aggregation queries (`/api/v1/inventory`, `/api/v1/certificates/expiring`, `/api/v1/priority`). An operator who enabled at-rest encryption for compliance reasons should be aware that the most interesting fields of a scan are projected beside the encrypted blob in cleartext.

If you require end-to-end encryption of these fields, the current options are:

1. **Accept the reduced scope** — document internally that at-rest encryption covers payload archival but not the analytics projection. Most deployments will choose this.
2. **Revert migration v7** — `DROP TABLE findings; ALTER TABLE scans DROP COLUMN findings_extracted_at;` disables the analytics views entirely. The rest of Triton continues to function against the encrypted scan blobs.
3. **Wrap the projection at the storage layer** — use PostgreSQL TDE (Transparent Data Encryption via a plugin like `pgcrypto` with indexable encrypted columns) or filesystem-level encryption on the data volume. Outside Triton's own code path.

Tracked under `/pensive:full-review` item B3 (2026-04-09). Phase 2+ will revisit this if an operator requires column-level encryption of the findings projection.

### 5d. Running the report server

**Binary directly:**
```bash
triton server \
  --listen :8080 \
  --db "postgres://triton:triton@localhost:5435/triton?sslmode=disable"
```

**Container (bound to host PostgreSQL):**
```bash
podman run -d \
  --name triton-report \
  -p 8080:8080 \
  -e TRITON_LICENSE_KEY="$TRITON_LICENSE_KEY" \
  -e REPORT_SERVER_DATA_ENCRYPTION_KEY="$ENC_KEY" \
  triton:local \
  server \
    --listen :8080 \
    --db "postgres://triton:triton@host.containers.internal:5435/triton?sslmode=disable"
```

**Compose (full stack):**
```bash
podman compose --profile server up -d
```

Inside the compose network PostgreSQL is reachable at `postgres:5432` (the external host port 5435 is mapped only for local developer access).

### 5e. TLS

Terminate TLS at the report server (recommended for single-instance deployments) or at an upstream proxy (recommended for multi-instance). If terminating at the report server:

```bash
triton server \
  --listen :8443 \
  --tls-cert /certs/server.crt \
  --tls-key /certs/server.key
```

Self-signed cert for testing:
```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout server.key -out server.crt \
  -days 365 -subj "/CN=triton-report.example.com"
```

For production use a CA-signed cert (Let's Encrypt, internal PKI, etc.).

---

## 6. License Server

### 6a. Purpose

The license server is the authority for:

- Organizations (create, update, suspend, delete)
- Licenses (tier, seat pool, expiry)
- Activations (which machines are bound to which license)
- Superadmins (platform operators who manage all of the above)

It exposes:

- **Client API** (public): `/auth/login`, `/license/activate`, `/license/deactivate`, `/license/validate`, `/health`
- **Admin API** (`X-Triton-Admin-Key`): full CRUD over orgs, licenses, activations, superadmins, audit log, binaries

### 6b. Configuration

All license-server options are environment variables. See `cmd/licenseserver/main.go` for the authoritative list.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TRITON_LICENSE_SERVER_LISTEN` | No | `:8081` | Bind address |
| `TRITON_LICENSE_SERVER_DB_URL` | Yes | — | PostgreSQL URL (should use a dedicated DB or schema) |
| `TRITON_LICENSE_SERVER_ADMIN_KEY` | Yes | — | Admin API key for the `X-Triton-Admin-Key` header; multiple comma-separated values allowed |
| `TRITON_LICENSE_SERVER_SIGNING_KEY` | Yes | — | Hex-encoded Ed25519 private key (64 hex chars = 32-byte seed + 32-byte pubkey) used to sign license tokens AND superadmin JWTs |
| `TRITON_LICENSE_SERVER_ADMIN_EMAIL` | No | `admin@localhost` | Bootstrap superadmin email (only used on first startup against empty users table) |
| `TRITON_LICENSE_SERVER_ADMIN_PASSWORD` | Yes (first boot) | — | Bootstrap superadmin password. Rotate immediately after first login. |
| `TRITON_LICENSE_SERVER_TLS_CERT` | No | — | TLS certificate path (leave blank for plaintext / reverse proxy termination) |
| `TRITON_LICENSE_SERVER_TLS_KEY` | No | — | TLS key path |
| `TRITON_LICENSE_SERVER_BINARIES_DIR` | No | `/opt/triton/binaries` | Directory for uploaded agent binaries (filesystem path inside the container) |
| `TRITON_LICENSE_SERVER_REPORT_URL` | No | — | Internal URL the license server uses to reach the report server (e.g. `http://triton:8080` in compose). Used for cross-server provisioning. |
| `TRITON_LICENSE_SERVER_REPORT_PUBLIC_URL` | No | — | Customer-facing report server URL baked into generated `agent.yaml` downloads (e.g. `https://reports.example.com`). Falls back to `TRITON_LICENSE_SERVER_REPORT_URL`. |
| `TRITON_LICENSE_SERVER_REPORT_KEY` | No | — | Shared secret for cross-server provisioning. **Must match** `REPORT_SERVER_SERVICE_KEY` on the report server. |
| `TRITON_LICENSE_SERVER_PUBLIC_URL` | No | — | The license server's own external URL (e.g. `https://license.example.com`). Required for one-liner install commands. If unset, the "Copy install command" button is disabled. |
| `RESEND_API_KEY` | No | — | Resend API key for invite emails. **Note:** uses a generic prefix, NOT `TRITON_LICENSE_SERVER_RESEND_*`. |
| `RESEND_FROM_EMAIL` | No | — | From address for invite emails |
| `RESEND_FROM_NAME` | No | `Triton Reports` | From name for invite emails |
| `REPORT_SERVER_INVITE_URL_BASE` | No | — | Login link embedded in invite emails. **Note:** the report server reads this as `REPORT_SERVER_INVITE_URL` (different name). |

**Admin key bootstrap:** on first startup against an empty database, the license server seeds an initial `platform_admin` user using `TRITON_LICENSE_SERVER_ADMIN_EMAIL` and `TRITON_LICENSE_SERVER_ADMIN_PASSWORD`. Change the bootstrap password immediately after first login.

**Naming pitfalls:** the license server uses `RESEND_*` (generic prefix) for its mailer, while the report server uses `REPORT_SERVER_RESEND_*`. If both services need to send emails, set both sets of variables. Similarly, the invite URL is `REPORT_SERVER_INVITE_URL_BASE` on the license server but `REPORT_SERVER_INVITE_URL` on the report server. See `.env.example` for the complete mapping.

### 6c. Running the license server

```bash
make build-licenseserver

export TRITON_LICENSE_SERVER_DB_URL="postgres://triton:triton@localhost:5435/triton_license?sslmode=disable"
export TRITON_LICENSE_SERVER_ADMIN_KEY="your-secret-admin-key"
export TRITON_LICENSE_SERVER_SIGNING_KEY="<hex-encoded-ed25519-private-key>"

./bin/triton-license-server
```

Or via compose:
```bash
make container-run-licenseserver
# License server on :8081, admin UI at http://localhost:8081/ui/
```

### 6d. Generating the signing key

```bash
go run ./cmd/keygen
# Outputs a fresh Ed25519 keypair (hex-encoded). Use the private key for
# TRITON_LICENSE_SERVER_SIGNING_KEY; embed the public key in client
# binaries via ldflags or bundle it via internal/license/pubkey.go.
```

### 6e. Cross-server provisioning wiring

For the license-server-initiated org provisioning flow to reach the report server, BOTH env vars must be set on the license server:

```bash
export TRITON_LICENSE_SERVER_REPORT_URL="https://reports.example.com"
export TRITON_LICENSE_SERVER_REPORT_SERVICE_KEY="$(openssl rand -hex 32)"
```

And the SAME service key must be configured on the report server via its `Config.ServiceKey` field (currently via a wrapper main — see the programmatic note in section 5b).

If either variable is empty, the license server still creates orgs in its own database but does NOT push provisioning calls, and the report server does not register the `/api/v1/admin/*` route group. Use this mode if you're running the license server as a pure license registry without a live report-server integration.

### 6f. Generating agent.yaml downloads

For the fool-proof "email the customer a single file, they drop it next to the binary, done" deployment path (see §7e), the license server admin UI exposes a one-click download on the license detail page.

**Flow:**

1. Superadmin opens `http://<license-server>/ui/#/licenses/<license-id>`
2. Clicks **Download agent.yaml**
3. License server mints a fresh Ed25519-signed token from the license's stored claims, bakes it into a yaml template with a security header comment, and streams it back as `agent.yaml`
4. Admin hands the file to the customer via their preferred trusted channel

The generated file contains:

- `license_key` — a fresh token for the license (NOT the same token as any existing activation row; activations are not tracked for this path)
- `report_server` — the `TRITON_LICENSE_SERVER_REPORT_PUBLIC_URL` value (the customer-facing URL), with fallback to `TRITON_LICENSE_SERVER_REPORT_URL` when the public URL is unset
- `profile` — the default scan profile (`quick` unless overridden)
- A verbose header comment with license ID, org name, tier, expiry, and a "treat as secret" warning with `chmod 600` / `icacls` snippets

**Default token binding:** the minted token is NOT machine-bound by default. Any host that drops the file next to the binary can use it. This is the deliberate trade-off for drop-and-run usability — an operator who needs per-machine scoping should either use `triton license activate` on each target host (tracked in the activations table) or supply `bind_to_machine` in the request body with the target host's fingerprint (see `triton license fingerprint`).

**API equivalent:** the same file can be generated programmatically from automation:

```bash
curl -X POST \
  -H "X-Triton-Admin-Key: $TRITON_LICENSE_SERVER_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -o agent.yaml \
  -d '{}' \
  https://license.example.com/api/v1/admin/licenses/<license-id>/agent-yaml
```

Optional body fields:

```json
{
  "report_server": "https://reports.example.com",
  "profile": "standard",
  "bind_to_machine": "a1b2c3d4..."
}
```

- `report_server` — override the server-default URL; set to `""` to force local-report-only mode.
- `profile` — one of `quick`, `standard`, `comprehensive`.
- `bind_to_machine` — target host fingerprint; when set, mints a machine-bound token.

**Refusal cases:** the endpoint returns `400 Bad Request` for revoked or expired licenses (the resulting token would be unusable anyway — failing at download time is clearer than failing at agent start time). Every download is recorded in the audit log as `license_download_agent_yaml` with profile, report_server, machine_bound flag, tier, and expiry for compliance trails.

**Rotation:** to rotate a deployed agent.yaml, regenerate from the admin UI and redistribute. The old token remains valid until the license itself is revoked — there is no per-token invalidation for this path. Revoking the license invalidates every token it ever minted, including downloaded agent.yaml files.

---

## 7. Agent Deployment

The agent is the scanner binary in "submit my results to a central server" mode.

### 7a. Flags

| Flag | Required | Description |
|------|----------|-------------|
| `--report-server` | Yes | Report server URL (e.g. `https://reports.example.com`) |
| `--server` | — | Deprecated alias for `--report-server`; prints warning |
| `--profile` | No (default `quick`) | Scan profile: `quick`, `standard`, `comprehensive` |
| `--interval` | No | Repeat interval (e.g. `24h`); unset = run once and exit |
| `--license-key` | No | Enterprise license token (or resolve via env/file) |

### 7b. Auth

Agents authenticate to the report server via **license token**, not API key. Legacy `--api-key` was removed in Phase 4. The agent sends the license token in the `X-Triton-License-Token` header; the report server verifies it with the embedded/configured public key and extracts the org ID from the token's claims. No round trip to the license server per scan.

### 7c. Running

**One-shot:**
```bash
triton agent \
  --report-server https://reports.example.com \
  --profile standard \
  --license-key "$TRITON_LICENSE_KEY"
```

**Continuous (every 24 hours):**
```bash
triton agent \
  --report-server https://reports.example.com \
  --profile standard \
  --interval 24h \
  --license-key "$TRITON_LICENSE_KEY"
```

**Systemd service (Linux):**
```ini
# /etc/systemd/system/triton-agent.service
[Unit]
Description=Triton Cryptographic Scanner Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/triton agent \
  --report-server https://reports.example.com \
  --profile standard \
  --interval 24h
Environment=TRITON_LICENSE_KEY=eyJsaWQiOiI1YTgz...
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now triton-agent
sudo journalctl -u triton-agent -f
```

### 7d. Activating against the license server

If you deployed a license server, each agent must first activate to exchange a license UUID for a signed token:

```bash
triton license activate \
  --license-server https://license.example.com \
  --license-id <license-uuid>
```

The CLI saves the token + cache metadata to `~/.triton/license.key` and `~/.triton/license.meta`. Subsequent `triton agent` runs read the cached token. If the license server becomes unreachable, a 7-day offline grace period keeps the agent operational.

### 7e. Fool-proof drop-and-run deployment (`agent.yaml`)

For non-technical end-users who should not have to learn any licence commands, Triton supports a **single-file drop-and-run** deployment path:

1. **Superadmin generates the file** — downloads `agent.yaml` from the license server admin UI (see §6f) or via the admin API.
2. **Superadmin delivers it** — emails or hands the file to the customer via any trusted channel.
3. **Customer deploys** — saves `agent.yaml` next to the `triton` (or `triton.exe`) binary and runs the binary. No flags, no env vars, no commands.

**How the agent resolves config:** at startup the agent looks for `agent.yaml` in the same directory as its own executable (NOT the shell's working directory — this is deliberate so double-clicking from a file manager works). When found, it overlays the file's fields (`license_key`, `report_server`, `profile`, `output_dir`, `formats`) on top of whatever was passed via flags or environment variables. Flags still win for explicit overrides.

**Dual-mode:**

- **With `report_server` set** — the agent submits scan results to the report server using the embedded license_key as its auth token. No local report files are written.
- **Without `report_server`** — the agent runs in local mode and writes reports into `output_dir` (default `reports/`), formatted according to its licence tier.

**Security posture:** the `license_key` in `agent.yaml` IS the credential. Anyone with the file can submit scans as the organisation it was issued to and (if a report server is configured) read back that org's results. The generated file's header comment tells the operator to:

```bash
chmod 600 agent.yaml                                              # Linux / macOS
icacls agent.yaml /inheritance:r /grant:r "%USERNAME%:R"          # Windows
```

Any handoff channel that leaves the file readable by other users on the host is a security bug.

**When to use this path vs. `triton license activate`:**

| Requirement | Use `agent.yaml` | Use `triton license activate` |
|-------------|------------------|------------------------------|
| Non-technical operator | ✓ | ✗ |
| Per-machine visibility in activations table | ✗ (not tracked) | ✓ |
| Need to revoke a single host | ✗ (only whole license) | ✓ |
| Machine-bound token by default | ✗ (opt-in via `bind_to_machine`) | ✓ |
| Single-file distribution | ✓ | ✗ |
| Offline bootstrap with no network to licence server | ✓ | ✗ |

For large fleets that need per-machine accounting, prefer the activation path. For one-off customer deployments or when the customer cannot run licence commands, use `agent.yaml`.

### 7f. Fool-proof agent installation (bundle + one-liner)

For operators who need to hand pre-built binaries to end-users, the license server admin UI offers two zero-touch installation flows accessible from the license detail page (`/ui/#/licenses/<id>`).

#### Flow A — Bundle download

1. Superadmin opens the license detail page and selects the target platform (Linux amd64, Linux arm64, macOS arm64, Windows amd64).
2. Clicks **Download bundle**.
3. The license server calls `POST /api/v1/admin/licenses/{id}/bundle` with `{"os":"linux","arch":"amd64"}` (or equivalent) and streams back a compressed archive:
   - Linux/macOS: `.tar.gz` containing `triton`, `agent.yaml`, `install.sh`
   - Windows: `.zip` containing `triton.exe`, `agent.yaml`, `install.bat`
4. Superadmin delivers the archive to the operator (email, SFTP, shared drive).
5. Operator extracts and runs the install script — no further configuration required.

**Install paths set by the script:**

| OS | Binary | Config | Reports |
|----|--------|--------|---------|
| Linux / macOS | `/opt/triton/triton` | `/opt/triton/agent.yaml` | `/opt/triton/reports/` |
| Windows | `C:\Program Files\Triton\triton.exe` | `C:\Program Files\Triton\agent.yaml` | `C:\Program Files\Triton\reports\` |

**`install.sh` behaviour (Linux/macOS):**

- Requires root (`sudo`); exits with an error if run as a non-root user.
- Creates `/opt/triton/` with `755` permissions.
- Copies the binary and agent.yaml; sets binary to `755`, agent.yaml to `600`.
- On macOS, runs `xattr -dr com.apple.quarantine /opt/triton/triton` to bypass Gatekeeper without requiring the user to navigate security settings.

**`install.bat` behaviour (Windows):**

- Must be run from an elevated (Administrator) command prompt.
- Creates `C:\Program Files\Triton\` and copies the files.
- Sets ACLs on `agent.yaml` to restrict read access to the current user only.

#### Flow B — One-liner install

1. Superadmin clicks **Copy install command** on the license detail page.
2. Superadmin pastes the command into Slack/email for the operator.
3. Operator runs the one-liner on the target host:

```bash
curl -sSL 'https://license.example.com/api/v1/install/<TOKEN>' | sudo bash
```

**How the one-liner works:**

- `POST /api/v1/admin/licenses/{id}/install-token` generates a short-lived (24 h) install token and returns an install URL.
- The install URL (`GET /api/v1/install/{token}`) serves a platform-detecting shell script that:
  1. Detects the host OS and architecture.
  2. Downloads the correct binary from `GET /api/v1/install/{token}/binary/{os}/{arch}`.
  3. Downloads the pre-baked `agent.yaml` from `GET /api/v1/install/{token}/agent-yaml`.
  4. Installs both to `/opt/triton/` (Linux/macOS) with correct permissions and Gatekeeper bypass.
- The install token is single-use and expires after 24 hours.
- `TRITON_LICENSE_SERVER_PUBLIC_URL` **must** be set on the license server for one-liner generation to work — the URL is baked into the install token link returned to the admin.

**Windows one-liner (PowerShell):**

The admin UI also provides a PowerShell one-liner for Windows targets:

```powershell
iex (irm 'https://license.example.com/api/v1/install/<TOKEN>?ps=1')
```

#### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| macOS: "unidentified developer" dialog | Quarantine attribute set by browser download | The install script/one-liner runs `xattr -dr com.apple.quarantine` automatically. If you copied the binary manually, run that command yourself. |
| Windows: SmartScreen blocks `install.bat` | Unsigned script | Right-click → **Run as administrator** → click **More info** → **Run anyway**. Or run from an elevated CMD: `install.bat`. |
| `Permission denied` on Linux/macOS | Script not run as root | Prefix with `sudo`: `sudo bash install.sh` or use the `| sudo bash` form of the one-liner. |
| One-liner URL not generated | `TRITON_LICENSE_SERVER_PUBLIC_URL` not set | Set the env var to the license server's externally-reachable URL (e.g. `https://license.example.com`) and restart the license server. |
| Install token expired | Token is 24 h single-use | Generate a new one from the admin UI and share the updated URL. |

---

## 8. Authentication Modes

Triton's report server supports three distinct auth modes that can coexist on the same deployment:

| Mode | Used by | Transport | Verification |
|------|---------|-----------|--------------|
| **License token** | Agents | `X-Triton-License-Token` header | Local Ed25519 signature verify + machine binding |
| **User JWT** | Human org users (web UI, CLI wrappers) | `Authorization: Bearer <jwt>` | Local Ed25519 signature verify + session lookup |
| **Service key** | License server → report server provisioning calls | `X-Triton-Service-Key` header | Constant-time compare against `Config.ServiceKey` |
| **Guard fallback** (single-tenant only) | Anyone, no header | — | Guard's embedded license token provides a default tenant context |

The `UnifiedAuth` middleware (see `pkg/server/auth_middleware.go`) resolves the tenant on every request in the order: JWT → license token → Guard fallback → empty. Any route that reads data requires a non-empty tenant (`RequireTenant` middleware); submitting a scan without auth is allowed only in single-tenant mode.

### 8a. Login rate limiting (Phase 5.1)

Both servers enforce per-email rate limiting on their login endpoints:

- **5 failed attempts** within a **15-minute sliding window** → **15-minute lockout**
- Response is `429 Too Many Requests` with a `Retry-After` header
- Successful login clears the counter for that email
- Failures against unknown emails also burn the bucket (prevents enumeration via timing differences)

Tunable via `Config.LoginRateLimiterConfig` on both servers (programmatic today; flag-exposed in Sprint 3). See [ADR 0001](adr/0001-in-memory-login-rate-limiter.md) for the design rationale and the known split-brain limitation under multi-replica deployment.

### 8b. Invite expiry (Phase 5.2)

Users created via the provisioning or resend-invite flows start with `must_change_password=true` and an `invited_at` timestamp. If they do not complete the change-password flow within **7 days**, subsequent login attempts with the temp password return `401 Invalid Credentials` (deliberately indistinguishable from a wrong password — see Sprint 1 review finding D4 for the credential-oracle rationale). The recovery path is the `POST /api/v1/users/{id}/resend-invite` endpoint which rotates the temp password and resets `invited_at`.

### 8c. Password policy

All user-facing passwords must be at least **12 characters** (OWASP 2021 recommendation). The constant lives at `internal/auth.MinPasswordLength` and is enforced in `handleCreateUser`, `handleChangePassword`, `handleCreateSuperadmin`, and the provisioning receiver.

---

## 9. Org Provisioning & Invite Flow

### 9a. End-to-end happy path

```
1. Superadmin logs into license server admin UI (port 8081/ui)
2. "Create Org" form: org name + initial admin email + initial admin name
3. License server:
   a. Creates row in organizations table
   b. Calls GenerateTempPassword(24) for initial temp password
   c. POSTs to report server /api/v1/admin/orgs with the admin details
   d. Report server creates matching org row + admin user (mcp=true, invited_at=now)
   e. License server (if Resend configured) sends invite email with temp password
   f. Response returned to the admin UI:
      - email_delivered=true  → modal says "invite sent; password is in the email"
      - email_delivered=false → modal shows the temp password ONCE for manual copy
4. Invitee receives email, clicks the login link, lands on report server login page
5. First login with temp password → report server returns JWT with mcp=true
6. UI routes to change-password screen (forced — RequireTenant + BlockUntilPasswordChanged middleware)
7. User sets new password → mcp cleared → fresh JWT with mcp=false → overview dashboard
```

### 9b. Resend invite

If the invitee never receives the email or the 7-day window expires, an org admin can trigger a resend:

```
POST /api/v1/users/{id}/resend-invite
Authorization: Bearer <org_admin JWT>
```

Behavior depends on whether the report server has a Mailer configured:

- **Mailer configured** → new temp password rotated in DB, pushed via email, response is `{status: "invite resent", emailDelivered: "true"}` with NO tempPassword in the body
- **Mailer nil** → new temp password rotated in DB, response is `{status: "invite resent", tempPassword: "..."}` with `Cache-Control: no-store` so the admin can manually deliver it

The store layer uses `WHERE must_change_password = TRUE` to refuse resending against users who already completed their first login, so this endpoint cannot be abused to silently reset a working account's password.

### 9c. Configuring the mailer

Both servers accept the same Resend configuration. Set env vars on the license server (for initial provisioning) and wire `Config.Mailer` on the report server (for resend-invite) via a wrapper main or wrapper init.

```bash
export TRITON_LICENSE_SERVER_RESEND_API_KEY="re_..."
export TRITON_LICENSE_SERVER_RESEND_FROM_EMAIL="noreply@reports.example.com"
export TRITON_LICENSE_SERVER_RESEND_FROM_NAME="Triton Reports"
export TRITON_LICENSE_SERVER_INVITE_URL="https://reports.example.com/ui/#/login"
```

Without Resend configured, both flows fall back to returning the temp password in the API response body. This is functional but deviates from the security posture — only use it for dev / staging.

---

## 10. Security Configuration

### 10a. Security headers

Both servers set the following on every response by default (see `pkg/server/server.go::securityHeaders` and `pkg/licenseserver/server.go::licenseSecurityHeaders`):

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Strict-Transport-Security: max-age=63072000; includeSubDomains` (license server only, when TLS terminated locally)

Resend-invite responses additionally set `Cache-Control: no-store` and `Pragma: no-cache` to prevent any intermediate cache from retaining the response body when it contains the fallback temp password.

### 10b. PostgreSQL TLS

Use `sslmode=require` at minimum, or `sslmode=verify-full` with a pinned CA for production. Example:

```
postgres://triton:strong-pw@postgres.example.com:5432/triton?sslmode=verify-full&sslrootcert=/etc/ssl/pg-ca.crt
```

### 10c. Reverse proxy considerations

If you terminate TLS at a reverse proxy (nginx, Caddy, Envoy), **disable response-body logging for the `/api/v1/users/*/resend-invite` route** — that endpoint's response body may contain a temp password when the Mailer is not configured. The `Cache-Control: no-store` header is belt-and-braces but cannot override a proxy configuration that explicitly logs bodies.

### 10d. Image and Kubernetes Scanner Credentials (Server Mode)

`triton server` does **not** fall back to ambient SDK default credential
chains for OCI image or Kubernetes cluster scans. Scan requests targeting
images or clusters must carry explicit credentials in the request body.

### 10e. Kubernetes Scanner RBAC

Deploy the following ClusterRole and bind it to a ServiceAccount:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: triton-scanner
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["list", "get"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses"]
  verbs: ["list"]
- apiGroups: ["admissionregistration.k8s.io"]
  resources: ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"]
  verbs: ["list"]
- apiGroups: ["cert-manager.io"]
  resources: ["certificates", "issuers", "clusterissuers"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: triton-scanner
subjects:
- kind: ServiceAccount
  name: triton-scanner
  namespace: triton-system
roleRef:
  kind: ClusterRole
  name: triton-scanner
  apiGroup: rbac.authorization.k8s.io
```

**Security note:** Triton extracts algorithm, key size, and subject
metadata from TLS secrets. Raw private key material is parsed in memory
for algorithm identification and immediately discarded — it is never
written to disk, logs, findings, or reports.

---

## 11. Production Checklist

### Database

- [ ] Strong credentials (not the default `triton/triton`)
- [ ] `sslmode=require` or `verify-full` in the DB connection URL
- [ ] Volume backups with point-in-time recovery for the `triton-data` volume
- [ ] Separate databases (or schemas) for the license server and report server

### License server

- [ ] `TRITON_LICENSE_SERVER_ADMIN_KEY` set to a strong random value, stored in a secrets manager
- [ ] `TRITON_LICENSE_SERVER_SIGNING_KEY` is a fresh Ed25519 keypair; backup kept offline
- [ ] Bootstrap superadmin password rotated on first login
- [ ] TLS terminated at the license server or an upstream proxy
- [ ] Resend API credentials configured so invite emails land reliably
- [ ] Cross-server service key configured if wiring to a report server
- [ ] `TRITON_LICENSE_SERVER_REPORT_PUBLIC_URL` set to the customer-facing report server URL (distinct from the internal `_REPORT_URL`) so generated `agent.yaml` files embed a hostname customers can actually resolve

### Report server

- [ ] `REPORT_SERVER_DATA_ENCRYPTION_KEY` set (64 hex chars)
- [ ] `Config.ServiceKey` set to match the license server's `TRITON_LICENSE_SERVER_REPORT_SERVICE_KEY`
- [ ] `Config.JWTSigningKey` set (independent from license server's signing key)
- [ ] `Config.Mailer` wired so resend-invite delivers via email
- [ ] Enterprise license installed via `TRITON_LICENSE_KEY` or file
- [ ] TLS terminated at the report server or an upstream proxy
- [ ] `Config.LoginRateLimiterConfig` reviewed — default 5/15min/15min is appropriate for most deployments
- [ ] Reverse proxy configured to NOT log response bodies for `/api/v1/users/*/resend-invite`

### Agents

- [ ] Machine-bound license token installed via `triton license activate`, OR `agent.yaml` dropped next to the binary with `chmod 600` (or Windows equivalent)
- [ ] If using `agent.yaml`: file delivered via a trusted channel (not a chat system that retains attachments indefinitely)
- [ ] Systemd timer or `--interval` schedule configured
- [ ] Log aggregation: journalctl or container logs shipped to central collector
- [ ] Agent user has least-privilege filesystem access for the modules it runs

### Networking

- [ ] Only the report server port (8080/8443) exposed externally
- [ ] PostgreSQL reachable only from license-server and report-server hosts
- [ ] License server (8081) exposed only to: superadmin operators, report server egress, agent activation traffic
- [ ] Failed-login log events (`event=login_failure …`) shipped to a SIEM for coordinated-attack detection

### Monitoring

- [ ] `GET /api/v1/health` polled from external monitoring
- [ ] `LoginRateLimiterStats.LockedEmails` metric alerted on sudden spike (Sprint 3: Prometheus exporter)
- [ ] PostgreSQL connection pool saturation alerted
- [ ] Disk watermark on the `triton-data` volume

---

## 12. Troubleshooting

### Common issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `cannot reach server: connection refused` | Report server not running or wrong URL | Check it's running, verify `--report-server` URL |
| `opening database: failed to connect` | PostgreSQL not reachable | `make db-up`, verify the DB URL + port |
| `429 too many failed login attempts` | Rate limiter engaged | Wait out the `Retry-After`; investigate via failed-login log events |
| `401 invalid credentials` after 7 days | Invite expired — see §8b | Have an org admin call `POST /api/v1/users/{id}/resend-invite` |
| `403 feature requires enterprise licence` | Running in free tier | Install an enterprise license token |
| `403 feature requires pro licence` on `/diff` / `/trend` | Pro tier feature gated at middleware | Upgrade to pro or enterprise |
| `500 FATAL: invalid DataEncryptionKeyHex` at startup | Malformed encryption key env var | Generate a fresh 64-hex-char key with `openssl rand -hex 32` |
| `502 invite password rotated but email delivery failed` | Mailer configured but Resend rejected | Check Resend API key + from address; retry or contact invitee out-of-band |
| Port 5435 in use | Another PostgreSQL or pki service | Stop the conflict or change the port in `compose.yaml` |
| Port 8080 or 8081 in use | Other service on the port | Change `--listen` or container port mapping |

### Diagnostic commands

```bash
# Health checks
curl http://localhost:8080/api/v1/health
curl http://localhost:8081/api/v1/health

# Report server logs
podman logs triton-server

# License server logs
podman logs triton-license-server

# PostgreSQL logs
podman logs triton-db

# Shell into PostgreSQL
podman exec -it triton-db psql -U triton

# Check container status
podman ps

# Check container resource usage
podman stats

# Inspect the active license from a client
triton --license-key "$TRITON_LICENSE_KEY" license show
```

### Failed-login forensic log format (Sprint 2)

Both servers emit structured log lines for every login attempt:

```
event=login_failure server=report stage=bad_password email=alice@example.com ip=10.0.0.1 reason="bcrypt mismatch"
event=login_failure server=license stage=rate_limited email=attacker@evil.com ip=1.2.3.4 reason=retry-after=850
event=login_success server=report email=alice@example.com ip=10.0.0.1
```

Parse with a single regex in your log aggregator. Join the two servers' streams on the `email=` field to detect cross-server brute-force patterns — the in-memory rate limiter cannot coordinate across servers today, so this log-layer correlation is the defense until a shared durable limiter ships.

### Server timeouts

| Timeout | Value |
|---------|-------|
| Read header | 10s |
| Read body | 30s |
| Write response | 60s |
| Idle connection | 120s |
| Request middleware | 60s |

Large scan submissions (>10MB findings sections) may need adjusted timeouts — see `pkg/server/server.go`.

### Request throttling

Both servers apply `middleware.Throttle(100)` — up to 100 concurrent requests. Heavier load should stagger agent scan intervals or horizontally scale (noting the rate-limiter split-brain trade-off in ADR 0001).

## 13. Analytics Dashboard

Triton ships two analytics phases that are **fully standalone** — they provide production-ready dashboard views with no dependency on future phases. No additional features need to be enabled or configured beyond what is described in §13 and §14.

### Phase overview

| Phase | What it adds | Status |
|-------|-------------|--------|
| **Phase 1** | Crypto Inventory, Expiring Certificates, Migration Priority views + `findings` read-model table | Shipped |
| **Phase 2** | Executive Summary on Overview — readiness, trend, projection, dual policy verdicts, machine health tiers, top-5 blockers | Shipped |

Both phases degrade gracefully: a fresh org with no scans sees empty/zero-value states, not errors. The dashboard is usable from day one and becomes richer as scan data accumulates.

### 13.1 Analytics Views (Phase 1)

The report server's web UI includes three analytical views under a new "Analytics" sidebar section:

- **Crypto Inventory** (`#/inventory`) — aggregated by `(algorithm, key_size)` across the org, filtered to the latest scan per host. Answers "what crypto is currently deployed?"
- **Expiring Certificates** (`#/certificates`) — certs sorted by soonest expiry, with 30/90/180-day filter chips. Default window is 90 days. Already-expired certs are always included regardless of the filter.
- **Migration Priority** (`#/priority`) — top 20 findings by `migration_priority` score, read-only. Summary cards break down by criticality (≥80 critical, 60–79 high, 40–59 medium).

All three views read from a new denormalized `findings` table (schema v7) that is populated on every scan submit transactionally alongside the scan row. For historical data, a first-boot background goroutine walks `scans.result_json`, extracts crypto findings, and marks each scan via the new `findings_extracted_at` column. The goroutine runs once per process start, is bounded to 30 minutes, and is idempotent across restarts — dropping the findings table and clearing `findings_extracted_at` triggers a fresh extraction without data loss.

### 13.1a. Backfill observability

Three Prometheus metrics expose backfill progress via `/api/v1/metrics`:

- `triton_backfill_scans_processed_total` — counter of successfully processed scans
- `triton_backfill_scans_failed_total` — counter of scans that failed extraction and were marked to skip (check logs for causes — typically corrupt or unreadable `result_json` blobs)
- `triton_backfill_in_progress` — gauge, 1 while the goroutine is running, 0 otherwise

While backfill is in progress, the three analytics API responses include an `X-Backfill-In-Progress: true` header and the UI shows an inline cyan banner on the affected views. The banner auto-clears when the header stops being sent.

### 13.1b. Recovery runbook

The `findings` table is a **read-model** over `scans.result_json`. Dropping or truncating it loses nothing permanent — it can always be rebuilt from the scan blobs.

**If the findings table has stale or wrong data (e.g., mid-flight bug wrote bad rows):**

```sql
TRUNCATE findings;
UPDATE scans SET findings_extracted_at = NULL;
```

Restart the report server — the backfill goroutine re-runs automatically and repopulates the table from `scans.result_json`.

**If the schema itself needs to be rolled back (worst case — v7 misbehaving in production):**

```sql
DROP TABLE findings;
ALTER TABLE scans DROP COLUMN findings_extracted_at;
```

Redeploy with a schema v6 binary. The report server will work without analytics views until v7 is re-applied.

### 13.1c. Single-tenant mode note

In deployments with no Guard and no JWT (the default local dev mode), `TenantFromContext` returns the empty string. The analytics views won't show any data in this mode because the `findings` table's `org_id` column is `UUID NOT NULL` and requires a real tenant. Scans still persist correctly — the write path short-circuits findings insertion for single-tenant scans. Analytics are a feature of multi-tenant deployments.

### 13.2 Executive Summary (Phase 2)

Phase 2 extends the Overview dashboard (`#/`) with an executive summary block designed for a CISO audience. The block shows:

- **Readiness percentage** — `safe_findings / total_findings × 100`, computed from the latest scan per host
- **Trend direction** — improving / declining / stable, computed from monthly-bucketed historical scans
- **Dual policy verdicts** — both NACSA-2030 and CNSA-2.0 built-in policies evaluated and displayed side-by-side
- **Projected completion year** — pace-based estimate of when the org reaches its target readiness
- **Top 5 blockers** — reused from Phase 1's `/api/v1/priority` endpoint
- **Machine health tiers** — red/yellow/green rollup on the upgraded Machines stat card

### 13.2a. Per-org configuration

The projection math uses two display preferences that live on each organization row:

| Column | Default | Meaning |
|--------|---------|---------|
| `executive_target_percent` | `80.0` | The "meaningfully ready" threshold used for projected completion |
| `executive_deadline_year` | `2030` | The compliance anchor; projections <= this year are "on track", > this year are "behind schedule" |

**Defaults** match Triton's primary audience (Malaysian government / NACSA-2030). No configuration is needed for deployments that accept the defaults.

**Per-org override** — operators with different compliance targets modify the columns directly via SQL. Phase 2 does not include an admin UI for these settings; Phase 2.5 will add one. Example for a US defense contractor targeting CNSA-2.0 by 2035:

```sql
UPDATE organizations
SET executive_target_percent = 95,
    executive_deadline_year  = 2035
WHERE name = 'US Defense Contractor';
```

After the UPDATE, the next `/api/v1/executive` request from that org sees the new values. No server restart needed.

### 13.2b. What's hard-coded

The three other tunables — flat-pace threshold (0.1%/month), regressing severity (red), and the 70-year projection cap — are hard-coded in `pkg/analytics/projection.go`. These are math plumbing, not user preferences; no deployment should need to tune them.

### 13.2c. What happens on a fresh org

An org with zero scans gets an "insufficient-history" projection status, empty top-blockers list, and zero-value machine health tiers. The dashboard still renders; chips show grey "insufficient" states. Once at least two scans across two calendar months exist, the trend and projection become computable.
