# Triton License Server Guide

This guide covers deploying and managing the Triton License Server — a centralized service for org-based seat pool management, online token validation, and admin oversight.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Quick Start](#3-quick-start)
4. [Configuration](#4-configuration)
5. [Keypair Generation](#5-keypair-generation)
6. [Authentication](#6-authentication)
7. [Organization Management](#7-organization-management)
8. [License Management](#8-license-management)
9. [Client Activation](#9-client-activation)
10. [Admin Web UI](#10-admin-web-ui)
11. [Binary Downloads](#11-binary-downloads)
12. [Offline Fallback](#12-offline-fallback)
13. [API Reference](#13-api-reference)
14. [Sizing & Capacity Planning](#14-sizing--capacity-planning)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Overview

The License Server provides centralized license management for Triton deployments:

- **Org-based seat pools** — Create organizations, issue licenses with seat limits, track which machines are activated
- **Online validation** — Triton CLI validates its license token against the server on each run
- **Offline fallback** — If the server is unreachable, a 7-day grace period uses cached validation
- **Admin web UI** — Browser-based dashboard for managing orgs, licenses, activations, and audit log
- **Ed25519 token signing** — Server signs activation tokens with the same Ed25519 scheme used by offline tokens

```
┌──────────────┐     activate/validate     ┌───────────────────┐
│  Triton CLI  │ ◄──────────────────────►  │  License Server   │
│  (client)    │     POST /api/v1/license  │  (separate binary)│
│              │                           │                   │
│  guard.go    │     offline fallback      │  Chi router       │
│  client.go   │     (cached token +       │  PostgreSQL       │
│  cache.go    │      7-day grace)         │  Ed25519 signing  │
└──────────────┘                           │  Admin Web UI     │
                                           └───────────────────┘
```

**Backward compatible**: If `--license-server` is not configured, the CLI works exactly as today (offline tokens only).

---

## 2. Prerequisites

- **Go 1.21+** for building from source
- **PostgreSQL 15+** (tested with 18)
- **Ed25519 keypair** for token signing (see [Keypair Generation](#5-keypair-generation))

---

## 3. Quick Start

### Build the Server

```bash
make build-licenseserver
# Output: bin/triton-license-server
```

### Start PostgreSQL

```bash
make db-up
```

### Run the Server

```bash
export TRITON_LICENSE_SERVER_DB_URL="postgres://triton:triton@localhost:5434/triton_license?sslmode=disable"
export TRITON_LICENSE_SERVER_SIGNING_KEY="<hex-encoded-ed25519-private-key>"
export TRITON_LICENSE_SERVER_ADMIN_EMAIL="admin@example.com"   # first-boot only
export TRITON_LICENSE_SERVER_ADMIN_PASSWORD="change-me-now"    # first-boot only

./bin/triton-license-server
```

The server starts on `:8081` by default. On a fresh database it seeds an initial platform admin user using the bootstrap credentials above — subsequent boots ignore those env vars once the user exists. Open `http://localhost:8081/ui/` and log in with the bootstrap email and password.

### Using Docker Compose

```bash
# Start license server + PostgreSQL
make container-run-licenseserver

# Stop
make container-stop-licenseserver
```

---

## 4. Configuration

All configuration is via environment variables:

### Required

| Variable | Description |
|----------|-------------|
| `TRITON_LICENSE_SERVER_DB_URL` | PostgreSQL connection URL |
| `TRITON_LICENSE_SERVER_SIGNING_KEY` | Ed25519 private key (hex-encoded, 64 bytes) |

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `TRITON_LICENSE_SERVER_LISTEN` | `:8081` | Listen address |
| `TRITON_LICENSE_SERVER_TLS_CERT` | (none) | TLS certificate file path (enables HTTPS) |
| `TRITON_LICENSE_SERVER_TLS_KEY` | (none) | TLS private key file path |
| `TRITON_LICENSE_SERVER_BINARIES_DIR` | `/opt/triton/binaries` | Directory for uploaded binaries |
| `TRITON_LICENSE_SERVER_STALE_THRESHOLD` | `336h` (14 days) | Age at which a stale activation is reaped |
| `TRITON_LICENSE_SERVER_PUBLIC_URL` | (none) | Public base URL (used in invite emails) |

### First-Boot Admin Bootstrap

These only take effect when the `users` table has no rows (idempotent — ignored on subsequent boots once any user exists):

| Variable | Default | Description |
|----------|---------|-------------|
| `TRITON_LICENSE_SERVER_ADMIN_EMAIL` | `admin@localhost` | Bootstrap superadmin email |
| `TRITON_LICENSE_SERVER_ADMIN_PASSWORD` | (required on empty DB) | Bootstrap superadmin password (min 12 chars) |

### Report Server Integration (optional)

Both must be set together — a partial pair logs a warning and disables provisioning:

| Variable | Description |
|----------|-------------|
| `TRITON_LICENSE_SERVER_REPORT_URL` | Internal Report Server URL (service-mesh name, e.g. `http://triton:8080`) |
| `TRITON_LICENSE_SERVER_REPORT_KEY` | Shared service key for Manage→Report calls |
| `TRITON_LICENSE_SERVER_REPORT_PUBLIC_URL` | Public Report Server URL embedded in agent.yaml downloads and invite emails |

### Email (Resend — optional)

Both must be set together — a partial pair logs a warning and disables email:

| Variable | Default | Description |
|----------|---------|-------------|
| `TRITON_LICENSE_SERVER_RESEND_API_KEY` | (none) | Resend API key for invite emails and license expiry warning emails |
| `TRITON_LICENSE_SERVER_RESEND_FROM_EMAIL` | (none) | Sender address for invite and expiry warning emails |
| `TRITON_LICENSE_SERVER_RESEND_FROM_NAME` | `Triton License` | Sender display name |
| `TRITON_LICENSE_SERVER_LOGIN_URL` | (none) | Frontend login page URL embedded in invite emails |
| `REPORT_SERVER_INVITE_URL_BASE` | (none) | Report Server invite URL base |

### License Expiry Notifications

When `TRITON_LICENSE_SERVER_RESEND_API_KEY` is set, the server automatically sends expiry warning emails at three intervals before each license's expiry date:

| Interval | Subject |
|----------|---------|
| 30 days  | `License expiring in 30 days — action required` |
| 7 days   | `License expiring in 7 days — urgent` |
| 1 day    | `License expiring tomorrow — immediate action required` |

Recipients for each license:
- All **platform_admin** users (their stored email addresses)
- The **organization's `contact_email`** (if non-empty)

Notifications are tracked in the database (`notified_30d_at`, `notified_7d_at`, `notified_1d_at` columns on the `licenses` table). Each interval fires at most once per license cycle — if the column is already set, no duplicate is sent.

If `TRITON_LICENSE_SERVER_RESEND_API_KEY` is not configured, expiry notifications are silently skipped; all other functionality is unaffected.

### Database Setup

The server auto-migrates its schema on startup. It uses its own tables with a separate version tracker (`license_schema_version`), so it can share a PostgreSQL instance with the Triton scan server without conflicts.

**Tables**: `organizations`, `licenses`, `activations`, `audit_log`, `users`, `sessions`

---

## 5. Keypair Generation

Generate an Ed25519 keypair for the license server:

```bash
# Using the existing keygen tool
go run cmd/keygen/main.go --generate-keypair

# Or use openssl
openssl genpkey -algorithm ed25519 -out license-key.pem
openssl pkey -in license-key.pem -outform DER | xxd -p -c 0
```

The hex-encoded private key goes in `TRITON_LICENSE_SERVER_SIGNING_KEY`. The corresponding public key must be embedded in the Triton CLI binary (via `internal/license/pubkey.go` or ldflags) for offline token verification.

---

## 6. Authentication

The admin web UI and all `/api/v1/admin/*` endpoints require a **JWT Bearer token**. There is no static admin API key — all access is through user accounts with the `platform_admin` role.

### First-Boot Setup

On a fresh database the server seeds one superadmin using the bootstrap env vars (`TRITON_LICENSE_SERVER_ADMIN_EMAIL` / `TRITON_LICENSE_SERVER_ADMIN_PASSWORD`). If the DB already has users the bootstrap vars are ignored.

Alternatively, the setup wizard at `POST /api/v1/setup/first-admin` can create the initial admin when no users exist yet:

```bash
# Check whether first-time setup is needed
curl http://localhost:8081/api/v1/setup/status
# → {"setupRequired": true}  or  {"setupRequired": false}

# Create the first platform admin (only works when setupRequired = true)
curl -X POST http://localhost:8081/api/v1/setup/first-admin \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "name": "Admin", "password": "secure-password-here"}'
```

### Login

```bash
curl -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "your-password"}'
# → {"token": "<jwt>", "expiresAt": "...", "mustChangePassword": false}
```

Tokens are valid for 24 hours. Store the `token` value and pass it as `Authorization: Bearer <token>` on all subsequent admin requests.

### Token Refresh

```bash
curl -X POST http://localhost:8081/api/v1/auth/refresh \
  -H "Authorization: Bearer <old-token>"
# → {"token": "<new-jwt>", "expiresAt": "..."}
```

Call this before the 24-hour TTL expires to keep a session alive without re-entering credentials.

### Logout

```bash
curl -X POST http://localhost:8081/api/v1/auth/logout \
  -H "Authorization: Bearer <token>"
```

### Change Password

Required when `mustChangePassword: true` is returned at login (e.g., after an admin invite):

```bash
curl -X POST http://localhost:8081/api/v1/auth/change-password \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"current": "temp-password", "next": "new-secure-password"}'
# → {"token": "<new-jwt>", "expiresAt": "..."}
```

The response contains a fresh token — old sessions are revoked immediately.

### Managing Platform Admins

Platform admins can invite additional superadmins. The server generates a temporary password and (if Resend is configured) emails it to the new admin:

```bash
# Invite a new platform admin
curl -X POST http://localhost:8081/api/v1/admin/superadmins \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email": "ops@example.com", "name": "Ops Team"}'
# → {"user": {...}, "tempPassword": "...", "emailSent": true}

# List all platform admins
curl http://localhost:8081/api/v1/admin/superadmins \
  -H "Authorization: Bearer <token>"

# Resend invite (rotates temp password, revokes old sessions)
curl -X POST http://localhost:8081/api/v1/admin/superadmins/<id>/resend-invite \
  -H "Authorization: Bearer <token>"

# Delete a platform admin (cannot delete self or the last admin)
curl -X DELETE http://localhost:8081/api/v1/admin/superadmins/<id> \
  -H "Authorization: Bearer <token>"
```

---

## 7. Organization Management

All org endpoints require `Authorization: Bearer <token>`.

### Create an Organization

```bash
curl -X POST http://localhost:8081/api/v1/admin/orgs \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Corp",
    "contact_name": "John Smith",
    "contact_email": "john.smith@acme.com",
    "contact_phone": "+60 12-345 6789"
  }'
```

`contact_name` and `contact_email` are required. `contact_phone` is optional. `contact_email` must be a valid RFC 5322 address (bare address, no display-name format). Expiry warning emails are sent to `contact_email` when a license is 30, 7, or 1 day from expiry.

### List Organizations

```bash
curl http://localhost:8081/api/v1/admin/orgs \
  -H "Authorization: Bearer <token>"
```

### Update an Organization

```bash
curl -X PUT http://localhost:8081/api/v1/admin/orgs/<org-id> \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp Updated", "contact_name": "Jane Doe", "contact_email": "jane.doe@acme.com"}'
```

### Suspend an Organization

Suspending an org blocks all new activations for its licenses while preserving existing ones:

```bash
curl -X POST http://localhost:8081/api/v1/admin/orgs/<org-id>/suspend \
  -H "Authorization: Bearer <token>"
```

---

## 8. License Management

All license endpoints require `Authorization: Bearer <token>`.

### Create a License

```bash
curl -X POST http://localhost:8081/api/v1/admin/licenses \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"orgID": "<org-id>", "tier": "pro", "seats": 10, "days": 365}'
```

Parameters:
- `orgID` — Organization UUID
- `tier` — `free`, `pro`, or `enterprise`
- `seats` — Maximum concurrent machine activations (0 = unlimited)
- `days` — License validity in days (default: 365)

### List Licenses

```bash
# All licenses
curl http://localhost:8081/api/v1/admin/licenses \
  -H "Authorization: Bearer <token>"

# Filter by org
curl "http://localhost:8081/api/v1/admin/licenses?org=<org-id>" \
  -H "Authorization: Bearer <token>"
```

### Update a License

```bash
curl -X PATCH http://localhost:8081/api/v1/admin/licenses/<license-id> \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"seats": 20}'
```

### Revoke a License

Revoking deactivates all machines and prevents new activations:

```bash
curl -X POST http://localhost:8081/api/v1/admin/licenses/<license-id>/revoke \
  -H "Authorization: Bearer <token>"
```

### Generate Install Token

Creates a short-lived token for self-service client download and activation:

```bash
curl -X POST http://localhost:8081/api/v1/admin/licenses/<license-id>/install-token \
  -H "Authorization: Bearer <token>"
# → {"token": "<install-token>", "url": "https://license-server:8081/api/v1/install/<token>/"}
```

---

## 9. Client Activation

### Activate a Machine

On each machine that needs a Triton license:

```bash
triton license activate \
  --license-server http://license-server:8081 \
  --license-id <license-uuid>
```

This:
1. Computes the machine's SHA-3-256 fingerprint
2. Sends an activation request to the server
3. Receives a signed Ed25519 token
4. Saves the token to `~/.triton/license.key`
5. Saves metadata to `~/.triton/license.meta` (for offline fallback)

### Deactivate a Machine

```bash
triton license deactivate
```

This frees the seat on the server and removes local token files. The server URL and license ID are read from cached metadata.

### Check License Status

```bash
triton license show
```

Displays current tier, seats, server connection status, and cache freshness.

### Running Scans with Server Validation

Once activated, scans automatically validate against the license server:

```bash
# Server URL can be set via flag or cached from activation
triton --license-server http://license-server:8081 --profile standard
```

Or set the environment variable:

```bash
export TRITON_LICENSE_SERVER=http://license-server:8081
```

---

## 10. Admin Web UI

Access the admin dashboard at `http://localhost:8081/ui/`.

On first visit you are shown a login page. Enter your platform admin email and password. The session token is stored in the browser and refreshed automatically. If `mustChangePassword` is set (new admin invite), you are redirected to a password-change screen before accessing the dashboard.

### Dashboard

Overview statistics: total organizations, licenses, active seats, revoked/expired counts.

### Organizations

Create, view, and delete organizations. Each organization requires a **contact name** and **contact email** address; an optional **contact phone** field is also available. The contact email receives expiry warning emails at 30, 7, and 1 day before the license expires.

### Licenses

Create licenses (select org, tier, seats, expiry), view license details with activation lists, and revoke licenses.

### Activations

View all machine activations across all licenses.

### Audit Log

Chronological log of all actions: org creation, license creation, activations, deactivations, revocations.

---

## 11. Binary Downloads

The license server can host Triton CLI binaries for client self-service download. This eliminates the need to share binaries manually — clients visit a download page, enter their license ID, and get the correct binary for their platform.

### Admin: Uploading Binaries

Upload binaries via the admin API or the admin web UI.

**Via API (curl):**

```bash
# Upload a Linux amd64 binary
curl -X POST https://license-server:8081/api/v1/admin/binaries \
  -H "Authorization: Bearer <token>" \
  -F "file=@bin/triton" \
  -F "version=3.1" \
  -F "os=linux" \
  -F "arch=amd64"

# Upload a Windows amd64 binary
curl -X POST https://license-server:8081/api/v1/admin/binaries \
  -H "Authorization: Bearer <token>" \
  -F "file=@bin/triton.exe" \
  -F "version=3.1" \
  -F "os=windows" \
  -F "arch=amd64"
```

Parameters:
- `file` — The binary file (max 50 MB)
- `version` — Semver version string (e.g. `3.1`, `3.1.0`)
- `os` — `linux`, `darwin`, or `windows`
- `arch` — `amd64` or `arm64`

The server computes a SHA-256 checksum and stores the binary at `{BinariesDir}/{version}/{os}-{arch}/triton[.exe]` with a `meta.json` sidecar.

**Via Admin Web UI:**

1. Navigate to `https://license-server:8081/ui/` and go to the **Binaries** tab
2. Click **Upload Binary** and fill in the version, OS, architecture, and select the file
3. Click **Upload**

**Automated CI/CD upload:**

If `LICENSE_SERVER_URL` and `LICENSE_SERVER_TOKEN` are configured in your GitHub repository secrets, the release workflow can automatically upload binaries after each tagged release using a service account JWT.

### Admin: Managing Binaries

**List all uploaded binaries:**

```bash
curl https://license-server:8081/api/v1/admin/binaries \
  -H "Authorization: Bearer <token>"
```

**Delete a specific binary:**

```bash
curl -X DELETE https://license-server:8081/api/v1/admin/binaries/3.1/linux/amd64 \
  -H "Authorization: Bearer <token>"
```

### Client: Downloading Binaries

Clients download binaries through the self-service download page — no admin key required.

**Step 1: Open the download page**

Direct your clients to:

```
https://license-server:8081/download
```

**Step 2: Enter license ID**

The client enters their License ID (UUID) and clicks **Continue**. The page fetches the latest available version and platform list from the server.

**Step 3: Select platform and download**

The page auto-detects the client's operating system and architecture. The client clicks the download button for their platform (or selects an alternative).

The download is gated by license validation — revoked or expired licenses are rejected with a clear error message.

**Step 4: Install and activate**

After downloading, the page shows platform-specific instructions with the client's license ID pre-filled:

macOS / Linux:
```bash
chmod +x triton
sudo mv triton /usr/local/bin/triton
triton license activate --license-server https://license-server:8081 --license-id <license-id>
triton --version
triton license show
```

Windows (PowerShell):
```powershell
Move-Item triton.exe C:\Windows\triton.exe
triton license activate --license-server https://license-server:8081 --license-id <license-id>
triton --version
triton license show
```

### Configuration

The binaries directory is configured via environment variable:

| Variable | Default | Description |
|----------|---------|-------------|
| `TRITON_LICENSE_SERVER_BINARIES_DIR` | `/opt/triton/binaries` | Directory for uploaded binary files |

Ensure the directory exists and is writable by the server process. For container deployments, mount a persistent volume:

```bash
# Create directory on host
mkdir -p /opt/triton/binaries

# Docker/Podman: mount as volume
podman run -v /opt/triton/binaries:/opt/triton/binaries ...
```

### Download API Reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/admin/binaries` | Admin key | Upload binary (multipart form) |
| GET | `/api/v1/admin/binaries` | Admin key | List all binaries |
| DELETE | `/api/v1/admin/binaries/{version}/{os}/{arch}` | Admin key | Delete a binary |
| GET | `/api/v1/license/download/latest-version` | None | Latest version + available platforms |
| GET | `/api/v1/license/download/{version}/{os}/{arch}?license_id=UUID` | License ID | Download binary (license must be valid) |

---

## 12. Offline Fallback

When the license server is unreachable, the Triton CLI uses cached validation:

1. **Fresh cache (< 7 days)** — Uses the cached tier and seat info. Logs a warning.
2. **Stale cache (> 7 days)** — Falls back to free tier. Logs a warning.
3. **No cache** — Falls back to free tier (same as having no license).

The grace period is 7 days (`GracePeriodDays` in `internal/license/cache.go`).

Cache metadata is stored at `~/.triton/license.meta` and is updated on every successful server validation.

---

## 13. API Reference

### Admin API

### Auth API

No authentication required for login; JWT required for logout, refresh, and change-password.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/setup/status` | None | Check if first-boot setup is needed |
| POST | `/api/v1/setup/first-admin` | None | Create first platform admin (only when no users exist) |
| POST | `/api/v1/auth/login` | None | Email + password login → JWT |
| POST | `/api/v1/auth/logout` | Bearer | Invalidate current session |
| POST | `/api/v1/auth/refresh` | Bearer | Rotate JWT before expiry |
| POST | `/api/v1/auth/change-password` | Bearer | Change password + rotate token |

### Admin API

All `/api/v1/admin/*` endpoints require `Authorization: Bearer <token>` (platform admin role).

**Organizations**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/admin/orgs` | Create organization |
| GET | `/api/v1/admin/orgs` | List organizations |
| GET | `/api/v1/admin/orgs/{id}` | Get organization detail |
| PUT | `/api/v1/admin/orgs/{id}` | Update organization |
| DELETE | `/api/v1/admin/orgs/{id}` | Delete organization |
| POST | `/api/v1/admin/orgs/{id}/suspend` | Suspend organization |

**Licenses**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/admin/licenses` | Create license |
| GET | `/api/v1/admin/licenses` | List licenses (optional `?org=<id>`) |
| GET | `/api/v1/admin/licenses/{id}` | License detail + activations |
| PATCH | `/api/v1/admin/licenses/{id}` | Update license (seats, schedule, etc.) |
| POST | `/api/v1/admin/licenses/{id}/revoke` | Revoke license |
| POST | `/api/v1/admin/licenses/{id}/install-token` | Generate self-service install token |
| POST | `/api/v1/admin/licenses/{id}/agent-yaml` | Download agent.yaml for Manage Server |
| POST | `/api/v1/admin/licenses/{id}/bundle` | Download agent bundle (yaml + binary) |

**Activations & Audit**

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/admin/activations` | List all activations |
| POST | `/api/v1/admin/activations/{id}/deactivate` | Force-deactivate a machine |
| GET | `/api/v1/admin/audit` | Audit log |
| GET | `/api/v1/admin/stats` | Dashboard statistics |

**Platform Admins (Superadmins)**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/admin/superadmins` | Invite new platform admin |
| GET | `/api/v1/admin/superadmins` | List all platform admins |
| GET | `/api/v1/admin/superadmins/{id}` | Get platform admin |
| PUT | `/api/v1/admin/superadmins/{id}` | Update name or password |
| DELETE | `/api/v1/admin/superadmins/{id}` | Delete platform admin (cannot delete self or last admin) |
| POST | `/api/v1/admin/superadmins/{id}/resend-invite` | Rotate temp password + resend invite email |

**Binaries**

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/admin/binaries` | Upload binary (multipart form) |
| GET | `/api/v1/admin/binaries` | List uploaded binaries |
| DELETE | `/api/v1/admin/binaries/{version}/{os}/{arch}` | Delete a binary |

### Install API (self-service, no auth)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/install/{token}/` | Install script (bash/PowerShell) |
| GET | `/api/v1/install/{token}/binary/{os}/{arch}` | Download binary via install token |
| GET | `/api/v1/install/{token}/agent-yaml` | Download agent.yaml via install token |

### Client API

No authentication required (secured by license UUID + machine fingerprint).

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/license/activate` | Activate machine |
| POST | `/api/v1/license/deactivate` | Deactivate machine |
| POST | `/api/v1/license/validate` | Validate token (also pushes schedule overrides) |
| POST | `/api/v1/license/usage` | Push near-real-time usage metrics |
| GET | `/api/v1/license/download/latest-version` | Latest version + available platforms |
| GET | `/api/v1/health` | Health check |

---

## 14. Sizing & Capacity Planning

This section provides resource sizing recommendations based on the license server's architecture and runtime characteristics.

### Request Profile

The license server handles lightweight JSON payloads (100-300 bytes per request) with fast database queries. The two hot-path operations are:

| Endpoint | Frequency | DB Cost | Notes |
|----------|-----------|---------|-------|
| `POST /license/validate` | Every CLI run (if online) | 2 queries (license + activation lookup) | Skipped if cache is fresh and server unreachable |
| `POST /license/activate` | Once per machine setup | Serializable transaction (seat enforcement) | Heaviest operation; rare |
| `POST /license/deactivate` | Machine teardown | 1 update | Rare |
| `GET /license/download/...` | Binary download | 1 query (license check) | Large response (~10-50 MB); rare |
| `GET /admin/*` | Admin browsing | 1-2 queries per page | Negligible compared to client traffic |

### Built-in Limits

These are hardcoded in the server binary:

| Parameter | Value | Source |
|-----------|-------|--------|
| Max concurrent requests | 100 | `middleware.Throttle(100)` in `server.go` |
| Request body limit | 1 MB | `maxRequestBody` in handlers |
| Read timeout | 30 s | `http.Server.ReadTimeout` |
| Write timeout | 60 s | `http.Server.WriteTimeout` |
| Idle timeout | 120 s | `http.Server.IdleTimeout` |
| Client timeout | 15 s | `ServerClient.httpClient.Timeout` |
| DB connection pool | 25 | pgx v5 default `pool_max_conns` |
| Audit query limit | 10,000 rows | Capped in handler |
| Offline grace period | 7 days | `GracePeriodDays` in `cache.go` |

### Traffic Estimation

Estimate your peak concurrent validation requests:

```
peak_rps = (active_machines × scans_per_day) / 86400
```

For example, 500 machines running 4 scans/day = ~0.02 RPS average, ~2-5 RPS burst. The server easily handles this on minimal hardware.

The 7-day offline cache means machines that lose connectivity do not generate retry storms — they silently use cached validation until the grace period expires.

### Sizing Tiers

#### Small (up to 100 machines, 5 orgs)

Suitable for a single team or department pilot.

| Resource | Specification |
|----------|---------------|
| **License Server** | 1 vCPU, 128 MB RAM |
| **PostgreSQL** | Shared instance, 1 vCPU, 1 GB RAM |
| **Disk (DB)** | 1 GB (audit log grows ~1 KB/event) |
| **Container image** | ~10 MB (scratch-based) |
| **DB connections** | 25 (default, no tuning needed) |
| **Network** | <1 Mbps |

Compose example (default config — no changes needed):

```bash
make container-run-licenseserver
```

#### Medium (100-1,000 machines, 20 orgs)

Suitable for a ministry or agency-wide deployment.

| Resource | Specification |
|----------|---------------|
| **License Server** | 2 vCPU, 256 MB RAM |
| **PostgreSQL** | Dedicated instance, 2 vCPU, 4 GB RAM |
| **Disk (DB)** | 5 GB (with audit retention) |
| **DB connections** | 25-40 |
| **Network** | <5 Mbps |

Tune the connection pool via the connection string:

```bash
export TRITON_LICENSE_SERVER_DB_URL="postgres://triton:triton@db:5432/triton_license?sslmode=require&pool_max_conns=40"
```

#### Large (1,000-10,000 machines, 50+ orgs)

Suitable for cross-agency or national-scale deployment.

| Resource | Specification |
|----------|---------------|
| **License Server** | 2-4 vCPU, 512 MB RAM |
| **PostgreSQL** | Dedicated instance, 4 vCPU, 8 GB RAM, SSD storage |
| **Disk (DB)** | 20 GB+ (with audit retention policy) |
| **DB connections** | 50-60 (or use PgBouncer) |
| **Network** | <10 Mbps |
| **Redundancy** | Reverse proxy (nginx/HAProxy) + multiple server instances |

For deployments above 100 concurrent requests, place the license server behind a reverse proxy or run multiple instances (the server is stateless — all state is in PostgreSQL):

```
                          ┌─────────────────────┐
                          │    Load Balancer     │
                          │  (nginx / HAProxy)   │
                          └──────┬──────┬────────┘
                                 │      │
                    ┌────────────┘      └────────────┐
                    │                                 │
           ┌────────────────┐               ┌────────────────┐
           │ License Server │               │ License Server │
           │   Instance 1   │               │   Instance 2   │
           └───────┬────────┘               └───────┬────────┘
                   │                                 │
                   └──────────┬──────────────────────┘
                              │
                    ┌─────────┴──────────┐
                    │    PostgreSQL       │
                    │  (+ PgBouncer)      │
                    └────────────────────┘
```

### PostgreSQL Sizing Detail

The license server uses 6 tables plus a version tracker:

| Table | Row Size (avg) | Growth Rate | Index Pressure |
|-------|---------------|-------------|----------------|
| `organizations` | ~200 B | Static (manual CRUD) | Low |
| `licenses` | ~300 B | Slow (admin creates) | Low |
| `activations` | ~400 B | 1 row per machine | Medium |
| `audit_log` | ~500 B | 3-5 rows per activation event | **High** |
| `users` | ~300 B | Static (platform admin CRUD) | Low |
| `sessions` | ~200 B | 1 row per active browser session; pruned on logout/expiry | Low |

**Audit log is the primary storage driver.** Estimate:

```
audit_storage_per_year = machines × events_per_machine_per_year × 500 B
```

For 1,000 machines with ~20 events/machine/year: ~10 MB/year. For 10,000 machines: ~100 MB/year.

**Recommendation**: Implement periodic audit cleanup for deployments >1,000 machines. The license server does not include built-in retention — use a cron job or database-level policy:

```sql
-- Delete audit entries older than 1 year
DELETE FROM audit_log WHERE timestamp < NOW() - INTERVAL '1 year';
```

### Transaction Isolation

The `Activate` and `RevokeLicense` operations use PostgreSQL **serializable** isolation to enforce seat limits under concurrency. This means:

- Under high concurrent activation bursts (e.g., 100 machines activating simultaneously), some transactions will be retried by the database
- This is correct behavior — it prevents overselling seats
- At normal load, serializable overhead is negligible

### Memory Profile

The license server binary is a static Go binary (~10 MB on disk). Runtime memory:

| Component | Memory |
|-----------|--------|
| Go runtime + GC | ~10-15 MB |
| HTTP server (idle) | ~5 MB |
| DB connection pool (25 conns) | ~5-10 MB |
| Per-request overhead | ~10-50 KB |
| **Typical steady state** | **20-30 MB** |
| **Under load (100 concurrent)** | **50-80 MB** |

The server never caches data in-process — all state is in PostgreSQL. This means memory usage is predictable and does not grow with the number of orgs/licenses/activations.

### Availability Considerations

| Scenario | Client Behavior | Duration Tolerance |
|----------|----------------|-------------------|
| Server healthy | Online validation, cache refreshed | Indefinite |
| Server down, fresh cache | Uses cached tier, logs warning | Up to 7 days |
| Server down, stale cache | Degrades to free tier | Until server restored |
| Server down, no cache | Free tier (first-time users blocked) | Until server restored |

For production deployments:

- **99% availability** is sufficient for most deployments — the 7-day grace period absorbs planned maintenance windows
- **Health check endpoint**: `GET /api/v1/health` returns `200 OK` with `{"status":"ok"}` — use this for load balancer probes
- **Graceful shutdown**: The server drains in-flight requests for 10 seconds on `SIGTERM`/`SIGINT`
- **Database failover**: If PostgreSQL becomes unavailable, the server returns 500 errors; clients fall back to cache

### Quick Reference

| Machines | Server CPU | Server RAM | PostgreSQL | Disk | DB Pool |
|----------|-----------|------------|------------|------|---------|
| 1-100 | 1 vCPU | 128 MB | Shared, 1 vCPU / 1 GB | 1 GB | 25 |
| 100-1,000 | 2 vCPU | 256 MB | Dedicated, 2 vCPU / 4 GB | 5 GB | 40 |
| 1,000-10,000 | 2-4 vCPU | 512 MB | Dedicated, 4 vCPU / 8 GB | 20 GB | 60 |
| 10,000+ | 4+ vCPU (2+ instances) | 512 MB each | HA cluster, 8+ vCPU / 16 GB | 50 GB+ | PgBouncer |

---

## 15. Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `activation failed: seats full` | All seats consumed | Deactivate unused machines or increase seat count |
| `activation failed: license expired` | License past expiry | Create a new license with future expiry |
| `activation failed: license revoked` | License was revoked | Create a new license |
| `license server unreachable` | Network issue or server down | Check server is running; CLI will use offline cache if available |
| `Cache Status: stale` | Server unreachable for >7 days | Restore server connectivity; re-activate if needed |
| `401 Unauthorized` on admin API | Missing/expired JWT or wrong credentials | Log in via `POST /api/v1/auth/login` to get a fresh token |
| `429 Too Many Requests` on login | Too many failed login attempts | Wait for `Retry-After` seconds before retrying |
| `license server has no users and no bootstrap password set` | Fresh DB with no `TRITON_LICENSE_SERVER_ADMIN_PASSWORD` env var | Set the env var and restart, or use `POST /api/v1/setup/first-admin` |
| `database: failed to connect` | PostgreSQL unreachable | Check `TRITON_LICENSE_SERVER_DB_URL` and database availability |

### Diagnostic Commands

```bash
# Check server health
curl http://localhost:8081/api/v1/health

# View license server logs
podman logs triton-license-server

# Check client activation status
triton license show

# Force re-activation
triton license deactivate
triton license activate --license-server http://server:8081 --license-id <id>
```
