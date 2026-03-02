# Triton License Server Guide

This guide covers deploying and managing the Triton License Server — a centralized service for org-based seat pool management, online token validation, and admin oversight.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Quick Start](#3-quick-start)
4. [Configuration](#4-configuration)
5. [Keypair Generation](#5-keypair-generation)
6. [Organization Management](#6-organization-management)
7. [License Management](#7-license-management)
8. [Client Activation](#8-client-activation)
9. [Admin Web UI](#9-admin-web-ui)
10. [Offline Fallback](#10-offline-fallback)
11. [API Reference](#11-api-reference)
12. [Sizing & Capacity Planning](#12-sizing--capacity-planning)
13. [Troubleshooting](#13-troubleshooting)

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
│  Triton CLI  │ ◄──────────────────────► │  License Server   │
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
export TRITON_LICENSE_SERVER_ADMIN_KEY="your-secret-admin-key"
export TRITON_LICENSE_SERVER_SIGNING_KEY="<hex-encoded-ed25519-private-key>"

./bin/triton-license-server
```

The server starts on `:8081` by default. Open `http://localhost:8081/ui/` for the admin dashboard.

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

| Variable | Default | Description |
|----------|---------|-------------|
| `TRITON_LICENSE_SERVER_LISTEN` | `:8081` | Listen address |
| `TRITON_LICENSE_SERVER_DB_URL` | (required) | PostgreSQL connection URL |
| `TRITON_LICENSE_SERVER_ADMIN_KEY` | (required) | API key for admin endpoints |
| `TRITON_LICENSE_SERVER_SIGNING_KEY` | (required) | Ed25519 private key (hex-encoded) |
| `TRITON_LICENSE_SERVER_TLS_CERT` | (optional) | TLS certificate file path |
| `TRITON_LICENSE_SERVER_TLS_KEY` | (optional) | TLS private key file path |

### Database Setup

The server auto-migrates its schema on startup. It uses its own tables (`organizations`, `licenses`, `activations`, `audit_log`) with a separate version tracker (`license_schema_version`), so it can share a PostgreSQL instance with the Triton scan server without conflicts.

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

## 6. Organization Management

### Create an Organization

```bash
curl -X POST http://localhost:8081/api/v1/admin/orgs \
  -H "X-Triton-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp", "contact": "admin@acme.com"}'
```

### List Organizations

```bash
curl http://localhost:8081/api/v1/admin/orgs \
  -H "X-Triton-Admin-Key: your-admin-key"
```

### Update an Organization

```bash
curl -X PUT http://localhost:8081/api/v1/admin/orgs/<org-id> \
  -H "X-Triton-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "Acme Corp Updated", "contact": "new@acme.com"}'
```

---

## 7. License Management

### Create a License

```bash
curl -X POST http://localhost:8081/api/v1/admin/licenses \
  -H "X-Triton-Admin-Key: your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{"orgID": "<org-id>", "tier": "pro", "seats": 10, "days": 365}'
```

Parameters:
- `orgID` — Organization UUID
- `tier` — `free`, `pro`, or `enterprise`
- `seats` — Maximum concurrent machine activations
- `days` — License validity in days (default: 365)

### List Licenses

```bash
# All licenses
curl http://localhost:8081/api/v1/admin/licenses \
  -H "X-Triton-Admin-Key: your-admin-key"

# Filter by org
curl "http://localhost:8081/api/v1/admin/licenses?org=<org-id>" \
  -H "X-Triton-Admin-Key: your-admin-key"
```

### Revoke a License

Revoking deactivates all machines and prevents new activations:

```bash
curl -X POST http://localhost:8081/api/v1/admin/licenses/<license-id>/revoke \
  -H "X-Triton-Admin-Key: your-admin-key"
```

---

## 8. Client Activation

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

## 9. Admin Web UI

Access the admin dashboard at `http://localhost:8081/ui/`.

On first visit, you'll be prompted for the admin API key. The key is stored in the browser's localStorage.

### Dashboard

Overview statistics: total organizations, licenses, active seats, revoked/expired counts.

### Organizations

Create, view, and delete organizations.

### Licenses

Create licenses (select org, tier, seats, expiry), view license details with activation lists, and revoke licenses.

### Activations

View all machine activations across all licenses.

### Audit Log

Chronological log of all actions: org creation, license creation, activations, deactivations, revocations.

---

## 10. Offline Fallback

When the license server is unreachable, the Triton CLI uses cached validation:

1. **Fresh cache (< 7 days)** — Uses the cached tier and seat info. Logs a warning.
2. **Stale cache (> 7 days)** — Falls back to free tier. Logs a warning.
3. **No cache** — Falls back to free tier (same as having no license).

The grace period is 7 days (`GracePeriodDays` in `internal/license/cache.go`).

Cache metadata is stored at `~/.triton/license.meta` and is updated on every successful server validation.

---

## 11. API Reference

### Admin API

All admin endpoints require the `X-Triton-Admin-Key` header.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/admin/orgs` | Create organization |
| GET | `/api/v1/admin/orgs` | List organizations |
| GET | `/api/v1/admin/orgs/{id}` | Get organization detail |
| PUT | `/api/v1/admin/orgs/{id}` | Update organization |
| DELETE | `/api/v1/admin/orgs/{id}` | Delete organization |
| POST | `/api/v1/admin/licenses` | Create license |
| GET | `/api/v1/admin/licenses` | List licenses |
| GET | `/api/v1/admin/licenses/{id}` | License detail + activations |
| POST | `/api/v1/admin/licenses/{id}/revoke` | Revoke license |
| GET | `/api/v1/admin/activations` | List all activations |
| POST | `/api/v1/admin/activations/{id}/deactivate` | Force-deactivate |
| GET | `/api/v1/admin/audit` | Audit log |
| GET | `/api/v1/admin/stats` | Dashboard statistics |

### Client API

No authentication required (secured by license UUID + machine fingerprint).

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/license/activate` | Activate machine |
| POST | `/api/v1/license/deactivate` | Deactivate machine |
| POST | `/api/v1/license/validate` | Validate token |
| GET | `/api/v1/health` | Health check |

---

## 12. Sizing & Capacity Planning

This section provides resource sizing recommendations based on the license server's architecture and runtime characteristics.

### Request Profile

The license server handles lightweight JSON payloads (100-300 bytes per request) with fast database queries. The two hot-path operations are:

| Endpoint | Frequency | DB Cost | Notes |
|----------|-----------|---------|-------|
| `POST /license/validate` | Every CLI run (if online) | 2 queries (license + activation lookup) | Skipped if cache is fresh and server unreachable |
| `POST /license/activate` | Once per machine setup | Serializable transaction (seat enforcement) | Heaviest operation; rare |
| `POST /license/deactivate` | Machine teardown | 1 update | Rare |
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

The license server uses 4 tables plus a version tracker:

| Table | Row Size (avg) | Growth Rate | Index Pressure |
|-------|---------------|-------------|----------------|
| `organizations` | ~200 B | Static (manual CRUD) | Low |
| `licenses` | ~300 B | Slow (admin creates) | Low |
| `activations` | ~400 B | 1 row per machine | Medium |
| `audit_log` | ~500 B | 3-5 rows per activation event | **High** |

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

## 13. Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `activation failed: seats full` | All seats consumed | Deactivate unused machines or increase seat count |
| `activation failed: license expired` | License past expiry | Create a new license with future expiry |
| `activation failed: license revoked` | License was revoked | Create a new license |
| `license server unreachable` | Network issue or server down | Check server is running; CLI will use offline cache if available |
| `Cache Status: stale` | Server unreachable for >7 days | Restore server connectivity; re-activate if needed |
| `401 Unauthorized` on admin API | Wrong or missing admin key | Verify `X-Triton-Admin-Key` matches `TRITON_LICENSE_SERVER_ADMIN_KEY` |
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
