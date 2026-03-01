# Triton Client-Server Deployment Guide

This guide covers deploying Triton in client-server mode: a central server with PostgreSQL storage, remote agents submitting scan results, and a web dashboard for analysis.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Quick Start](#3-quick-start)
4. [Server Deployment](#4-server-deployment)
5. [Agent Deployment](#5-agent-deployment)
6. [Web Dashboard](#6-web-dashboard)
7. [API Reference](#7-api-reference)
8. [Licence Management](#8-licence-management)
9. [Production Checklist](#9-production-checklist)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Architecture Overview

```
                          ┌──────────────────────────────┐
                          │        Triton Server          │
  ┌──────────┐   HTTP     │  ┌────────┐  ┌───────────┐   │
  │  Agent A  │──────────▶│  │REST API │  │  Web UI   │   │
  │ (scanner) │   POST    │  │(chi/v5) │  │(embedded) │   │
  └──────────┘  /api/v1/  │  └────┬───┘  └───────────┘   │
                scans     │       │                       │
  ┌──────────┐            │       ▼                       │
  │  Agent B  │──────────▶│  ┌─────────┐                  │
  │ (scanner) │           │  │ Store   │                  │
  └──────────┘            │  │ (pgx)   │                  │
                          │  └────┬────┘                  │
  ┌──────────┐            │       │                       │
  │  Browser  │──────────▶│       ▼                       │
  │ (Web UI)  │  :8080    │  ┌──────────┐                 │
  └──────────┘            │  │PostgreSQL│                 │
                          │  │   18     │                 │
                          │  └──────────┘                 │
                          └──────────────────────────────┘
```

**Components:**

- **Server** — REST API + embedded web UI. Stores scan results in PostgreSQL. Provides diff, trend analysis, report generation, and policy evaluation.
- **Agent** — Runs scans on target machines and submits results to the central server via `POST /api/v1/scans`. Can run once or on a repeating interval.
- **PostgreSQL** — Stores scan results as JSONB. Supports upserts, machine history, and trend queries.
- **Web Dashboard** — Embedded single-page application served at `/ui/`. No separate build or deployment required.

> **Licence requirement:** Server and agent modes require an **enterprise** licence. See [Licence Management](#8-licence-management).

---

## 2. Prerequisites

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Podman (or Docker) | Podman 4.0+ / Docker 20.10+ | With compose plugin |
| PostgreSQL | 14+ | Containerised (included) or external |
| Enterprise licence | — | For server and agent modes |
| Go | 1.21+ | Only if building from source |

### Install Podman (macOS)

```bash
brew install podman
podman machine init
podman machine start
```

### Install Podman (Linux)

```bash
# Fedora/RHEL
sudo dnf install podman podman-compose

# Ubuntu/Debian
sudo apt install podman
pip3 install podman-compose
```

> **Docker users:** All `podman` commands in this guide work identically with `docker`. Replace `podman` with `docker` and `podman compose` with `docker compose`.

---

## 3. Quick Start

The fastest way to get a running Triton server with PostgreSQL:

```bash
git clone https://github.com/amiryahaya/triton.git
cd triton
make container-run
```

This single command:

1. Builds the `triton:local` container image (~10MB)
2. Starts PostgreSQL 18 (port 5434)
3. Starts the Triton server (port 8080)

Open `http://localhost:8080` in your browser to access the web dashboard.

To stop everything:

```bash
make container-stop
```

---

## 4. Server Deployment

### 4a. Container Image

**Build locally:**

```bash
make container-build
# Produces: triton:local
```

**Pull from registry:**

```bash
podman pull ghcr.io/amiryahaya/triton:latest
```

**Image details:**

- Multi-stage build: `golang:1.25` (builder) → `scratch` (production)
- Final image size: ~10MB
- Includes CA certificates (for PostgreSQL TLS) and timezone data
- Static binary with `CGO_ENABLED=0`
- Default entrypoint: `/triton server`

### 4b. PostgreSQL Setup

#### Using Compose (recommended for development)

```bash
# Start PostgreSQL only
make db-up
```

This starts PostgreSQL 18 with:

- **Port:** 5434 (mapped from container's 5432)
- **Database:** `triton`
- **Username:** `triton`
- **Password:** `triton`
- **Volume:** `triton-data` mounted at `/var/lib/postgresql`

Additional database commands:

```bash
# Stop PostgreSQL
make db-down

# Destroy volume and recreate fresh
make db-reset
```

#### External PostgreSQL

Any PostgreSQL 14+ instance works. Create a dedicated database:

```sql
CREATE DATABASE triton;
CREATE USER triton WITH PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE triton TO triton;
```

Connection URL format:

```
postgres://user:password@host:port/dbname?sslmode=require
```

Triton auto-creates tables on first connection (no manual migration needed).

### 4c. Server Configuration

All server flags and their defaults:

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `:8080` | Bind address (host:port) |
| `--db` | `postgres://triton:triton@localhost:5434/triton?sslmode=disable` | PostgreSQL connection URL |
| `--api-key` | _(none)_ | API key for authentication (repeatable) |
| `--tls-cert` | _(none)_ | Path to TLS certificate file |
| `--tls-key` | _(none)_ | Path to TLS private key file |
| `--license-key` | _(none)_ | Enterprise licence token |

**Run the server binary directly:**

```bash
triton server \
  --listen :8080 \
  --db "postgres://triton:triton@localhost:5434/triton?sslmode=disable" \
  --license-key "$TRITON_LICENSE_KEY"
```

**Run with podman (no compose):**

```bash
podman run -d \
  --name triton-server \
  -p 8080:8080 \
  -e TRITON_LICENSE_KEY="$TRITON_LICENSE_KEY" \
  triton:local \
  server \
    --listen :8080 \
    --db "postgres://triton:triton@host.containers.internal:5434/triton?sslmode=disable"
```

> When running in a container, use `host.containers.internal` (podman) or `host.docker.internal` (Docker) to reach PostgreSQL on the host machine.

**Using compose (full stack):**

The included `compose.yaml` defines both services. The triton server is behind a `server` profile:

```bash
# Start PostgreSQL + Triton server
podman compose --profile server up -d

# Or equivalently:
make container-run
```

Inside the compose network, PostgreSQL is reachable at `postgres:5432` (not `localhost:5434`).

### 4d. TLS Configuration

#### Generate a Self-Signed Certificate (testing only)

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout server.key -out server.crt \
  -days 365 -subj "/CN=triton-server"
```

#### Run Server with TLS

**Binary:**

```bash
triton server \
  --listen :8443 \
  --tls-cert server.crt \
  --tls-key server.key \
  --db "postgres://triton:triton@localhost:5434/triton?sslmode=disable" \
  --license-key "$TRITON_LICENSE_KEY"
```

**Container (mount certs read-only):**

```bash
podman run -d \
  --name triton-server \
  -p 8443:8443 \
  -v ./server.crt:/certs/server.crt:ro \
  -v ./server.key:/certs/server.key:ro \
  -e TRITON_LICENSE_KEY="$TRITON_LICENSE_KEY" \
  triton:local \
  server \
    --listen :8443 \
    --tls-cert /certs/server.crt \
    --tls-key /certs/server.key \
    --db "postgres://triton:triton@host.containers.internal:5434/triton?sslmode=disable"
```

### 4e. API Key Authentication

API key authentication protects all API endpoints (except the health check).

**Configure keys on the server:**

```bash
triton server \
  --api-key "key-for-agent-a" \
  --api-key "key-for-agent-b" \
  --db "postgres://triton:triton@localhost:5434/triton?sslmode=disable" \
  --license-key "$TRITON_LICENSE_KEY"
```

Multiple `--api-key` flags can be specified. Each agent or API consumer gets its own key.

**How it works:**

- Clients must send the `X-Triton-API-Key` header with every request
- The health endpoint (`GET /api/v1/health`) is exempt from authentication
- Key comparison uses `crypto/subtle.ConstantTimeCompare` (timing-attack resistant)
- Missing key returns `401 Unauthorized`; invalid key returns `403 Forbidden`

**Example authenticated request:**

```bash
curl -H "X-Triton-API-Key: key-for-agent-a" \
  http://localhost:8080/api/v1/scans
```

---

## 5. Agent Deployment

### 5a. Overview

The agent runs scans on target machines and submits results to a central Triton server. It:

- Performs a local scan using the configured profile
- Saves results locally (if PostgreSQL is available)
- Submits results to the server via `POST /api/v1/scans`
- Can run once or on a repeating interval
- Identifies itself as `triton-agent/{version}/{os}` in scan metadata
- Checks server connectivity before scanning (healthcheck)

### 5b. Agent Flags

| Flag | Default | Required | Description |
|------|---------|----------|-------------|
| `--server` | — | Yes | Server URL (e.g. `http://server:8080`) |
| `--api-key` | — | No | API key matching one of the server's `--api-key` values |
| `--profile` | `quick` | No | Scan profile: `quick`, `standard`, `comprehensive` |
| `--interval` | `0` | No | Repeat interval (e.g. `1h`, `24h`). If unset, runs once and exits |
| `--license-key` | — | No | Enterprise licence token (or use env/file) |

### 5c. Running the Agent

**Single scan:**

```bash
triton agent \
  --server http://server:8080 \
  --api-key "key-for-agent-a" \
  --profile standard \
  --license-key "$TRITON_LICENSE_KEY"
```

**Continuous scanning (every 24 hours):**

```bash
triton agent \
  --server http://server:8080 \
  --api-key "key-for-agent-a" \
  --profile standard \
  --interval 24h \
  --license-key "$TRITON_LICENSE_KEY"
```

**Container mode:**

```bash
podman run --rm \
  -e TRITON_LICENSE_KEY="$TRITON_LICENSE_KEY" \
  triton:local \
  agent \
    --server http://server:8080 \
    --api-key "key-for-agent-a" \
    --profile standard
```

> When scanning host filesystems from a container, bind-mount the target paths (e.g. `-v /etc:/scan/etc:ro`).

### 5d. Systemd Service (Linux)

For scheduled, persistent scanning on Linux servers:

```ini
# /etc/systemd/system/triton-agent.service
[Unit]
Description=Triton Cryptographic Scanner Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/triton agent \
  --server https://triton-server.internal:8443 \
  --api-key "agent-key-here" \
  --profile standard \
  --interval 24h
Environment=TRITON_LICENSE_KEY=eyJsaWQiOiI1YTgz...
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now triton-agent
sudo journalctl -u triton-agent -f
```

---

## 6. Web Dashboard

The web dashboard is an embedded single-page application served by the Triton server. No separate build or deployment is required.

**Access:** `http://server:8080/ui/` (or `http://server:8080/` which redirects to the UI)

**Features:**

- **Dashboard** — Aggregate statistics: total scans, machines, findings, risk breakdown
- **Machines** — List of scanned machines with latest scan details
- **Scans** — Full scan history with per-scan findings detail
- **Diff** — Compare two scans side-by-side to see what changed
- **Trend** — Chart cryptographic risk trends over time for a machine or all hosts

The dashboard uses vanilla JavaScript with Chart.js for visualisations. It communicates with the server's REST API. If API key authentication is enabled on the server, the dashboard makes unauthenticated requests from the browser — API keys protect the `/api/v1/` routes but the UI static assets are served without auth.

> **Note:** The diff and trend features require a **pro** or **enterprise** licence on the server.

---

## 7. API Reference

All endpoints are under `/api/v1/`. When API key authentication is enabled, include the `X-Triton-API-Key` header (except for health).

| Method | Path | Description | Licence |
|--------|------|-------------|---------|
| `GET` | `/api/v1/health` | Health check (no auth required) | Any |
| `POST` | `/api/v1/scans` | Submit a scan result | Any |
| `GET` | `/api/v1/scans` | List all scans | Any |
| `GET` | `/api/v1/scans/{id}` | Get a specific scan | Any |
| `DELETE` | `/api/v1/scans/{id}` | Delete a scan | Any |
| `GET` | `/api/v1/scans/{id}/findings` | Get findings for a scan | Any |
| `GET` | `/api/v1/machines` | List scanned machines | Any |
| `GET` | `/api/v1/machines/{hostname}` | Machine scan history | Any |
| `GET` | `/api/v1/diff` | Compare two scans | Pro+ |
| `GET` | `/api/v1/trend` | Trend data for a machine | Pro+ |
| `GET` | `/api/v1/aggregate` | Aggregate statistics | Any |
| `GET` | `/api/v1/reports/{id}/{format}` | Generate report from scan | Format-gated |
| `POST` | `/api/v1/policy/evaluate` | Evaluate policy against scan | Tier-gated |

**Format gating (reports):**

| Format | Licence Required |
|--------|-----------------|
| `json` | Any |
| `cdx`, `html`, `xlsx` | Pro+ |
| `sarif` | Enterprise |

**Policy gating:**

| Policy Type | Licence Required |
|-------------|-----------------|
| Builtin (NACSA-2030, CNSA-2.0) | Pro+ |
| Custom YAML | Enterprise |

---

## 8. Licence Management

Server and agent modes require an **enterprise** licence. For full details on generating and distributing licence keys, see [LICENSE_KEY_GUIDE.md](LICENSE_KEY_GUIDE.md).

### Quick Reference

**Licence resolution order** (first found wins):

1. `--license-key` CLI flag
2. `TRITON_LICENSE_KEY` environment variable
3. `~/.triton/license.key` file

**Machine binding:** Tokens are bound to a machine fingerprint by default (`SHA-256(hostname|GOOS|GOARCH)`). A token used on a different machine degrades to free tier. Use `--no-bind` when issuing tokens to create portable (unbound) tokens.

**Graceful degradation:** Invalid, expired, or machine-mismatched tokens never block Triton — they fall back to free tier. Free tier does not support server or agent modes.

### Tier Requirements Summary

| Feature | Free | Pro | Enterprise |
|---------|------|-----|------------|
| CLI scanning | Yes (limited) | Yes | Yes |
| Server mode | — | — | Yes |
| Agent mode | — | — | Yes |
| Diff / trend API | — | Yes | Yes |
| All report formats | — | Partial | Yes |
| Custom policies | — | — | Yes |
| DB persistence | — | Yes | Yes |

### Verify Licence

```bash
# Show active licence details
triton license show

# Verify a specific token
triton license verify <token>
```

---

## 9. Production Checklist

- [ ] **Database credentials** — Use strong credentials (not the default `triton/triton`)
- [ ] **TLS** — Enable TLS on the server (`--tls-cert` / `--tls-key`)
- [ ] **API keys** — Set `--api-key` on the server; configure matching keys on agents
- [ ] **Licence** — Use machine-bound enterprise licence on each node
- [ ] **Firewall** — Expose only the server port (8080 or 8443); block direct PostgreSQL access
- [ ] **PostgreSQL TLS** — Use `sslmode=require` or `sslmode=verify-full` in the DB connection URL
- [ ] **Volume backups** — Back up the `triton-data` PostgreSQL volume regularly
- [ ] **Agent scheduling** — Run agents with `--interval` or via systemd for continuous scanning
- [ ] **Monitoring** — Poll `GET /api/v1/health` from your monitoring system
- [ ] **Log aggregation** — Collect container logs: `podman logs triton-server`
- [ ] **Resource limits** — Set container memory/CPU limits in production compose files

---

## 10. Troubleshooting

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `cannot reach server: connection refused` | Server not running or wrong URL | Check server is running, verify `--server` URL |
| `opening database: failed to connect` | PostgreSQL not reachable | Check DB is running (`make db-up`), verify `--db` URL |
| `missing API key` (401) | Agent not sending API key | Add `--api-key` flag to agent command |
| `invalid API key` (403) | Key mismatch between agent and server | Ensure agent's `--api-key` matches one of the server's keys |
| `feature requires enterprise licence` | Server/agent without enterprise token | Set enterprise licence via `--license-key`, env, or file |
| `feature requires pro licence` (403 on /diff or /trend) | Server licence is free tier | Upgrade to pro or enterprise licence |
| Port 5434 in use | Another PostgreSQL or service on that port | Stop conflicting service or change port in `compose.yaml` |
| Port 8080 in use | Another service on that port | Use `--listen :8081` or change port mapping in compose |

### Diagnostic Commands

```bash
# Check server health
curl http://localhost:8080/api/v1/health

# View server logs
podman logs triton-server

# View PostgreSQL logs
podman logs triton-db

# Connect to PostgreSQL directly
podman exec -it triton-db psql -U triton

# Check running containers
podman ps

# Check container resource usage
podman stats

# Verify licence on the server
triton --license-key "$TRITON_LICENSE_KEY" license show

# Test agent connectivity
curl -H "X-Triton-API-Key: your-key" http://localhost:8080/api/v1/health
```

### Server Timeouts

The server has built-in timeouts:

| Timeout | Value |
|---------|-------|
| Read header | 10s |
| Read body | 30s |
| Write response | 60s |
| Idle connection | 120s |
| Request (middleware) | 60s |

If agents submit very large scan results, you may need to rebuild with adjusted timeouts in `pkg/server/server.go`.

### Rate Limiting

The server uses a throttle middleware allowing up to **100 concurrent requests**. Under heavy load from many agents, some requests may be queued. Scale the server horizontally or stagger agent scan intervals to mitigate.
