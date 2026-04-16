# Onboarding Phase 6 — Agent-Push + Per-Host Certs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** User clicks "Push agent to group" in the portal → engine pushes the `triton-agent` binary + per-host TLS cert to each Linux host via SSH → agent starts, registers with the engine via mTLS on port 9443, heartbeats every 30s, runs scans on demand, submits findings through the engine → host flips from `mode=agentless` to `mode=agent` in inventory.

**Architecture:** Engine becomes a mini-CA for its agents — signs per-host Ed25519 certs using its engine cert (which is itself signed by the org's engine-CA from Phase 2). Agents dial the engine on a dedicated port 9443 (separate from the portal-facing 8443), presenting their per-host cert. Engine routes: `/agent/register`, `/agent/heartbeat`, `/agent/scan` (trigger), `/agent/submit` (findings). The `triton-agent` binary is a Go daemon: heartbeat loop + on-demand scanner (triggered via heartbeat response) + findings submit. Push mechanism uses SSH (bootstrap-admin credential from Phase 4 keystore) to upload binary + cert + config + install systemd service.

**Tech Stack:** Go 1.25, `golang.org/x/crypto/ssh` for push, `crypto/x509` + `crypto/ecdh` for cert minting, existing `pkg/scanner` for agent-side scans, systemd unit file template, `jobqueue.Queue` for push jobs (5th consumer — already generic from Phase 7).

**Spec:** `docs/plans/2026-04-14-onboarding-design.md` §7.3 (agent-host mutual auth), §10 (agent-push lifecycle), §8.1 (fleet.agents table).

---

## Prerequisites

- [ ] Phase 7 merged (PR #63). Migration head: v22. Jobqueue abstraction available.
- [ ] Engine binary built and running with keystore + credential handler.
- [ ] Bootstrap-admin credential type already in the auth_type enum.

---

## File Map

**Create:**
- `pkg/server/agentpush/types.go` — PushJob, AgentRecord
- `pkg/server/agentpush/store.go` — Store interface
- `pkg/server/agentpush/postgres.go` + test
- `pkg/server/agentpush/handlers_admin.go` — portal admin: trigger push, list agents, uninstall
- `pkg/server/agentpush/handlers_gateway.go` — engine gateway: push-job poll/ack
- `pkg/server/agentpush/handlers_test.go`
- `pkg/server/agentpush/routes.go`
- `pkg/engine/agentpush/executor.go` — SSH push: upload binary + cert + config + install service
- `pkg/engine/agentpush/executor_test.go`
- `pkg/engine/agentpush/certmint.go` — per-host cert generation (engine signs)
- `pkg/engine/agentpush/certmint_test.go`
- `pkg/engine/agentpush/worker.go` — push-job polling loop
- `pkg/engine/agentpush/worker_test.go`
- `pkg/engine/agentgw/server.go` — agent-facing mTLS listener on port 9443
- `pkg/engine/agentgw/handlers.go` — /agent/register, /heartbeat, /scan, /submit
- `pkg/engine/agentgw/handlers_test.go`
- `cmd/triton-agent/main.go` — agent binary
- `cmd/triton-agent/config.go` — config loader
- `pkg/tritonagent/client.go` — agent HTTP client (mTLS to engine)
- `pkg/tritonagent/loop.go` — heartbeat + on-demand scan + submit
- `pkg/tritonagent/loop_test.go`
- `Containerfile.agent` — agent container (for dev; production uses bare binary)
- `pkg/engine/agentpush/systemd.go` — systemd unit file template

**Modify:**
- `pkg/store/migrations.go` — v23 (agent_push_jobs + fleet_agents tables)
- `pkg/engine/loop/loop.go` — add PushWorker slot + agent gateway start
- `cmd/triton-engine/main.go` — wire push worker + agent gateway listener
- `cmd/server.go` + `cmd/server_engine.go` — mount agentpush admin + gateway routes
- `pkg/server/ui/dist/manage/app.js` — `#/fleet` page, "Push agent" button on groups
- `pkg/server/ui/dist/manage/index.html` — Fleet nav link
- `Makefile` — `build-agent`, `container-build-agent`

---

### Task 1: Migration v23 — push jobs + fleet agents

```go
`
CREATE TABLE agent_push_jobs (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine_id       UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    group_id        UUID REFERENCES inventory_groups(id) ON DELETE SET NULL,
    host_ids        UUID[] NOT NULL,
    credential_profile_id UUID NOT NULL REFERENCES credentials_profiles(id) ON DELETE RESTRICT,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled')),
    error           TEXT,
    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    progress_total  INTEGER NOT NULL DEFAULT 0,
    progress_done   INTEGER NOT NULL DEFAULT 0,
    progress_failed INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_agent_push_jobs_engine_queue
    ON agent_push_jobs(engine_id, requested_at)
    WHERE status = 'queued';

CREATE TABLE fleet_agents (
    id               UUID PRIMARY KEY,
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    host_id          UUID NOT NULL REFERENCES inventory_hosts(id) ON DELETE CASCADE,
    engine_id        UUID NOT NULL REFERENCES engines(id) ON DELETE CASCADE,
    cert_fingerprint TEXT NOT NULL UNIQUE,
    installed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat   TIMESTAMPTZ,
    version          TEXT,
    status           TEXT NOT NULL DEFAULT 'installing'
                     CHECK (status IN ('installing', 'healthy', 'unhealthy', 'uninstalled')),
    UNIQUE (host_id)
);

CREATE INDEX idx_fleet_agents_engine ON fleet_agents(engine_id);
CREATE INDEX idx_fleet_agents_status ON fleet_agents(status);
`,
```

Commit: `feat(store): agent_push_jobs + fleet_agents tables (v23)`

---

### Task 2: Per-host cert minting

Create `pkg/engine/agentpush/certmint.go` + test.

The engine signs per-host agent certs using its own engine cert as the CA. The engine's private key lives in memory (loaded from the bundle on startup).

```go
package agentpush

import (
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "time"
)

type AgentCert struct {
    CertPEM       []byte
    KeyPEM        []byte
    EngineCACert  []byte // engine's own cert (agents use this as their CA trust root)
    Fingerprint   string // SHA-256 hex of cert DER
}

// MintAgentCert generates an Ed25519 keypair for a host, signs a client cert
// using the engine's private key (engine acts as CA for its agents).
// Cert validity: 90 days. ExtKeyUsage: ClientAuth.
func MintAgentCert(engineCert *x509.Certificate, engineKey any, hostname string) (*AgentCert, error) {
    agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }

    serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    template := x509.Certificate{
        SerialNumber: serial,
        Subject:      pkix.Name{CommonName: hostname, Organization: []string{"Triton Agent"}},
        NotBefore:    time.Now().UTC(),
        NotAfter:     time.Now().UTC().AddDate(0, 0, 90),
        KeyUsage:     x509.KeyUsageDigitalSignature,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
    }

    certDER, err := x509.CreateCertificate(rand.Reader, &template, engineCert, agentPub, engineKey)
    if err != nil {
        return nil, err
    }

    certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
    keyDER, _ := x509.MarshalPKCS8PrivateKey(agentPriv)
    keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

    fp := sha256Hex(certDER)

    engineCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: engineCert.Raw})

    return &AgentCert{
        CertPEM:      certPEM,
        KeyPEM:       keyPEM,
        EngineCACert: engineCertPEM,
        Fingerprint:  fp,
    }, nil
}
```

Tests:
- `TestMintAgentCert_RoundTrip` — mint + parse back, verify CN + validity + KeyUsage
- `TestMintAgentCert_VerifiesAgainstEngineCA` — x509.Verify with engine cert as root pool
- `TestMintAgentCert_UniqueSerials` — two mints produce different serials

Commit: `feat(engine/agentpush): per-host Ed25519 cert minting signed by engine CA`

---

### Task 3: Systemd unit template + SSH push executor

Create `pkg/engine/agentpush/systemd.go` — template for the agent systemd service:

```go
const agentServiceTemplate = `[Unit]
Description=Triton Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/triton/triton-agent
Restart=always
RestartSec=10
WorkingDirectory=/opt/triton
Environment=TRITON_AGENT_CONFIG=/opt/triton/agent.yaml

[Install]
WantedBy=multi-user.target
`
```

Agent config template (`agent.yaml`):

```yaml
engine_url: https://<engine-address>:9443
cert_path: /opt/triton/agent.crt
key_path: /opt/triton/agent.key
ca_path: /opt/triton/engine-ca.crt
scan_profile: standard
```

Create `pkg/engine/agentpush/executor.go` — pushes files + installs service per host:

```go
type Executor struct {
    Keystore      KeystoreReader
    EngineCert    *x509.Certificate
    EngineKey     any // ed25519.PrivateKey or ecdsa.PrivateKey
    EngineAddress string // host:port for agent config
    AgentBinary   []byte // pre-loaded triton-agent binary
}

type PushResult struct {
    HostID      string
    Success     bool
    Fingerprint string // cert fingerprint on success
    Error       string
}

func (e *Executor) PushToHost(ctx context.Context, host HostTarget, secretRef, authType string) PushResult {
    // 1. Keystore lookup → build SSH client (same as scanexec)
    // 2. MintAgentCert(e.EngineCert, e.EngineKey, host.Hostname)
    // 3. SSH: mkdir -p /opt/triton
    // 4. SFTP/SCP: upload triton-agent binary, agent.crt, agent.key, engine-ca.crt, agent.yaml
    // 5. SSH: chmod 0755 /opt/triton/triton-agent; chmod 0600 /opt/triton/agent.key
    // 6. SSH: write systemd unit to /etc/systemd/system/triton-agent.service
    // 7. SSH: systemctl daemon-reload && systemctl enable triton-agent && systemctl start triton-agent
    // 8. Return PushResult with cert fingerprint
}
```

For SSH file transfer, use `sftp` package (`github.com/pkg/sftp`) or shell-out `cat > file << EOF`. SFTP is cleaner. Add `github.com/pkg/sftp` dependency.

Tests:
- `TestPushToHost_SSHDialFail` — unreachable host → error
- `TestPushToHost_KeystoreMiss` → error
- Full integration test deferred (requires real SSH target)

Commit: `feat(engine/agentpush): SSH push executor with systemd install`

---

### Task 4: Push worker + portal store + handlers

Uses `jobqueue.Queue` (5th consumer). Same pattern as scanjobs but for push jobs.

**Portal store:** `pkg/server/agentpush/{types,store,postgres}.go` with:
- `CreatePushJob`, `GetPushJob`, `ListPushJobs`, `CancelPushJob`
- `ClaimNext` → enrich with host targets + credential info (same as scanjobs)
- `UpdateProgress`, `FinishJob` (via jobqueue)
- `RegisterAgent(ctx, agent FleetAgent)` — insert into `fleet_agents`
- `GetAgent`, `ListAgents`, `UpdateAgentHeartbeat`, `UninstallAgent`

**Portal admin handlers:** `/api/v1/manage/agent-push/*`
- `POST /` — create push job (Engineer+). Body: `{group_id, credential_profile_id}`. Same one-engine-per-job validation as scanjobs.
- `GET /` — list push jobs
- `GET /{id}` — get push job
- `POST /{id}/cancel` — cancel queued
- `GET /agents` — list fleet agents for org
- `POST /agents/{id}/uninstall` — queue uninstall job (Engineer+)

**Portal gateway handlers:** `/api/v1/engine/agent-push/*` (mTLS)
- `GET /poll` — long-poll for push jobs
- `POST /{id}/progress` — per-host push status
- `POST /{id}/finish` — terminal-state guard via jobqueue
- `POST /agents/register` — engine reports successful agent installation with cert fingerprint + host_id; portal flips `inventory_hosts.mode = 'agent'` and inserts into `fleet_agents`

Push worker on engine: `pkg/engine/agentpush/worker.go` mirrors scanexec.Worker.

Commit (3 commits):
- `feat(agentpush): portal store + handlers + jobqueue consumer`
- `feat(agentpush): engine-side push worker`
- `feat(server): wire agent-push admin + gateway routes`

---

### Task 5: Agent gateway on engine (port 9443)

Create `pkg/engine/agentgw/server.go` — a second mTLS listener on the engine:

```go
package agentgw

import (
    "crypto/tls"
    "crypto/x509"
    "net/http"

    "github.com/go-chi/chi/v5"
)

type Server struct {
    Addr       string // default :9443
    EngineCert tls.Certificate
    EngineCA   *x509.CertPool // engine's own cert as the trust root for agents
    Handler    http.Handler
}

func (s *Server) ListenAndServeTLS(ctx context.Context) error {
    tlsCfg := &tls.Config{
        Certificates: []tls.Certificate{s.EngineCert},
        ClientAuth:   tls.RequireAndVerifyClientCert,
        ClientCAs:    s.EngineCA,
        MinVersion:   tls.VersionTLS12,
    }
    srv := &http.Server{
        Addr:      s.Addr,
        Handler:   s.Handler,
        TLSConfig: tlsCfg,
        ReadTimeout:  5 * time.Minute,
        WriteTimeout: 5 * time.Minute,
    }
    go func() { <-ctx.Done(); srv.Shutdown(context.Background()) }()
    return srv.ListenAndServeTLS("", "") // certs from TLSConfig
}
```

Create `pkg/engine/agentgw/handlers.go`:

```go
type Handlers struct {
    // For agent registration callback to portal
    PortalClient PortalRegistrar
    // For findings submission to portal
    ScanSubmitter ScanSubmitter
}

type PortalRegistrar interface {
    RegisterAgent(ctx context.Context, hostID, agentCertFingerprint string) error
}

type ScanSubmitter interface {
    SubmitScanFindings(ctx context.Context, jobID, hostID string, scanResult []byte, findings int) error
}
```

Endpoints (agent presents per-host cert; middleware extracts agent identity):
- `POST /agent/register` — agent sends `{host_id, version}`. Engine verifies cert fingerprint matches what it minted, then calls portal's `/api/v1/engine/agent-push/agents/register` to update fleet.
- `POST /agent/heartbeat` — agent sends `{host_id}`. Engine updates local state + relays to portal periodically (batched, not per-heartbeat).
- `GET /agent/scan` — agent long-polls for scan commands. Engine returns `{scan_profile, paths}` when a scan-job targets this host in agent mode. Returns 204 if no work.
- `POST /agent/submit` — agent submits scan findings. Engine relays to portal via existing scan-submit path.

**Agent identity middleware:** Extract cert fingerprint from `r.TLS.PeerCertificates[0]`, look up in a local in-memory map (populated during push). Reject unknown certs.

Commit: `feat(engine/agentgw): agent-facing mTLS listener + register/heartbeat/scan/submit handlers`

---

### Task 6: `triton-agent` binary

Create `cmd/triton-agent/main.go` + `pkg/tritonagent/{client,loop}.go`.

**Agent is minimal:**

```go
// cmd/triton-agent/main.go
func main() {
    cfgPath := os.Getenv("TRITON_AGENT_CONFIG")
    if cfgPath == "" { cfgPath = "/opt/triton/agent.yaml" }

    cfg := loadConfig(cfgPath) // engine_url, cert_path, key_path, ca_path, scan_profile

    c, err := tritonagent.NewClient(cfg)
    if err != nil { log.Fatal(err) }

    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    tritonagent.Run(ctx, c, cfg.ScanProfile)
}
```

**Client (`pkg/tritonagent/client.go`):**

```go
type Client struct {
    EngineURL string
    HTTP      *http.Client // mTLS configured
    HostID    string       // from config or derived
}

func NewClient(cfg Config) (*Client, error) {
    cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
    caCert, _ := os.ReadFile(cfg.CAPath)
    pool := x509.NewCertPool()
    pool.AppendCertsFromPEM(caCert)

    tlsCfg := &tls.Config{
        Certificates:       []tls.Certificate{cert},
        RootCAs:            pool,
        InsecureSkipVerify: true, // MVP — engine uses self-signed server cert
        MinVersion:         tls.VersionTLS12,
    }

    return &Client{
        EngineURL: cfg.EngineURL,
        HTTP:      &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}, Timeout: 45 * time.Second},
    }, nil
}

func (c *Client) Register(ctx context.Context) error { /* POST /agent/register */ }
func (c *Client) Heartbeat(ctx context.Context) error { /* POST /agent/heartbeat */ }
func (c *Client) PollScan(ctx context.Context) (*ScanCommand, error) { /* GET /agent/scan */ }
func (c *Client) SubmitFindings(ctx context.Context, scanResult []byte) error { /* POST /agent/submit */ }
```

**Loop (`pkg/tritonagent/loop.go`):**

```go
func Run(ctx context.Context, c *Client, defaultProfile string) error {
    // 1. Register with engine (retry with backoff)
    // 2. Heartbeat loop (every 30s)
    // 3. Concurrent: poll for scan commands (long-poll)
    //    When scan command received:
    //    a. Load scan profile from command (or use default)
    //    b. Run scanner.Engine locally (no SshReader — direct filesystem)
    //    c. Submit findings to engine
}
```

The agent runs `scanner.Engine` in **local mode** (no FileReader injection — uses the default LocalReader). This is the same scanner the CLI uses, just triggered by the engine via the heartbeat/poll mechanism.

Tests:
- `TestRun_RegistersAndHeartbeats` — stub client, verify Register called once, Heartbeat called periodically
- `TestRun_ExecutesScanOnCommand` — stub PollScan returns a ScanCommand, verify local scanner runs + SubmitFindings called
- `TestRun_ExitsOnContextCancel`

Commit: `feat(triton-agent): agent binary with heartbeat + on-demand scan + submit`

---

### Task 7: Containerfile + Makefile

```dockerfile
# Containerfile.agent
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/amiryahaya/triton/internal/version.Version=${VERSION}" \
    -o /out/triton-agent ./cmd/triton-agent

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/triton-agent /triton-agent
ENTRYPOINT ["/triton-agent"]
```

Makefile:
```make
build-agent:
	go build -o bin/triton-agent ./cmd/triton-agent

container-build-agent:
	podman build -t triton-agent:local -f Containerfile.agent .
```

The agent binary also needs to be available as a **raw binary** for the push executor to SCP to targets. The push executor reads from a configurable path (env `TRITON_AGENT_BINARY_PATH`, default `/opt/triton/triton-agent`). For development, `make build-agent` produces `bin/triton-agent` which the engine can reference.

Commit: `feat(agent): Containerfile.agent + Makefile targets`

---

### Task 8: Engine loop wiring + agent gateway start

Extend `pkg/engine/loop/loop.go` Config:
- `PushWorker Worker` — push-job polling loop
- `AgentGateway func(ctx context.Context) error` — starts the 9443 listener

```go
if cfg.PushWorker != nil {
    go cfg.PushWorker.Run(ctx)
}
if cfg.AgentGateway != nil {
    go cfg.AgentGateway(ctx)
}
```

Wire in `cmd/triton-engine/main.go`:
- Construct push executor + push worker
- Construct agent gateway server (port 9443, engine cert as both server cert + CA for agent certs)
- Load agent binary from `TRITON_AGENT_BINARY_PATH`
- Start agent gateway alongside existing workers

Commit: `feat(engine): wire push worker + agent gateway into loop + main`

---

### Task 9: Portal server wiring

Mount admin routes at `/api/v1/manage/agent-push/*` (JWT).
Mount gateway routes at `/api/v1/engine/agent-push/*` (mTLS on 8443).
Start StaleReaper for push jobs.

Commit: `feat(server): wire agent-push admin + gateway routes + stale reaper`

---

### Task 10: Management UI — fleet page + push action

Add `#/fleet` route showing:
- List of installed agents (host, status, version, last heartbeat)
- "Push agent to group" button (form: group + credential profile → POST)
- Push job history with progress
- Per-agent uninstall button

Add "Push agent" action on Groups page alongside existing "Scan now".

Commit: `feat(ui): fleet management page + "Push agent" action on groups`

---

### Task 11: Verify + PR + review

- `go build ./...` clean
- `make lint` 0 issues
- Unit tests pass
- Integration tests pass
- Push, PR, dispatch code-reviewer

---

## Self-Review

**Spec coverage:**
- §7.3 (per-host TLS cert minted by engine): Task 2 ✓
- §10 (agent-push lifecycle): Tasks 3-4 ✓
- §8.1 (`fleet.agents` table): Task 1 ✓
- Agent calls back to engine (not portal): Task 5 ✓

**Deviations:**
1. **Agent gateway on separate port 9443** (not documented in spec — spec says agents call "back to engine" without specifying port). Cleaner TLS separation.
2. **WinRM push deferred.** Linux SSH only for MVP.
3. **Cert renewal deferred.** 90-day validity; manual re-push to renew.
4. **Agent auto-update deferred.** Version is recorded but not acted on.
5. **InsecureSkipVerify on agent → engine TLS.** Same MVP trade-off as engine → portal. Agent trusts engine via out-of-band config.
6. **Agent binary must be pre-built and available to the engine.** No in-process cross-compilation. Operator builds `triton-agent` for the target architecture and places it at `TRITON_AGENT_BINARY_PATH`.

**Risks:**
- Agent binary architecture mismatch (engine is amd64, target is arm64). Document: operator must provide the correct binary for the target architecture.
- SSH push requires root/sudo on the target for systemd unit installation. Bootstrap-admin credential must have sufficient privileges.
- Agent port 9443 must be reachable from all agent hosts — firewall rule required.
