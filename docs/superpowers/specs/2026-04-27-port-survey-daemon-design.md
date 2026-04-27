# Port Survey Daemon — Design Spec

**Date:** 2026-04-27
**Branch:** feat/network-discovery (follow-on to PR #102)
**Status:** Approved for implementation

---

## 1. Goal

Evolve the port survey feature from an in-process execution model (fingerprintx running inside the manage server) into a standalone `triton-portscan` binary that the manage server spawns as a subprocess per job. This gives process isolation, independent resource capping, and a pluggable Scanner interface so fingerprintx can be swapped for nmap, masscan, or rustscan without touching the communication or job lifecycle layers.

The same dispatcher + worker API + scanner interface pattern is explicitly designed to be reused by SSH agentless scanning (`triton-sshscan`) and any future external scan type.

---

## 2. Topology

```
[Manage Server machine]
  ├── manage server process
  │     ├── orchestrator  → filesystem jobs (in-process, unchanged)
  │     └── dispatcher    → port_survey / ssh_agentless jobs (spawns subprocesses)
  │
  ├── triton-portscan (subprocess, one per job)
  │     └── TCP probes → [Target Hosts]
  │
  └── triton-sshscan (future subprocess, one per job)
        └── SSH → [Target Hosts]

[Report Server]  ← triton-portscan submits ScanResult directly (POST /api/v1/scans)
```

**Key principle:** The manage server owns job state. External scan binaries own execution. Results bypass the manage server and go directly to the report server — same behaviour as triton-agent and SSH agentless.

---

## 3. User Flow

```
Operator → Manage Portal → ScanJobs page → Port Survey form
  - Select hosts: one or more from host list
  - Select profile: quick | standard | comprehensive
  - Schedule: now or specific datetime
  - Specific ports override (optional): e.g. "80,443,8080" or leave blank for profile default
  → Create

Manage server:
  - Creates N jobs in manage_scan_jobs (one per host, job_type = port_survey)
  - Dispatcher detects queued port_survey jobs
  - For each available slot (up to MaxConcurrent):
      - Samples host CPU + RAM
      - Computes dynamic resource caps
      - Spawns: triton-portscan --job-id <id> --max-cpu-percent N --max-memory NMiB ...
  - Each triton-portscan process:
      1. Claims its job (POST /v1/worker/jobs/{id}/claim)
      2. Resolves target IP (GET /v1/admin/hosts/{host_id})
      3. Starts heartbeat goroutine (every 30s)
      4. Runs FingerprintxScanner.Scan(ctx, Target{IP, Profile, RateLimit})
      5. Stops heartbeat
      6. Submits ScanResult directly to report server (POST /api/v1/scans)
      7. Marks job complete (POST /v1/worker/jobs/{id}/complete)
      8. Exits 0
```

---

## 4. Package Structure

```
cmd/triton-portscan/
  main.go                    — flags, wire FingerprintxScanner + clients, call runner.RunOne

pkg/scanrunner/              — shared foundation for ALL external scan binaries
  scanner.go                 — Scanner interface + Target + Finding + Credentials + TLSCertInfo
  runner.go                  — RunOne: claim → resolve host → scan → submit → complete
  client.go                  — ManageClient + ReportClient (HTTP)
  mapper.go                  — Finding[] → model.ScanResult

pkg/manageserver/portscan/   — fingerprintx implementation (refactored from PR #102)
  fingerprintx.go            — FingerprintxScanner implements scanrunner.Scanner
  tls.go                     — TLS cert extraction (unchanged)
  portlists.go               — port lists (unchanged)
  result_mapper.go           — REMOVED (consolidated into pkg/scanrunner/mapper.go)
  scan_func.go               — REMOVED (no longer in-process)

pkg/manageserver/scanjobs/
  dispatcher.go              — NEW: generic job_type → binary map, spawn + track processes
  orchestrator.go            — unchanged, handles filesystem jobs only
```

Future `triton-sshscan` adds:
```
cmd/triton-sshscan/main.go
pkg/manageserver/sshscan/sshagentless.go  — SSHAgentlessScanner implements scanrunner.Scanner
```

No changes to `pkg/scanrunner/` — the shared layer stays stable.

---

## 5. Scanner Interface (`pkg/scanrunner/scanner.go`)

The stable contract. Swapping the scan engine means implementing this interface and passing it to `runner.RunOne`. Nothing else changes.

```go
// Scanner is the pluggable port scanning engine.
// Implementations: FingerprintxScanner, future: NmapScanner, MasscanScanner, SSHAgentlessScanner.
type Scanner interface {
    Scan(ctx context.Context, target Target, onFinding func(Finding)) error
}

type Target struct {
    IP           string
    Profile      string      // "quick" | "standard" | "comprehensive"
    RateLimit    int         // max new TCP connections/sec; 0 = profile default
    PortOverride []uint16    // non-nil overrides profile port list; nil = use profile default
    Credentials  *Credentials // nil for port survey; populated for SSH agentless
}

type Credentials struct {
    Username   string
    Password   string
    PrivateKey []byte
    Port       int // default 22 for SSH
}

type Finding struct {
    Port    uint16
    Service string       // "ssh", "https", "smtp" etc.
    Banner  string       // version string / banner
    TLSCert *TLSCertInfo // non-nil when TLS certificate detected
}

type TLSCertInfo struct {
    Subject      string
    Issuer       string
    Algorithm    string // "RSA", "ECDSA"
    KeyBits      int
    NotBefore    time.Time
    NotAfter     time.Time
    SANs         []string
    SerialNumber string
    IsSelfSigned bool
}
```

**Profile-based rate limit defaults:**

| Profile | Concurrency | Rate limit (conn/s) | Scan time (est.) |
|---------|-------------|---------------------|-----------------|
| quick | 50 | 50 | ~5s |
| standard | 200 | 100 | ~20s |
| comprehensive | 500 | 200 | ~50s |

---

## 6. Dispatcher (`pkg/manageserver/scanjobs/dispatcher.go`)

### Config

```go
type DispatcherConfig struct {
    // job_type → executor config; extensible without code changes
    Executors map[string]ExecutorConfig

    MaxConcurrent int           // hard ceiling across all job types, default 4
    PollInterval  time.Duration // default 5s
    MaxCPUPct     int           // operator ceiling for dynamic cap, default 80
    MaxMemoryMiB  int           // operator ceiling for dynamic cap, default 1024
}

type ExecutorConfig struct {
    BinaryPath   string // "triton-portscan" (PATH-resolved) or absolute
    ManageURL    string // manage server base URL (self)
    WorkerKey    string // X-Worker-Key secret
    ReportURL    string // report server base URL
    LicenseToken string // report server auth token
}
```

### Poll loop

Every `PollInterval`:
1. Count in-flight processes → `slots = MaxConcurrent - len(running)`
2. If `slots == 0`: skip
3. Query store for queued jobs across all dispatched job_types, `scheduled_at <= NOW()`, limit = slots
   (requires new `Store.ListQueued(ctx, jobTypes []string, limit int) ([]Job, error)` method)
4. For each job: compute dynamic caps → spawn subprocess → track PID

### Dynamic resource caps

Sampled per spawn via `gopsutil`. Operator ceiling is never exceeded.

| Host CPU | Host free RAM | CPU cap | Memory cap | Action |
|----------|--------------|---------|------------|--------|
| < 50% | > 2 GB | min(MaxCPUPct, 50%) | min(MaxMemMiB, 512) | spawn |
| 50–70% | 1–2 GB | min(MaxCPUPct, 30%) | min(MaxMemMiB, 256) | spawn |
| > 70% | > 1 GB | min(MaxCPUPct, 15%) | min(MaxMemMiB, 128) | spawn |
| > 70% | < 1 GB | — | — | defer |

### Process lifecycle

```
spawn(jobID, executorCfg, caps):
  cmd = exec.CommandContext(ctx, binaryPath,
      "--job-id",          jobID,
      "--manage-server",   manageURL,
      "--worker-key",      workerKey,
      "--report-server",   reportURL,
      "--license-token",   licenseToken,
      "--max-cpu-percent", caps.cpuPct,
      "--max-memory",      caps.memMiB+"MiB",
  )
  cmd.Stdout, cmd.Stderr → manage server logger (structured, prefixed with job ID)
  cmd.Start()
  running[jobID] = cmd.Process
  go func() { cmd.Wait(); delete(running, jobID) }()
```

Dispatcher passes `--job-id` so the process claims its specific job — no SKIP LOCKED competition at spawn time. If the job was cancelled between spawn and claim, the process receives 409 and exits 0.

### Graceful shutdown

On `ctx.Done()`:
1. Stop polling
2. Wait up to 30s for in-flight processes to complete normally
3. After 30s: SIGTERM all remaining processes
4. Stale job reaper picks up any orphaned jobs within 5 minutes

---

## 7. Worker API (new manage server endpoints)

Authenticated via `X-Worker-Key` header. Route group: `/v1/worker/`.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/worker/jobs/{id}/claim` | Lock job → `status=running`, stamp `running_heartbeat_at` |
| `PATCH` | `/v1/worker/jobs/{id}/heartbeat` | Renew `running_heartbeat_at` |
| `POST` | `/v1/worker/jobs/{id}/complete` | `status=completed` |
| `POST` | `/v1/worker/jobs/{id}/fail` | `status=failed` + `{"error":"..."}` body |

Claim returns:
```json
{
  "job_id": "...",
  "host_id": "...",
  "profile": "standard",
  "credentials_ref": null
}
```

409 if job already claimed or cancelled. 404 if job not found.

---

## 8. `triton-portscan` Binary (`cmd/triton-portscan/`)

### Flags

```
--job-id           UUID of the job to claim (required, set by dispatcher)
--manage-server    Manage server base URL (required)
--worker-key       X-Worker-Key secret (required)
--report-server    Report server base URL (required)
--license-token    Report server auth token (required)
--max-cpu-percent  CPU cap 0–100 (optional, set by dispatcher)
--max-memory       Memory cap e.g. 256MiB (optional, set by dispatcher)
```

### Startup sequence

```
1. Parse flags
2. limits.Apply(maxCPU, maxMemory)       — reuse internal/runtime/limits/
3. POST /v1/worker/jobs/{id}/claim       — 404/409 → exit 0; 200 → got job
4. GET  /v1/admin/hosts/{host_id}        — resolve IP
5. Start heartbeat goroutine (30s tick)
6. FingerprintxScanner.Scan(ctx, Target{IP, Profile, RateLimit})
7. Stop heartbeat
8. mapper.ToScanResult(hostname, profile, findings)
9. POST /api/v1/scans on report server   — direct, same as triton-agent
10. POST /v1/worker/jobs/{id}/complete
11. Exit 0

On error after step 3: POST /v1/worker/jobs/{id}/fail + exit 1
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success, or job already claimed/cancelled (clean) |
| 1 | Scan or submission failed — job marked failed |
| 2 | Startup error (bad flags, unreachable manage server) |

---

## 9. Stale Job Reaper (extend existing)

Any job with `status = 'running'` AND `running_heartbeat_at < NOW() - 5min` → reset to `status = 'queued'`. Covers crashes, OOM kills, and network partitions. No operator intervention needed.

---

## 10. DDoS / Disruption Risk Mitigation

Port scanning sends many TCP connections to target hosts. fingerprintx uses full TCP connects (not raw SYN), which is more polite than nmap SYN scan, but comprehensive profile at 500 concurrent connections can still:

- Trigger IDS/IPS alerts on the target
- Temporarily overwhelm small devices (IoT, embedded, firewalls)

**Mitigations built into this design:**

1. **Rate limiting per target** — `Target.RateLimit` caps new connections/second; profile defaults: quick=50, standard=100, comprehensive=200
2. **`scheduled_at`** — operator can target off-hours maintenance windows (already in schema)
3. **UI warning** — manage portal shows a warning when comprehensive is selected: *"Comprehensive scan sends up to 200 TCP connections/second per host. Schedule during maintenance windows for sensitive targets."*
4. **Dynamic resource caps** — dispatcher defers spawning under host pressure, naturally throttling scan burst rate
5. **Process isolation** — one host per process; a disrupted scan for one host does not cascade to others

---

## 11. Manage Portal UI Changes

- Port Survey form: add **specific ports** field (comma-separated, overrides profile port list)
- Port Survey form: add **comprehensive warning banner** when profile = comprehensive
- ScanJobs list: `job_type = port_survey` badge already implemented (PR #102)
- No changes to Discovery.vue or Hosts.vue

---

## 12. What Changes from PR #102

| Component | PR #102 | This design |
|-----------|---------|-------------|
| `scan_func.go` | NewPortScanFunc wired to orchestrator | Removed |
| `result_mapper.go` | In portscan package | Moved to pkg/scanrunner/mapper.go |
| Orchestrator | Dispatches filesystem + port_survey | Filesystem only |
| Port survey execution | In-process goroutine | Subprocess per job |
| Resource limits | None | Dynamic + operator cap |
| Scanner swappability | No interface | Scanner interface |
| SSH agentless | Separate design | Shares dispatcher + scanrunner |

---

## 13. Out of Scope

- UDP port scanning
- Raw SYN scan (requires root/CAP_NET_RAW) — fingerprintx TCP connect is sufficient
- SNMP scanning — separate future job type
- Auto-discovery integration (Discovery.vue CIDR scan is separate; port survey targets known hosts)
