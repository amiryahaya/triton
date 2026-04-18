# Fleet Scan (SSH-Agentless) Architecture

Technical reference for `triton fleet-scan`. Covers runtime architecture, trust model, SSH connection lifecycle, portal integration, and every CLI option. Target audience: SREs, platform engineers, security reviewers, and Triton contributors.

Companion documents:
- `docs/plans/2026-04-18-fleet-scan-design.md` — design spec
- `docs/plans/2026-04-18-fleet-scan-plan.md` — implementation plan
- Source: `pkg/scanner/netscan/fleet/` + `cmd/fleet_scan.go`

---

## 1. What fleet-scan is (and isn't)

**Is:** an orchestrator that fans out `triton scan` across a host inventory via SSH, collects reports, and writes a summary. For each unix host in the inventory, the orchestrator:

1. Opens an SSH connection
2. Pushes the triton binary via SFTP
3. Launches `triton scan --detach` on the target (daemonised scan)
4. Polls the remote scan's `status.json` until it reaches a terminal state
5. Streams the report tarball back over the same SSH connection
6. Cleans up the binary + work directory on the target
7. Closes the SSH connection

**Isn't:**
- A persistent agent. Nothing is installed on the target. Every trace is removed after `--cleanup`.
- A pull-based scanner (like Qualys or Tenable that probe services remotely). Fleet-scan runs the full Triton scanner ON the target, so it sees files, processes, and crypto material that pure protocol probes cannot.
- A replacement for `triton device-scan` (formerly `network-scan`). Device-scan runs SSH/NETCONF protocol probes against routers and switches. Fleet-scan pushes a binary. They can target the same inventory but do different things.

The name "SSH-agentless" is an industry convention. Technically the triton binary IS an agent while running — it's just ephemeral. The binary is copied, executed, and removed within a single scan cycle.

---

## 2. Runtime architecture

### 2.1 Process layout

```
┌──────────────────────────────┐      ┌──────────────────────────────┐
│ Operator host (laptop / CI) │      │ Target host (unix server)    │
│                              │      │                              │
│ triton fleet-scan            │      │                              │
│ ├─ orchestrator worker pool  │ SSH  │  sshd                        │
│ │   (N goroutines)           ├─────▶│  └─ triton (ephemeral)       │
│ ├─ SSH client pool           │      │      ├─ detached daemon      │
│ ├─ inventory + credentials   │      │      │   (scan + status)     │
│ └─ summary writer            │      │      └─ work-dir             │
│                              │      │          ~/.triton/jobs/<id>/│
└──────────────────────────────┘      └──────────────────────────────┘
```

One triton binary runs in two roles simultaneously:
- **Parent** (operator host): `triton fleet-scan` orchestrator
- **Child** (target host): `triton scan --detach` daemon

The parent binary is also the binary that gets pushed — `os.Args[0]` by default. Override via `--binary /path/to/triton-<goos>-<goarch>` for cross-arch fleets or per-device in `devices.yaml` via `binary: /opt/triton-binaries/triton-aix-ppc64`.

### 2.2 Worker pool concurrency

```go
// pkg/scanner/netscan/fleet/orchestrator.go
func (o *Orchestrator) Run(ctx, devices, creds) ([]HostResult, error) {
    queue := make(chan Device, len(devices))
    for _, d := range devices { queue <- d }
    close(queue)

    var wg sync.WaitGroup
    for i := 0; i < o.cfg.Concurrency; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for d := range queue {
                result := scanHost(runCtx, &d, creds, o.cfg)
                // ... aggregate + check --max-failures
            }
        }()
    }
    wg.Wait()
}
```

Default `--concurrency 20`. Each worker:
- Owns its SSH connection for the lifetime of one host scan
- Contends only on a shared results slice (mutex-guarded) + atomic failure counter
- Exits cleanly on parent context cancel (`Ctrl+C` or `--max-failures` trip)

`--max-failures N` acts as a circuit breaker. When N hosts fail, the outer context is cancelled; in-flight workers finish their current phase and return. Parent exits with code 3.

### 2.3 Per-host scan phases

Each phase has a label that surfaces in the summary on failure:

| # | Phase       | SSH call                          | Failure mode                                    |
|---|-------------|-----------------------------------|-------------------------------------------------|
| 1 | `ssh connect` | TCP dial + SSH handshake + auth | Wrong key, bad user, host key mismatch, network |
| 2 | `uname`       | `uname -s -m`                   | Command not found (extremely rare)              |
| 3 | `arch mismatch` | _local_ arch resolution       | No compatible binary for target arch            |
| 4 | `sudo check`  | `sudo -n true 2>&1`             | NOPASSWD not configured                         |
| 5 | (dry-run exits here if `--dry-run` set) | — | — |
| 6 | `scp binary`  | SFTP `open` + `write` + `chmod` | Disk full, wrong perms, sftp subsystem blocked  |
| 7 | `launch`      | `triton scan --detach --quiet`  | License tier rejection, unsupported flag        |
| 8 | `poll`        | `triton scan --status --json` × N | Device-timeout, daemon crashed, malformed JSON |
| 9 | `collect`     | `triton scan --collect -o -`    | Partial stream, terminal state != done          |
| 10 | (optional) upload to `--report-server` | HTTP POST | Non-fatal — records as warning |
| 11 | `--cleanup` + `rm -f <binary>` | 2 SSH calls | Best-effort, never fails the overall scan |

Phases 2-11 all run over the SAME SSH connection. Only phase 1 opens a new one.

### 2.4 `go test -race` correctness

The worker pool is race-safe:
- Results slice: `sync.Mutex` protects append + read
- Failure counter: `sync/atomic.Int32`
- Context cancellation: idempotent; multiple workers can observe cancel simultaneously
- Shared dialer: called concurrently from N goroutines; must be safe (transport.SSHClient is; fakeDialer in tests uses a `newRunnerPerDialDialer` pattern that returns a fresh fakeRunner per call to avoid shared mutable state)

---

## 3. Trust model — NOPASSWD sudo

### 3.1 Why NOPASSWD is required

A triton scan needs to read system resources that are root-only on most unix systems:
- `/etc/ssl/private/` — private TLS keys
- `/etc/shadow` — password hashes
- `/root/.ssh/` — admin SSH state
- `/var/lib/` — database state, containers
- `/proc/<pid>/maps` — library paths for running processes (for the `library`/`binary` scanners)

If triton runs as the SSH user (no sudo), it reads only what that user can see. That's a *useful* but *incomplete* scan.

If triton runs as root via `sudo`, SSH password prompts become a problem. The shell is non-interactive and the SSH session has no TTY. A sudo prompt would hang until the connection times out. Even with `ssh -t`, password forwarding via sudo is fragile and a security liability (credentials in process args, timing-sensitive).

NOPASSWD sudo is the standard solution: a sudoers entry that lets the triton-scanner user run specific commands (or all commands) as root without a password. Fleet-scan checks this up front with `sudo -n true` (`-n` fails fast if a prompt would be needed) and aborts the scan before touching the binary if it's misconfigured.

### 3.2 Sudoers configuration

The operator installs this on each target host:

```
# /etc/sudoers.d/triton-scanner
triton-scanner ALL=(ALL) NOPASSWD: ALL
```

`chmod 440 /etc/sudoers.d/triton-scanner` and `visudo -c` to validate syntax.

**Tighter scope** (recommended for production): limit to the triton binary and the work-dir:

```
# /etc/sudoers.d/triton-scanner
triton-scanner ALL=(root) NOPASSWD: /tmp/.triton-*, /home/triton-scanner/.triton/*
```

This prevents the triton-scanner user from escalating outside the scan workflow. Note: `/tmp/.triton-<uuid8>` is how fleet-scan names its pushed binary, so the glob must match. Adjust the path if you set `--work-dir` or `device.work_dir` to something else.

### 3.3 When NOPASSWD isn't set

Two options:

1. **Set `sudo: false` in the inventory.** Fleet-scan will run triton as the SSH user, skip `sudo -n true`, and accept reduced coverage. Findings will be a subset of what a root scan would produce. Useful for air-gapped hosts where NOPASSWD is a compliance headache.

2. **Fail the scan.** Default when `sudo: true` and NOPASSWD isn't configured. Fleet-scan exits phase 4 with `sudo check: NOPASSWD sudo required` and the host is recorded as `failed` in summary.json. The binary is never uploaded.

### 3.4 Audit trail

On the target host, every fleet-scan invocation leaves these traces in system logs:

- `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL): SSH login + the sudo commands executed (timestamp, user, command)
- `/var/log/syslog`: the daemon's stdout (when `--format all` writes progress lines)
- `journalctl -u ssh`: SSH session start/end

For compliance, the `sudo -n true` preflight also appears as a logged audit event. Operators can grep `journalctl` for the scan window to reconstruct what happened.

Fleet-scan does NOT leave anything on disk after `--cleanup`:
- Binary removed via `rm -f <remote-path>`
- Work-dir removed via `triton scan --cleanup --job-id <id>`
- Result tarball exists only on the operator's local `--output-dir` (or uploaded to `--report-server`)

---

## 4. SSH shell lifecycle

### 4.1 Connection = one host scan

Fleet-scan does NOT keep SSH connections open across hosts. Each worker goroutine:

```
[open SSH] → [run 7-8 commands back-to-back] → [close SSH]
```

The SSH connection stays open for the entire per-host scan duration (from `ssh connect` through `--cleanup`). For a 2-minute scan on a quick profile, that's 2 minutes of a held connection. For a 4-hour comprehensive scan, that's 4 hours.

This differs from the detached-scan CLI (`triton scan --detach`) which explicitly supports "close SSH and come back later." Fleet-scan keeps the connection open because:
- The orchestrator needs to poll `--status` every 10 seconds, which requires SSH
- Keeping the connection open avoids repeated auth overhead (20 scans × re-auth = minutes of wasted time)
- SSH keep-alive + TCP keep-alive make idle-disconnect rare on reasonable networks

**When would you want close-and-reconnect?** If you're doing a 72-hour scan (e.g. comprehensive across 100TB of data) and worry about SSH keep-alive failures. In that case, run `triton scan --detach` manually via fleet-scan's `--dry-run` output or via a one-off SSH session, then use fleet-scan's future `--resume --job-id` mode (not yet implemented). For v1, keep-alive tuning on the SSH config handles this:

```
# /etc/ssh/ssh_config on the operator host
Host *
    ServerAliveInterval 60
    ServerAliveCountMax 60     # = 1 hour before disconnect on silent line
    TCPKeepAlive yes
```

### 4.2 Detach daemon survives SSH disconnect

Even though fleet-scan keeps the SSH connection open, the triton scan daemon on the target is resilient to SSH disconnects:

```
Parent (operator):                       Child (target):
triton fleet-scan                        sshd forks a shell
  │                                        │
  ├─ open SSH connection                   │
  │                                        │
  ├─ ssh exec "triton scan --detach"   →  │
  │                                        ├─ triton scan (parent)
  │                                        │    ├─ fork-exec daemon with
  │                                        │    │   TRITON_DETACHED=1
  │                                        │    ├─ SysProcAttr{Setsid: true}
  │                                        │    └─ exit 0 (parent dies)
  │ ← prints job-id                        │
  │                                        ▼
  │                                    triton daemon
  │                                      ├─ reparented to PID 1 (init)
  │                                      ├─ own session (setsid)
  │                                      ├─ writes status.json
  ├─ poll --status every 10s              │
  │                                        │
  ├─ eventually SSH drops? ←── no ──       │
  │                                        │
  │  If SSH DOES drop (e.g. operator        │
  │  laptop closes): the daemon            │
  │  ignores SIGHUP because setsid         │
  │  already detached the session.         │
  │  Scan continues.                       │
  │                                        │
  │  Operator can re-run fleet-scan        │
  │  targeting the same inventory; the     │
  │  running job gets skipped because       │
  │  --detach refuses duplicate job-id.    │
  │  OR: operator SSH'es to host manually  │
  │  and runs `triton scan --status`.      │
```

So the daemon ALWAYS survives SSH disconnect. What's lost on disconnect is fleet-scan's ability to poll and collect. The scan completes; the output stays in the work-dir on the target until the operator retrieves it.

### 4.3 Cancellation

Two ways to cancel a running fleet-scan:

**Ctrl+C on the operator host** (SIGINT / SIGTERM):
1. Parent process catches signal via `signal.NotifyContext`
2. Outer context cancels
3. All workers observe ctx.Done and exit their current Run call
4. Deferred `rm -f <binary>` runs for each in-flight host using `context.Background()` + 10s timeout (so cleanup survives the cancelled parent ctx)
5. **BUT**: the remote daemon is NOT told to cancel. It keeps running to completion on each target.

To cleanly abort all remote scans after Ctrl+C:

```bash
# After Ctrl+C, iterate the inventory + run --cancel on each
while read host; do
    ssh "$host" 'triton scan --cancel --job-id "$(triton scan --list-jobs --work-dir ~/.triton/jobs/ | head -1 | awk "{print \$1}")"'
done < hosts.txt
```

This is clunky. A future PR will add a `triton fleet-scan --cancel` mode that fans out cancellations. For v1: Ctrl+C closes the operator's connection but leaves remote daemons running.

**`--max-failures N` circuit break**: after N hosts fail, outer ctx cancels, in-flight workers finish their current phase and return. Same remote-daemon caveat as above.

---

## 5. Manage-portal integration

Fleet-scan is a CLI command. Portal integration is the portal's job — fleet-scan provides the primitives.

### 5.1 Invocation patterns

**(a) Portal shells out to fleet-scan directly**

```bash
# Portal backend (any language) invokes triton as a subprocess
triton fleet-scan \
    --inventory /var/lib/portal/tenants/acme/devices.yaml \
    --credentials /var/lib/portal/tenants/acme/credentials.yaml \
    --report-server https://portal.internal/api/v1/scans \
    --output-dir /var/lib/portal/scan-outputs/acme/ \
    --license-key "$(cat /etc/portal/tenant-acme.license)" \
    --profile standard \
    --concurrency 20 \
    --max-memory 2GB --max-duration 4h \
    --interval 0
```

Captured stdout gets parsed for per-host lines (one line per host with job-id or failure phase). Exit code tells success/partial/fatal:
- `0`: all hosts succeeded
- `2`: some hosts failed — check summary.json
- `3`: `--max-failures` breached
- `1`: runtime error (bad inventory, credentials decryption failure, etc.)

The portal's scheduler library (e.g. BullMQ for Node, Sidekiq for Ruby, celery for Python) wraps this in a job queue. Each fleet-scan invocation is one job; retries / backoff / dead-letter handling is up to the portal.

**(b) Portal reads summary.json + tars**

After fleet-scan exits, the portal reads:

```
/var/lib/portal/scan-outputs/acme/
  2026-04-18T14-30-00/
    summary.json        ← portal parses this for dashboard
    summary.txt
    hosts/
      web-1.tar.gz      ← portal extracts individual reports
      web-2.tar.gz
      ...
  latest → 2026-04-18T14-30-00
```

`summary.json` schema (stable contract, treat as versioned):

```json
{
  "invoked_at": "2026-04-18T14:30:00Z",
  "completed_at": "2026-04-18T14:52:13Z",
  "duration": "22m13s",
  "inventory": "/var/lib/portal/tenants/acme/devices.yaml",
  "flags": {"profile": "standard", "concurrency": 20, "max_memory": "2GB"},
  "counts": {"total": 50, "succeeded": 48, "failed": 2},
  "hosts": [
    {
      "device": "web-1",
      "state": "done",
      "duration": "2m14s",
      "findings_count": 137,
      "job_id": "7a3f9e2c-...",
      "output_path": "hosts/web-1.tar.gz"
    },
    {
      "device": "srv-03",
      "state": "failed",
      "duration": "8s",
      "error": "ssh connect: handshake failed",
      "phase": "ssh connect"
    }
  ]
}
```

**(c) Portal uses `--report-server` for centralized storage**

When `--report-server` is set, each successful host's `result.json` (the canonical ScanResult JSON) is POSTed to `<server>/api/v1/scans` — same endpoint the standalone `triton agent` uses. The report server deduplicates by host+timestamp and writes to its own PostgreSQL store.

In this mode, the portal doesn't parse per-host tarballs directly — it queries the server via its existing analytics endpoints (`/api/v1/inventory`, `/api/v1/priority`, etc.). `--output-dir` is still required alongside `--report-server` in v1 because fleet-scan reads `result.json` out of the collected tarball to upload; pure streaming upload (without local tarball) is a deferred feature.

### 5.2 Running multiple fleet-scans

Common patterns:

**Parallel tenants, one worker per tenant**:

```yaml
# portal.yaml
tenants:
  - id: acme
    inventory: /var/lib/portal/tenants/acme/devices.yaml
    credentials: /var/lib/portal/tenants/acme/credentials.yaml
    schedule: "0 2 * * *"    # 2am daily
  - id: globex
    inventory: /var/lib/portal/tenants/globex/devices.yaml
    credentials: /var/lib/portal/tenants/globex/credentials.yaml
    schedule: "0 3 * * *"    # 3am daily
```

The portal's scheduler runs one `triton fleet-scan` per tenant. They don't interfere — different inventories, different credentials, different `--output-dir` subdirs, different license tokens.

**Staggered sub-fleet scans**:

```bash
# 2am: production web tier
triton fleet-scan --inventory devices.yaml --group prod-web \
                  --output-dir ./scans/web --interval 24h &

# 2:05am: production db tier (staggered to avoid network saturation)
sleep 300 && triton fleet-scan --inventory devices.yaml --group prod-db \
                                --output-dir ./scans/db --interval 24h &

# 2:10am: bastion hosts
sleep 600 && triton fleet-scan --inventory devices.yaml --group bastion \
                                --output-dir ./scans/bastion --interval 24h &
```

Same inventory, different `--group` filter, different output directories. Running in parallel with `&` is safe because the groups don't share hosts.

**Continuous mode**:

```bash
# Single long-running fleet-scan that repeats every 24h with ±10% jitter
triton fleet-scan --inventory devices.yaml --credentials creds.yaml \
                  --report-server https://portal.internal \
                  --interval 24h
```

The process sleeps between iterations and re-runs the full flow. SIGTERM cleanly exits after the current iteration. Suitable for running as a systemd service on a dedicated orchestration host:

```ini
# /etc/systemd/system/triton-fleet-scan.service
[Unit]
Description=Triton Fleet Scanner
After=network-online.target

[Service]
Type=simple
User=triton-orch
Environment="TRITON_SCANNER_CRED_KEY=/etc/triton/cred.key"
Environment="TRITON_LICENSE_KEY=/etc/triton/license.key"
ExecStart=/usr/local/bin/triton fleet-scan \
    --inventory /etc/triton/devices.yaml \
    --credentials /etc/triton/credentials.yaml \
    --report-server https://portal.internal \
    --output-dir /var/lib/triton/scans \
    --concurrency 50 --profile standard \
    --max-memory 2GB --max-duration 4h \
    --interval 24h

Restart=on-failure
RestartSec=300s
# Resource limits for the orchestrator itself
MemoryMax=2G
CPUQuota=50%

[Install]
WantedBy=multi-user.target
```

### 5.3 Portal authentication + multi-tenancy

Fleet-scan itself is single-tenant — one invocation = one license + one inventory. Multi-tenancy lives in the portal:

1. Portal holds a **license pool** — one Pro/Enterprise license per tenant
2. Portal writes tenant-specific `devices.yaml` + encrypted `credentials.yaml` to per-tenant volumes (e.g. `/var/lib/portal/tenants/<id>/`)
3. Portal injects `TRITON_LICENSE_KEY` + `TRITON_SCANNER_CRED_KEY` via env when spawning fleet-scan
4. `--report-server` POSTs include a tenant-id header (added by portal if going through its proxy)

Fleet-scan doesn't know or care about tenants. It does know about licenses (via the guard gate on `FeatureFleetScan`) and credentials (via the encrypted YAML).

### 5.4 Scheduling and retries

Fleet-scan has `--interval` for continuous mode and `--max-failures` for circuit-breaking. It does NOT have built-in retry or dead-letter handling. The portal provides those.

Retry policy recommendations:
- **Transient failures** (ssh connect timeout, network flake): retry with backoff 3 times, then give up
- **Configuration failures** (sudo check, arch mismatch, license): don't retry — alert the operator
- **Terminal scan failures** (daemon crash): retry once with reduced scope (e.g. profile=quick)

The portal inspects `summary.json` → `hosts[].phase` to classify failures. Retries happen by re-running fleet-scan with `--device <name>` to target just the failing host.

---

## 6. Complete CLI options reference

Every flag on `triton fleet-scan`, grouped by concern. Defaults in **bold**.

### 6.1 Inventory + credentials

| Flag | Default | Purpose |
|---|---|---|
| `--inventory <path>` | `/etc/triton/devices.yaml` | Path to devices.yaml |
| `--credentials <path>` | `/etc/triton/credentials.yaml` | Path to encrypted credentials.yaml. Decryption key from `TRITON_SCANNER_CRED_KEY` env (hex, 64 chars) |
| `--group <name>` | `""` (all) | Scan only devices belonging to this inventory group |
| `--device <name>` | `""` (all) | Scan only this one device. Useful for targeted retries or debugging |

### 6.2 Orchestration

| Flag | Default | Purpose |
|---|---|---|
| `--concurrency N` | **20** | Max concurrent host scans. Capped effectively by file descriptor limits and target SSH `MaxSessions`. For 100+ hosts consider 50 |
| `--device-timeout D` | **30m** | Per-host deadline. Worker aborts its current Run call at this duration. Remote daemon keeps running |
| `--dry-run` | **false** | Validate inventory + credentials + SSH reachability + sudo check only. Skip phases 6-11 |
| `--interval D` | **0** (disabled) | Continuous mode: repeat the full scan every D with ±10% jitter. Exit on SIGTERM |
| `--max-failures N` | **0** (unlimited) | Circuit-breaker. If N hosts fail, cancel the outer context and exit code 3 |

### 6.3 SSH + host keys

| Flag | Default | Purpose |
|---|---|---|
| `--known-hosts <path>` | `""` | Path to SSH known_hosts for host-key verification. Required unless `--insecure-host-key` |
| `--insecure-host-key` | **false** | Accept any host key (lab / test only). Mutually exclusive with `--known-hosts` |

### 6.4 Binary source

| Flag | Default | Purpose |
|---|---|---|
| `--binary <path>` | `os.Args[0]` (self) | Binary to push to targets. Override for cross-arch fleets |

Per-device override: set `binary: /path/to/triton-<goos>-<goarch>` in `devices.yaml`. Device-level wins over `--binary`.

### 6.5 Output

| Flag | Default | Purpose |
|---|---|---|
| `--output-dir <path>` | `""` | Write per-host tar.gz + summary locally. Creates `<output-dir>/<timestamp>/summary.{json,txt}` + `hosts/<name>.tar.gz` |
| `--report-server <url>` | `""` | POST each host's `result.json` to `<url>/api/v1/scans` using `pkg/agent.Client`. Requires `--output-dir` in v1 (upload from local tar) |

At least one of `--output-dir`, `--report-server`, or `--dry-run` is required (Cobra enforces via `MarkFlagsOneRequired`).

### 6.6 Forwarded scan parameters

These are passed verbatim to each remote `triton scan --detach`:

| Flag | Default | Purpose |
|---|---|---|
| `--profile <name>` | `standard` | `quick` / `standard` / `comprehensive` — controls which scanners run on each target |
| `--format <name>` | `all` | `json` / `cdx` / `html` / `sarif` / `xlsx` / `all` — which reports the daemon generates |
| `--policy <name>` | `""` | NACSA / CNSA / custom policy YAML name. Gates on license tier |

### 6.7 Resource limits (forwarded to remote daemon)

These apply per target host, not across the fleet. Implemented in `internal/runtime/limits/` (PR #71):

| Flag | Default | Purpose |
|---|---|---|
| `--max-memory <size>` | `""` | Soft memory cap on the remote scan. E.g. `2GB`. Watchdog self-kills at 1.5x |
| `--max-cpu-percent <n>` | `""` | Cap GOMAXPROCS to this % of remote host's CPU count. E.g. `50`. Caps parallelism, not CPU time |
| `--max-duration <D>` | **0** (disabled) | Wall-clock budget for the remote scan. `--max-duration 4h` returns partial results at 4h |
| `--stop-at <HH:MM>` | `""` | Stop the remote scan at this local clock time. `--stop-at 03:00` = stop at 3am. Rolls to tomorrow if past |
| `--nice <n>` | **0** | `setpriority` adjustment on the remote (unix). Positive = nicer. No-op on Windows |

**Important nuance**: these cap *each individual remote scan*. If you set `--max-memory 2GB --concurrency 20`, that's up to 2GB per host × 20 hosts = 40GB total network-wide scan budget. The orchestrator itself has no built-in memory cap; use `systemd MemoryMax=` or a wrapper.

### 6.8 Licensing

| Flag | Default | Purpose |
|---|---|---|
| `--license-key <token>` | `""` | Literal Ed25519 license token. Overrides `TRITON_LICENSE_KEY` env. Empty = free tier (which fails the FeatureFleetScan gate) |
| `--license-file <path>` | `""` | Path to a file containing the license token |
| `--license-server <url>` | `""` | License server for online validation (v3.0) |
| `--license-id <id>` | `""` | License ID for server activation |

Fleet-scan requires **Pro or Enterprise** tier (`FeatureFleetScan` gate). Free tier exits 1 with a license error before any SSH work.

### 6.9 Standard persistent flags (inherited from root)

These are available on every triton command, including fleet-scan:

| Flag | Default | Purpose |
|---|---|---|
| `--config <path>` | `~/.triton.yaml` | Config file (viper-loaded) |
| `--db <url>` | `""` | PostgreSQL URL — not used by fleet-scan orchestrator itself, but forwarded if the remote scan uses it |

---

## 7. Common operations playbook

### 7.1 One-off scan against a single host

```bash
triton fleet-scan \
    --inventory my-hosts.yaml \
    --credentials my-creds.yaml \
    --device web-1 \
    --output-dir ./scans/ \
    --profile standard
```

### 7.2 Scheduled nightly scan

```bash
# crontab
0 2 * * * /usr/local/bin/triton fleet-scan \
    --inventory /etc/triton/devices.yaml \
    --credentials /etc/triton/credentials.yaml \
    --report-server https://portal.internal \
    --output-dir /var/lib/triton/scans \
    --profile standard \
    --max-memory 2GB --max-duration 6h \
    --concurrency 50 --max-failures 5 \
    >> /var/log/triton-nightly.log 2>&1
```

### 7.3 Debug a single failing host

```bash
# Get verbose output for one host
triton fleet-scan \
    --inventory my-hosts.yaml \
    --credentials my-creds.yaml \
    --device problem-host \
    --output-dir ./scans/ \
    --profile quick \
    --device-timeout 5m \
    2>&1 | tee debug.log

# Inspect the collected tarball
tar -tvf ./scans/latest/hosts/problem-host.tar.gz
```

### 7.4 Dry-run before a big scan

```bash
# Verify inventory, credentials, SSH reachability, sudo config —
# without actually scanning.
triton fleet-scan \
    --inventory prod.yaml \
    --credentials prod-creds.yaml \
    --output-dir /tmp/dryrun/ \
    --dry-run
# Read /tmp/dryrun/<ts>/summary.txt for per-host OK/FAIL
```

### 7.5 Cancel a running fleet-scan

```bash
# On the operator host: Ctrl+C
# Remote daemons keep running. To stop them, iterate:

# Parse out running job-ids from the last summary
jq -r '.hosts[] | select(.state == "running" or .state == "done" | not) | .device' \
    scans/latest/summary.json \
    | while read device; do
        # Requires per-host SSH — or use fleet-scan's future --cancel mode
        echo "Would cancel scan on $device"
    done
```

A `triton fleet-scan --cancel` mode is planned for a future PR.

---

## 8. Troubleshooting

**"sudo check: NOPASSWD sudo required"**
Target host's sudoers doesn't allow passwordless sudo for the SSH user. See §3.2. Alternative: set `sudo: false` in `devices.yaml` for that host.

**"arch mismatch: local=darwin/arm64 remote=linux/amd64"**
You're running fleet-scan from a Mac but targeting Linux. Set `--binary /path/to/triton-linux-amd64` or configure per-device `binary:` in `devices.yaml`.

**"ssh connect: handshake failed: unable to authenticate"**
SSH key doesn't match or the SSH user is wrong. Verify `ssh -i /path/to/key user@host` works manually before running fleet-scan.

**"ssh connect: handshake failed: ssh: handshake failed: ssh: host key mismatch"**
Update your `~/.ssh/known_hosts` or the `--known-hosts` file. DO NOT use `--insecure-host-key` in production.

**"launch: feature 'profile:comprehensive' requires higher tier"**
Remote triton binary has a license but it's free-tier. The comprehensive profile requires Pro+. Either embed a Pro license in the pushed binary (via ldflags at build time) or use `--profile standard`.

**Fleet-scan hangs at "poll" phase**
Remote daemon is running but your `--device-timeout` is shorter than the scan itself. Increase `--device-timeout` or reduce the profile.

**Non-fatal "report-server upload failed" warnings**
Network issue to the report server, or the server is down. Local tarball is still on disk in `--output-dir`. Re-upload later manually:

```bash
# Extract result.json from the tarball and POST to server
tar -xOf scans/latest/hosts/web-1.tar.gz 'reports/triton-report-*.json' \
    | curl -X POST https://portal.internal/api/v1/scans \
           -H 'Content-Type: application/json' \
           --data-binary @-
```

---

## 9. Known limitations (v1)

- **`--report-server` requires `--output-dir`.** Fleet-scan extracts `result.json` from the local tarball to upload. Pure streaming upload (no local tarball) is a deferred feature.
- **No arch-match validation in `ResolveBinary`.** The orchestrator trusts the operator to supply a compatible binary. A darwin/arm64 binary pushed to linux/amd64 fails at launch with a cryptic exec format error.
- **SSH `Upload` ignores context.** Large uploads can't be interrupted by Ctrl+C; they block until the TCP connection times out.
- **No `--cancel` mode for fleet-scan.** Ctrl+C closes operator connections but leaves remote daemons running. Explicit per-host cancel requires SSH-in-a-loop or waiting for remote `--max-duration` to fire.
- **Integration tests are Docker-based.** On CI runners without Docker (rare in practice), the four end-to-end tests skip. One test (`TestFleetScan_MaxFailures`) uses TCP-unreachable addresses and runs without Docker.

All of these are tracked as follow-ups in PR #74's description.
