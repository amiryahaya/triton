# Fleet Scan (SSH Fan-out) — Design Spec

**Date:** 2026-04-18
**Status:** Approved
**Parent roadmap:** `memory/agent-control-features.md` — step 3 of 4
**Builds on:** PR #71 (resource limits), PR #72 (detached scan lifecycle)
**Next step:** Agent supervisor integration (step 4)

## Goal

Add `triton fleet-scan` — an orchestrator that fans out `triton scan` across a host inventory via SSH. For each unix host: push binary, run `triton scan --detach`, poll until terminal, collect reports, clean up. Reuses existing inventory/credentials/transport infrastructure from `pkg/scanner/netscan/` plus the `--detach`/`--status`/`--collect` surface from PR #72. Also renames `network-scan` → `device-scan` for consistency.

## Non-goals

- Agent supervisor resource-limits integration (step 4; separate PR)
- Windows/macOS-specific target handling (unix only for v1)
- Portal UI for fleet-scan summary (portal-unification work)
- Tier enforcement on inventory size caps (gate is present; limits deferred)
- Parallel scp fan-out via tar+pipe (current: serial scp-per-host via SSH pool)

## Architecture

Four layers, all reusing existing primitives; zero new RPC protocols.

```
CLI layer (cmd/fleet_scan.go + rename cmd/network_scan.go → cmd/device_scan.go)
  triton fleet-scan --inventory devices.yaml --credentials creds.yaml
    [--profile standard] [--max-memory 2GB] [--concurrency 20]
    [--output-dir ./scans/]
        │
        ▼
Fleet orchestrator (pkg/scanner/netscan/fleet/)  — NEW
  • PreFlight(device, creds) — SSH dial, uname arch check, sudo check,
    binary arch resolution
  • PushBinary(device, path) — scp the local binary (or per-device override)
  • RunDetachedScan(device, creds, scanFlags) → jobID
    [remote: triton scan --detach --quiet …]
  • PollStatus(device, jobID) → Status
    [remote: triton scan --status --job-id X --json]
  • CollectReports(device, jobID) → tar.gz bytes
    [remote: triton scan --collect --job-id X -o -]
  • Cleanup(device, jobID) — remove binary + --cleanup daemon work-dir
  • Worker pool: --concurrency N goroutines draining a device queue;
    result channel carries per-host success/failure
        │
        ▼
SSH transport (pkg/scanner/netadapter/transport/ — existing ssh.go)
  Reuses crypto/ssh; known-hosts verification already in place
        │
        ▼
Remote host (runs triton scan --detach from PR #72)
  Orchestrator treats the remote as a black box that speaks the triton
  CLI. Zero triton-host-specific wire protocol — just SSH + exec +
  stdout parsing. Reads the same status.json schema PR #72 introduced.
```

### Rename plan (same PR)

- `cmd/network_scan.go` → `cmd/device_scan.go` with `Use: "device-scan"`.
- Keep `network-scan` as alias: prints `DEPRECATED: use 'triton device-scan' instead` to stderr, delegates to `runDeviceScan`.
- All `ns*` var names → `ds*` (e.g. `nsInventory` → `dsInventory`).
- `FeatureNetworkScan` → `FeatureDeviceScan` with alias for backcompat one release cycle.
- Integration test confirms the alias still works.

## CLI surface

```
triton fleet-scan --inventory /etc/triton/devices.yaml
                  --credentials /etc/triton/credentials.yaml
                  [fleet orchestration flags]
                  [output flags — at least one required]
                  [forwarded scan flags]
```

**Fleet orchestration flags** (match `device-scan` conventions):

| Flag | Default | Notes |
|---|---|---|
| `--group <name>` | "" | Scan only devices in this group |
| `--device <name>` | "" | Scan only this one device (debugging) |
| `--concurrency N` | 20 | Max concurrent host scans |
| `--device-timeout D` | 30m | Per-host deadline (longer than network-scan's 5m since full scan) |
| `--dry-run` | false | Validate + SSH pre-flight only; no scan |
| `--interval D` | 0 | Continuous mode; 0 disables |
| `--max-failures N` | 0 | Circuit-breaker; 0 disables (unlimited) |
| `--known-hosts <path>` | "" | Required unless `--insecure-host-key` |
| `--insecure-host-key` | false | Accept any host key (lab only) |
| `--binary <path>` | `os.Args[0]` | Override binary source globally |

**Output flags** (at least one required — enforced via Cobra `MarkFlagsOneRequired`):

| Flag | Purpose |
|---|---|
| `--output-dir <path>` | Write per-host tar.gz + summary locally |
| `--report-server <url>` | POST each result.json to central server |

**Forwarded scan flags** (passed through to each remote `triton scan --detach …`):

- `--profile`, `--format`, `--policy` (same as foreground scan)
- `--max-memory`, `--max-cpu-percent`, `--max-duration`, `--stop-at`, `--nice` (PR #71)

Flag parsing rule: `fleet-scan` explicitly registers the forwarded flags. Anything unrecognized is an error (no wildcard passthrough).

### Example flows

```bash
# Quick fleet-wide scan, local reports only
triton fleet-scan --inventory devices.yaml --credentials creds.yaml \
                  --output-dir ./scans/ --profile quick --max-duration 10m

# Production: upload to server, cap failures at 5
triton fleet-scan --inventory devices.yaml --credentials creds.yaml \
                  --report-server https://triton.corp.internal \
                  --concurrency 50 --max-failures 5 \
                  --profile standard --max-memory 2GB

# Dry-run pre-flight
triton fleet-scan --inventory devices.yaml --credentials creds.yaml --dry-run

# Continuous mode (daily)
triton fleet-scan --inventory devices.yaml --credentials creds.yaml \
                  --report-server https://triton.corp.internal \
                  --interval 24h --profile standard
```

## Inventory schema

**Existing** (`pkg/scanner/netscan/inventory.go::Device`) — unchanged:
- Name, Type, Address, Port, Credential, EnableCredential, ScanPaths, Sudo, OSHint

**New optional fields** (backward-compatible):

```go
type Device struct {
    // ... existing fields ...

    Binary     string `yaml:"binary,omitempty"`      // per-device --binary override
    WorkDir    string `yaml:"work_dir,omitempty"`    // remote temp dir; default /tmp
    SkipFleet  bool   `yaml:"skip_fleet,omitempty"`  // fleet-scan skips this device
    SkipDevice bool   `yaml:"skip_device,omitempty"` // device-scan skips this device
}
```

### Device filtering per command

| Command | Devices included |
|---|---|
| `device-scan` | Any `type ∈ {unix, cisco-iosxe, juniper-junos}` where `!SkipDevice` |
| `fleet-scan` | Any `type == unix` where `!SkipFleet` (other types silently skipped — no general-purpose OS to run triton on) |

Both commands respect `--group` / `--device` filters on top.

### Example inventory

```yaml
version: 1
defaults:
  port: 22
  scan_timeout: 5m
  sudo: true

devices:
  # Standard unix host — fleet-scan and device-scan both target
  - name: web-srv1
    type: unix
    address: 10.0.1.10
    credential: prod-ssh-key
    scan_paths: [/etc, /opt]

  # Special host — needs a different binary
  - name: aix-legacy-1
    type: unix
    address: 10.0.1.20
    credential: legacy-ssh
    binary: /opt/triton-binaries/triton-aix-ppc64

  # Unix host that fleet-scan should skip
  - name: pci-vault-1
    type: unix
    address: 10.0.9.1
    credential: vault-ssh
    skip_fleet: true

  # Network device — device-scan only
  - name: edge-router-1
    type: cisco-iosxe
    address: 10.0.0.1
    credential: cisco-tacacs
```

### Credentials

No schema changes. Existing SSH key + passphrase credentials work. Per the sudo model, fleet-scan requires NOPASSWD on targets, so no `sudo_password` field is introduced.

### Validation additions

- `type: unix` devices with no `credential` set → error (already enforced in device-scan path)
- `binary:` if set must be an absolute path (existence verified at fleet-scan pre-flight, not inventory load, so inventory stays portable)

## Per-host execution flow

```go
func scanHost(ctx context.Context, d *Device, creds *Credentials, cfg FleetConfig) HostResult {
    res := HostResult{Device: d.Name, StartedAt: time.Now()}
    defer func() { res.Duration = time.Since(res.StartedAt) }()

    ctx, cancel := context.WithTimeout(ctx, cfg.DeviceTimeout)
    defer cancel()

    // 1. SSH pre-flight
    conn, err := cfg.Transport.Dial(ctx, d, creds)
    if err != nil { return res.fail("ssh connect", err) }
    defer conn.Close()

    // 2. Arch-match
    arch, err := conn.Run(ctx, "uname -s -m")
    if err != nil { return res.fail("uname", err) }
    binary, err := cfg.resolveBinary(d, arch)
    if err != nil { return res.fail("arch mismatch", err) }

    // 3. Sudo pre-flight (only if d.Sudo)
    if d.Sudo {
        if _, err := conn.Run(ctx, "sudo -n true"); err != nil {
            return res.fail("sudo check",
                fmt.Errorf("NOPASSWD sudo required; %w", err))
        }
    }

    // 4. Push binary
    remotePath := filepath.Join(d.WorkDir, ".triton-"+uuid.NewString()[:8])
    if err := conn.Upload(ctx, binary, remotePath, 0o755); err != nil {
        return res.fail("scp binary", err)
    }
    defer func() { _, _ = conn.Run(context.Background(), "rm -f "+remotePath) }()

    // 5. Launch detached scan
    launchCmd := buildLaunchCommand(remotePath, d.Sudo, cfg.ScanFlags)
    out, err := conn.Run(ctx, launchCmd)
    if err != nil { return res.fail("launch", err) }
    jobID := parseJobID(out)
    if !isValidUUID(jobID) { return res.fail("launch", fmt.Errorf("no job-id in output: %q", out)) }

    // 6. Poll until terminal
    statusCmd := fmt.Sprintf("%s scan --status --job-id %s --json", remotePath, jobID)
    status, err := pollUntilTerminal(ctx, conn, statusCmd, 10*time.Second)
    if err != nil { return res.fail("poll", err) }

    // 7. Collect reports (streamed tar.gz over stdout)
    if err := collectTar(ctx, conn, remotePath, jobID, cfg.OutputDir, d.Name); err != nil {
        return res.fail("collect", err)
    }

    // 8. Upload to --report-server if set (non-fatal)
    if cfg.ReportServerURL != "" {
        if err := uploadToReportServer(ctx, cfg, d.Name, /* result.json */); err != nil {
            res.Warning = "report-server upload failed: " + err.Error()
        }
    }

    // 9. Remote cleanup
    _, _ = conn.Run(ctx, fmt.Sprintf("%s scan --cleanup --job-id %s", remotePath, jobID))

    res.Status = status
    res.ok()
    return res
}
```

### Failure phases

| Phase | Typical cause | Operator sees |
|---|---|---|
| `ssh connect` | Network / auth / host-key | `srv-03: ssh connect: unable to authenticate` |
| `uname` | Command not found on target | `srv-04: uname: exit 127` |
| `arch mismatch` | Heterogeneous fleet w/o --binary | `srv-04: arch mismatch: local=darwin/arm64 remote=linux/amd64 — set --binary or device.binary` |
| `sudo check` | NOPASSWD not configured | `srv-05: sudo check: NOPASSWD sudo required` |
| `scp binary` | Disk full / permissions | `srv-06: scp binary: No space left on device` |
| `launch` | License tier gate on remote | `srv-07: launch: feature "profile:comprehensive" requires higher tier` |
| `poll` | Device-timeout hit | `srv-08: poll: device-timeout 30m exceeded` |
| `collect` | Daemon crashed | `srv-09: collect: remote status=failed, error="daemon vanished"` |

### HostResult

```go
type HostResult struct {
    Device     string
    StartedAt  time.Time
    Duration   time.Duration
    Status     *jobrunner.Status  // nil if failed before launch
    JobID      string
    OutputPath string              // local tar.gz path if --output-dir
    Err        error
    Phase      string              // failure phase name
    Warning    string              // non-fatal issue
}
```

### Concurrency + cancellation

- `--concurrency N` workers drain a buffered device channel
- Outer `ctx` tied to SIGINT/SIGTERM; Ctrl+C cancels all in-flight hosts
- Per-host `context.WithTimeout` gives each worker its own budget
- `--max-failures N` checked atomically after each `HostResult`; breach cancels outer ctx

### Continuous mode

`--interval 24h` wraps the full fleet-scan in an outer loop with ±10% jitter. Exit on SIGTERM or max-failures breach. Matches the network-scan `--interval` pattern.

## Output and aggregation

### `--output-dir` layout

```
scans/
  2026-04-18T14-30-00/                    # timestamped subdir per invocation
    summary.json                          # machine-readable
    summary.txt                           # human-readable
    hosts/
      web-srv1.tar.gz                     # reports/ dir from remote
      web-srv1.log                        # scan.log (if collect succeeded)
      web-srv1.status.json                # terminal status copy
      srv-03.error.txt                    # failed hosts: error message + phase
  latest → 2026-04-18T14-30-00            # symlink, refreshed each run
```

### `summary.json`

```json
{
  "invoked_at": "2026-04-18T14:30:00Z",
  "completed_at": "2026-04-18T14:52:13Z",
  "duration": "22m13s",
  "inventory": "/etc/triton/devices.yaml",
  "flags": { "profile": "standard", "max_memory": "2GB", "concurrency": 20 },
  "counts": { "total": 50, "succeeded": 48, "failed": 2 },
  "hosts": [
    {
      "device": "web-srv1",
      "state": "done",
      "duration": "2m14s",
      "findings_count": 137,
      "job_id": "7a3f9e2c-...",
      "output_path": "hosts/web-srv1.tar.gz",
      "warning": ""
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

### `summary.txt` (stdout + file)

```
FLEET SCAN SUMMARY — completed 2026-04-18 14:52:13 UTC (22m13s)
Inventory:   /etc/triton/devices.yaml
Flags:       --profile standard --max-memory 2GB --concurrency 20

Total hosts:      50
 ├─ Succeeded:    48
 └─ Failed:        2  (srv-03, srv-19)

Total findings:   3,812
Avg duration:     2m14s per host
Output dir:       ./scans/2026-04-18T14-30-00/

Failed hosts:
  srv-03   ssh connect: handshake failed: unable to authenticate
  srv-19   launch: feature "profile:comprehensive" requires higher tier
```

A "succeeded" host ran `triton scan` to a terminal `done` state — findings may be reduced if `sudo: false` restricts which paths triton can read, but that's a data-coverage concern, not a scan-completion concern. Hosts that emitted warnings during collection (e.g., report-server upload failed) are listed with a warning marker in the per-host line but still count as succeeded.

### Exit codes

- `0` — all hosts succeeded
- `1` — fleet-scan runtime error (inventory load, credentials decrypt, transport init, etc.)
- `2` — some hosts failed (≥1 failed but ≥1 succeeded); `--fail-on-any` elevates to 1
- `3` — max-failures threshold exceeded

### `--report-server` upload

Each successful host's `result.json` POST'd to `<server>/api/v1/scans` — same endpoint as `triton agent`. Auth: same license-server flow. Upload failure non-fatal (logged as warning per-host); local tar remains.

### License feature gate

- New `FeatureFleetScan` in `internal/license/features.go`
- Separate from `FeatureNetworkScan` because binary distribution + sudo is higher-trust than read-only protocol probes
- Enforced in `PreRunE` (matches network-scan's pattern)
- Tier mapping (tunable later):
  - Free: disabled
  - Pro: up to 10 hosts per inventory
  - Enterprise: unlimited

## Error handling matrix

| Situation | Behavior |
|---|---|
| `--output-dir` + `--report-server` both unset + not `--dry-run` | Cobra error before any SSH |
| Inventory parse fails | Exit 1 with YAML error or field validation error |
| Credentials decrypt fails | Exit 1, clear error (existing netscan behavior) |
| `--device` not in inventory | Exit 1 before SSH |
| All hosts in `--group` have `skip_fleet: true` | Warn + exit 0 |
| SSH dial timeout | Per-host failure, phase=`ssh connect` |
| Host key mismatch | Per-host failure; error points to `--known-hosts` |
| Arch mismatch | Per-host failure with concrete fix instruction |
| Sudo required, NOPASSWD missing | Per-host failure, phase=`sudo check` |
| Binary upload fails | Per-host failure, phase=`scp binary` |
| Remote `triton scan --detach` fails | Per-host failure, phase=`launch`, captures remote stderr |
| Remote daemon crashes mid-scan | Per-host failure; PR #72's stale detection catches it |
| `--device-timeout` elapsed | Per-host failure, phase=`poll`; remote job may still be running |
| Collect streams partial tar.gz | Per-host failure, phase=`collect`; partial file deleted |
| `--report-server` upload fails | Non-fatal warning; local tar untouched |
| `--max-failures N` exceeded | Outer ctx cancelled; in-flight hosts drain; exit 3 |
| SIGINT during scan | Outer ctx cancelled; workers finish or abort SSH commands; remote daemons keep running (can reconnect via triton scan --status). Summary still written. |

## File structure

### Create (new)

- `cmd/fleet_scan.go` — Cobra command, flag registration, orchestrator invocation
- `cmd/fleet_scan_test.go` — flag assembly, arch-match, output-dir tests
- `pkg/scanner/netscan/fleet/fleet.go` — `Orchestrator`, `FleetConfig`, `scanHost`, worker pool
- `pkg/scanner/netscan/fleet/fleet_test.go`
- `pkg/scanner/netscan/fleet/preflight.go` — SSH dial + uname + sudo check + binary arch resolution
- `pkg/scanner/netscan/fleet/preflight_test.go`
- `pkg/scanner/netscan/fleet/launch.go` — builds `triton scan --detach …` command; parses job-id
- `pkg/scanner/netscan/fleet/launch_test.go`
- `pkg/scanner/netscan/fleet/collect.go` — status polling, tar streaming, cleanup
- `pkg/scanner/netscan/fleet/collect_test.go`
- `pkg/scanner/netscan/fleet/summary.go` — HostResult aggregation → summary.json + summary.txt
- `pkg/scanner/netscan/fleet/summary_test.go`
- `pkg/scanner/netscan/fleet/doc.go`
- `cmd/network_scan_alias.go` — deprecation alias for `network-scan`
- `test/integration/Dockerfile.sshd`
- `test/integration/testdata/test_ed25519` (+ `.pub`) — fixture SSH key
- `test/integration/fleet_scan_test.go`

### Modify

- `cmd/network_scan.go` → renamed to `cmd/device_scan.go` (content: `ns*` → `ds*`, `Use: "device-scan"`)
- `pkg/scanner/netscan/inventory.go` — add `Binary`, `WorkDir`, `SkipFleet`, `SkipDevice` fields + `ValidateForFleetScan()` helper
- `internal/license/features.go` — `FeatureDeviceScan` alias + `FeatureFleetScan` constant + tier mapping
- `.github/workflows/ci.yml` — integration job gains sshd service container
- `README.md` — add "Fleet scan" section under Usage
- `CLAUDE.md` — add `### Fleet scan` reference

### Create (docs/examples)

- `docs/examples/fleet-scan/README.md`
- `docs/examples/fleet-scan/devices.yaml.example`

## Testing strategy

### Unit tests (pure Go, no Docker)

All unit tests use an `SSHClient` interface (test seam) that the worker pool operates against. Production impl is `crypto/ssh`; tests use an in-memory fake that records commands + returns scripted responses.

- `fleet_test.go` — worker pool concurrency; `--max-failures` circuit breaker via fake hosts; HostResult aggregation
- `preflight_test.go` — arch-match resolution with fake `uname` outputs (`Linux x86_64`, `Darwin arm64`, `FreeBSD amd64`, `AIX ppc64`); per-device binary override precedence
- `launch_test.go` — command-string builder: `sudo` prefix, flag forwarding, UUID extraction from `Detached as job <uuid>\npid 123` multi-line output
- `collect_test.go` — status JSON parsing, terminal-state detection, partial-tar cleanup
- `summary_test.go` — summary.json serialization, exit-code mapping
- `cmd/fleet_scan_test.go` — flag registration, `--group`/`--device` filtering, `MarkFlagsOneRequired` enforcement

### Integration tests (`//go:build integration`, Docker sshd container)

`test/integration/Dockerfile.sshd`:

```dockerfile
FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server sudo ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash triton-test && \
    echo 'triton-test ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/triton-test
RUN mkdir -p /run/sshd /home/triton-test/.ssh && chmod 700 /home/triton-test/.ssh
COPY testdata/test_ed25519.pub /home/triton-test/.ssh/authorized_keys
RUN chown -R triton-test:triton-test /home/triton-test/.ssh && chmod 600 /home/triton-test/.ssh/authorized_keys
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
```

Four tests:

1. **`TestFleetScan_EndToEnd_SingleHost`** — build triton binary, start sshd container, run fleet-scan against it, verify `scans/<ts>/hosts/testhost.tar.gz` exists and `summary.json` shows `succeeded: 1`
2. **`TestFleetScan_DryRun`** — same setup + `--dry-run`, verify no tar, exit 0, summary reports `1/1 hosts reachable`
3. **`TestFleetScan_SudoFailure`** — spin sshd variant without NOPASSWD, verify `sudo check` phase failure, exit 2
4. **`TestFleetScan_MaxFailures`** — inventory with 3 unreachable + 1 reachable + `--max-failures 2`, verify exit 3

Each CI test: ~30-45s (container startup + build + scan).

### Operator-facing smoke (`--dry-run`)

- Connects to every host (or `--group`/`--device` subset)
- Verifies known-hosts entry exists or `--insecure-host-key`
- Verifies `uname` returns supported arch
- Verifies sudo pre-flight when `sudo: true`
- Writes dry-run summary.txt with per-host OK/FAIL line
- Never touches binary or triggers scan

## Open items / deferred

- Portal UI for fleet-scan summary — portal-unification work
- Parallel scp fan-out via tar+pipe — v2 optimization
- Tier-specific host count caps (pro: 10, enterprise: unlimited) — gate exists, values tunable
- Windows targets via WinRM — separate PR

## Dependencies

- `crypto/ssh` (already transitive)
- `github.com/google/uuid` (already a dep)
- Existing `pkg/scanner/netscan/` for inventory + credentials
- Existing `pkg/scanner/netadapter/transport/` for SSH transport
- PR #71 `internal/runtime/limits/` for forwarded resource limit flags
- PR #72 `internal/runtime/jobrunner/` for reading remote status.json
