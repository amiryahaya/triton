# Agentless Scanning MVP — Design Spec

**Date:** 2026-04-14
**Branch:** `feat/agentless-scanning`
**Status:** Approved
**Scale target:** 1000+ devices per organization

## Problem

Triton today requires a binary on every scan target. This blocks:
- **Network devices** (Cisco, Juniper routers) — cannot run Go binaries
- **AIX / Solaris legacy systems** — binary distribution is operationally hard
- **Customer preference** — security teams prefer agentless models (Tenable, Qualys pattern)
- **Scale** — deploying 1000+ agents is a significant operational burden

Customers need a way to scan 1000+ hosts and routers from a single scanner host using SSH/NETCONF, with no binary deployed on targets.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Host coverage | Linux, macOS, AIX | SSH universally supported; Windows deferred to separate phase |
| Router coverage | Cisco IOS-XE + Juniper Junos | ~70% of enterprise market; proves multi-vendor architecture |
| Windows | Deferred | WinRM/Kerberos is a sub-platform; needs its own design |
| Module adapter strategy | FileReader abstraction | Single codebase for local + remote; zero-overhead local path |
| Scanner modules in MVP | Tier 1 only (14 file-read modules) | Sudo-dependent scanners (Tier 2) deferred |
| Credential storage | Encrypted YAML (AES-256-GCM) | Reuses existing encryption pattern; sufficient for MVP |
| Deployment model | Single scanner host reaches remote targets | Industry standard (Tenable/Qualys pattern) |
| Licensing | Enterprise tier feature | Consistent with server mode, agent mode |

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Triton scanner host (one per network segment)                   │
│                                                                   │
│  CLI: triton network-scan --inventory devices.yaml               │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Orchestrator                                             │   │
│  │  ├─ Load inventory.yaml (1000+ device entries)           │   │
│  │  ├─ Load credentials.yaml (encrypted at rest)             │   │
│  │  ├─ Worker pool (configurable concurrency, default 20)    │   │
│  │  ├─ Per-device timeout, failure isolation                 │   │
│  │  └─ Dispatch per device_type to appropriate adapter       │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Transport layer                                           │   │
│  │  ├─ ssh.Transport   — golang.org/x/crypto/ssh            │   │
│  │  └─ netconf.Transport — NETCONF/YANG over SSH port 830   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Adapters                                                  │   │
│  │  ├─ unix/     — FileReader over SSH (Linux/macOS/AIX)     │   │
│  │  ├─ cisco/    — CommandRunner + show-cmd parsers          │   │
│  │  └─ juniper/  — NetconfRunner + YANG XML parsers          │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  Scanner modules                                                  │
│  ├─ Tier 1 file scanners — receive FileReader                    │
│  └─ Network/protocol scanners — already remote-capable            │
│                                                                   │
│  Findings → model.ScanResult per device → POST /api/v1/scans    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ (one ScanResult per remote device,
                              │  hostname = device hostname,
                              │  existing ETL pipeline + analytics)
                              ▼
                    ┌──────────────────┐
                    │  Report server   │
                    │  (unchanged)     │
                    └──────────────────┘
```

**Key architectural property:** each scanned device produces a `*model.ScanResult` identical in shape to a local scan. The report server, ETL pipeline, analytics dashboards, remediation, and exports all work without modification.

## FileReader Abstraction

The core abstraction that decouples scanner modules from the source of file I/O.

### Interface

```go
// pkg/scanner/fsadapter/reader.go
package fsadapter

import (
    "context"
    "io/fs"
)

type FileReader interface {
    ReadFile(ctx context.Context, path string) ([]byte, error)
    Stat(ctx context.Context, path string) (fs.FileInfo, error)
    ReadDir(ctx context.Context, path string) ([]fs.DirEntry, error)
    Walk(ctx context.Context, root string, fn WalkFunc) error
}

type WalkFunc func(path string, entry fs.DirEntry, err error) error
```

### Implementations

**LocalReader** — wraps `os.ReadFile` / `os.Stat` / `filepath.WalkDir`. Zero overhead vs today. Used for local scans.

**SshReader** — uses an SSH session to execute commands on the remote host:
- `ReadFile(path)` → `cat path | base64 -w0` (binary-safe)
- `Stat(path)` → `stat -c '%s %Y %a %F' path`
- `Walk(root)` → **single `find` command** with NUL-separated output
  - Unix: `find root -print0 -printf '%y\0%s\0'`
  - AIX fallback: `find root -type f` (no `-printf`), follow-up stat per file

**Performance:** the single-find-per-walk optimization is critical. 50,000-file walk = one SSH round-trip, not 50,000.

### Walker integration

`pkg/scanner/walker.go` is refactored to accept an optional `FileReader`:

```go
type walkerConfig struct {
    target      model.ScanTarget
    reader      fsadapter.FileReader  // NEW: nil = LocalReader
    matchFile   func(path string) bool
    processFile func(ctx context.Context, reader fsadapter.FileReader, path string) error
    // existing fields: depth, excludes, size caps, hash-based incremental...
}
```

### Module changes

Each Tier 1 module's `processFile` callback signature changes from:
```go
func processFile(path string) error {
    data, _ := os.ReadFile(path)
    // parse data...
}
```
to:
```go
func processFile(ctx context.Context, reader fsadapter.FileReader, path string) error {
    data, _ := reader.ReadFile(ctx, path)
    // parse data... (unchanged)
}
```

**15 Tier 1 modules** change: certificate, key, library, binary, script, webapp, config, container, web_server, vpn, container_signatures, service_mesh, xml_dsig, mail_server, deps_ecosystems.

**Kernel, process, network, protocol, codesign, hsm, ldap, database modules remain unchanged** for MVP (their semantics don't fit FileReader cleanly).

## Router Adapters

Routers don't have filesystems. They need a different abstraction.

### CommandRunner (Cisco — CLI)

```go
// pkg/scanner/netadapter/runner.go
type CommandRunner interface {
    Run(ctx context.Context, command string) (string, error)
}
```

### NetconfRunner (Juniper — structured)

```go
type NetconfRunner interface {
    GetConfig(ctx context.Context, filter string) ([]byte, error) // returns XML
    Get(ctx context.Context, filter string) ([]byte, error)
}
```

### Cisco IOS-XE adapter

```go
// pkg/scanner/netadapter/cisco/cisco_iosxe.go
func (a *CiscoAdapter) Scan(ctx context.Context, findings chan<- *model.Finding) error {
    a.scanSSHConfig(ctx, findings)         // show ip ssh, show ssh
    a.scanCryptoTrustpoints(ctx, findings) // show crypto pki certificates
    a.scanIPsec(ctx, findings)             // show crypto ipsec sa, show crypto isakmp policy
    a.scanSNMP(ctx, findings)              // show snmp user
    a.scanRoutingAuth(ctx, findings)       // show ip ospf interface
    a.scanWebUI(ctx, findings)             // show ip http server status
    return nil
}
```

**SSH quirks handled by transport:**
- `terminal length 0` as first command (disable paging)
- Optional `enable` mode with separate enable password
- Per-command timeout (devices freeze)
- Concurrent session limit (some Cisco gear allows only 1-2 SSH sessions)

**Parsers** use Go regexes against CLI output. Test fixtures from real device output saved in `pkg/scanner/netadapter/cisco/testdata/`.

### Juniper Junos adapter

```go
// pkg/scanner/netadapter/juniper/junos.go
func (a *JunosAdapter) Scan(ctx context.Context, findings chan<- *model.Finding) error {
    a.scanSSHService(ctx, findings)    // <get-configuration><system><services><ssh/>
    a.scanIKE(ctx, findings)           // <get-configuration><security><ike>
    a.scanIPsec(ctx, findings)         // <get-configuration><security><ipsec>
    a.scanCertificates(ctx, findings)  // <get-configuration><security><pki>
    a.scanSNMP(ctx, findings)          // <get-configuration><snmp>
    return nil
}
```

NETCONF returns structured XML — uses `encoding/xml` with Junos schemas.

## Device Inventory

```yaml
# /etc/triton/devices.yaml — 1000+ entries realistic
version: 1

defaults:                        # applied to all devices unless overridden
  port: 22
  scan_timeout: 5m
  sudo: false

devices:
  - name: web-srv1
    type: unix
    address: 10.0.1.10
    credential: prod-ssh-key
    scan_paths: [/etc, /usr/local/etc, /opt]

  - name: edge-router-1
    type: cisco-iosxe
    address: 10.0.0.1
    credential: cisco-tacacs
    enable_credential: cisco-enable

  - name: core-srx-1
    type: juniper-junos
    address: 10.0.0.2
    port: 830
    credential: juniper-netconf

groups:                          # for selective scans
  - name: production
    members: [web-srv1, edge-router-1]
  - name: legacy
    members: [legacy-aix-1, legacy-solaris-2]
```

**Scale operations:**
- `triton network-scan --group production` — scan one group
- `triton network-scan --device edge-router-1` — single device (debugging)
- Inventory validation at startup — catches typos/missing credentials before any SSH attempt

## Credential Store

```yaml
# /etc/triton/credentials.yaml — encrypted at rest (AES-256-GCM)
# Logical structure shown here; on disk is base64(nonce || ciphertext || tag)
version: 1

credentials:
  - name: prod-ssh-key
    type: ssh-key
    username: triton-scanner
    private_key_path: /etc/triton/keys/prod_id_ed25519
    passphrase: ""

  - name: cisco-tacacs
    type: ssh-password
    username: triton-readonly
    password: "..."

  - name: cisco-enable
    type: enable-password
    password: "..."

  - name: juniper-netconf
    type: ssh-key
    username: triton-readonly
    private_key_path: /etc/triton/keys/juniper_id_ed25519
```

### Encryption

- 32-byte AES-256-GCM key from `TRITON_SCANNER_CRED_KEY` env var (hex-encoded)
- Missing key at startup = hard error
- Separate key from `REPORT_SERVER_DATA_ENCRYPTION_KEY` (different threat models)

### Management CLI

```
triton credential add      --name X --type ssh-key --username U --key /path
triton credential list                              # names + types only, never plaintext
triton credential rotate   --name X --key /new/path
triton credential delete   --name X                 # fails if any device references it
triton credential bootstrap --name triton-scanner   # generates keypair + prints pubkey + Ansible snippet
```

## Orchestrator

```go
// pkg/scanner/netscan/orchestrator.go
type Orchestrator struct {
    Inventory        *Inventory
    Credentials      *CredentialStore
    Concurrency      int           // default 20; tuned per deployment
    PerDeviceTimeout time.Duration // default 5m
}

func (o *Orchestrator) Scan(ctx context.Context) ([]*model.ScanResult, error) {
    sem := make(chan struct{}, o.Concurrency)
    results := make([]*model.ScanResult, len(o.Inventory.Devices))
    var wg sync.WaitGroup

    for i, device := range o.Inventory.Devices {
        wg.Add(1)
        sem <- struct{}{}
        go func(idx int, d Device) {
            defer wg.Done()
            defer func() { <-sem }()

            deviceCtx, cancel := context.WithTimeout(ctx, o.PerDeviceTimeout)
            defer cancel()

            result, err := o.scanDevice(deviceCtx, d)
            if err != nil {
                results[idx] = makeFailureResult(d, err)
                return
            }
            results[idx] = result
        }(i, device)
    }
    wg.Wait()
    return results, nil
}
```

### Per-device scan dispatch

```go
func (o *Orchestrator) scanDevice(ctx context.Context, d Device) (*model.ScanResult, error) {
    cred := o.Credentials.Get(d.Credential)
    switch d.Type {
    case "unix":
        return o.scanUnixHost(ctx, d, cred)
    case "cisco-iosxe":
        return o.scanCiscoDevice(ctx, d, cred)
    case "juniper-junos":
        return o.scanJuniperDevice(ctx, d, cred)
    default:
        return nil, fmt.Errorf("unknown device type: %s", d.Type)
    }
}
```

### Safeguards

- **Per-device timeout** — no single device blocks the pool
- **Failure isolation** — one device's crash doesn't affect others
- **Credential lockout protection** — 3 consecutive auth failures for same credential → pause that credential for 60s (avoids locking accounts in TACACS+/RADIUS)
- **Graceful shutdown** — Ctrl-C cancels in-flight scans, completed results are submitted

### Concurrency tuning for 1000+ devices

| Concurrency | Total scan time | Network/SSH load |
|---|---|---|
| 10 | ~8-10 min for 1000 devices | Light |
| 20 (default) | ~4-5 min | Moderate |
| 50 | ~2 min | Heavy (many targets may rate-limit) |
| 100+ | Risk of SSH rate limits, router CPU spikes | Not recommended |

Configurable via `--concurrency` flag or `concurrency` field in inventory.yaml.

## Findings Integration

Each device produces a `*model.ScanResult`:

```go
ScanResult {
    Metadata: {
        Hostname: d.Name,                              // from inventory
        AgentID:  "triton-netscan/<version>",         // distinguishes from local
        Profile:  "agentless",
        Timestamp: time.Now(),
    },
    Findings: [...collected from adapter...],
    OrgID: resolved-from-license-token,
}
```

Each result goes through the **existing** `POST /api/v1/scans` flow → SaveScanWithFindings → T1/T2/T3 pipeline → analytics. No changes to report server, no new analytics views, no new dashboard code.

## Deployment Model

### The scanner host

One VM or physical box per network segment. Requirements:
- Network access to targets (SSH ports 22, 830)
- Sufficient resources for N=20 concurrent SSH sessions (modest — 1 CPU, 1GB RAM handles this)
- Triton binary + inventory.yaml + credentials.yaml + SSH keys
- systemd timer or cron for scheduled scans

### Onboarding 1000 hosts (operator perspective)

**Prerequisite:** The customer already has Ansible/Puppet/Chef/Salt for fleet management.

```
┌────────────────────────────────────────────────────────────┐
│  Step 1: Scanner host setup (one-time, 10 min)             │
│                                                              │
│    sudo apt install triton-scanner                          │
│    triton credential bootstrap --name prod-scanner          │
│    # → prints public key + Ansible role snippet             │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│  Step 2: Deploy SSH access to 1000 targets (5 min via      │
│  customer's existing Ansible)                               │
│                                                              │
│    - user: { name: triton-scanner }                         │
│    - authorized_key: { key: "{{ scanner_pubkey }}" }        │
│                                                              │
│    ansible-playbook -i all-targets.yaml triton-access.yaml  │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│  Step 3: Generate inventory.yaml (5-30 min)                 │
│                                                              │
│    Options:                                                  │
│    - Export from AD / ServiceNow / CMDB                     │
│    - Convert Ansible inventory with provided script         │
│    - Manually curate for router list                        │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│  Step 4: First scan                                         │
│                                                              │
│    triton network-scan --inventory /etc/triton/devices.yaml │
│    # → scans 1000 devices in ~5 min at default concurrency │
│                                                              │
│    Results appear in dashboard immediately                  │
└────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│  Step 5: Schedule                                           │
│                                                              │
│    systemctl enable --now triton-netscan.timer              │
│    # daily scans; failure reports via existing report server│
└────────────────────────────────────────────────────────────┘
```

### Shipped artifacts for deployment

| Artifact | Purpose |
|---|---|
| Example Ansible playbook | `triton-access.yaml` — creates user + deploys SSH key |
| Example Bash loop | `setup-fleet.sh` — for customers without Ansible |
| `triton credential bootstrap` CLI | Generates keypair + prints ready-to-use Ansible snippet |
| Documentation | "Onboarding 1000 hosts in 30 minutes" walkthrough |

## CLI Commands

```bash
# One-shot scan
triton network-scan --inventory /etc/triton/devices.yaml

# Scan one group
triton network-scan --inventory devices.yaml --group production

# Single device (debugging)
triton network-scan --inventory devices.yaml --device edge-router-1

# Continuous mode
triton network-scan --inventory devices.yaml --interval 24h

# Dry run (validates inventory + credentials, tests connectivity, no scan)
triton network-scan --inventory devices.yaml --dry-run

# Credential management
triton credential add --name X --type ssh-key ...
triton credential list
triton credential rotate --name X ...
triton credential delete --name X
triton credential bootstrap --name prod-scanner
```

## Failure Handling

Per-device failures do NOT kill the run. Orchestrator emits a summary:

```
Network scan complete:
  Total devices: 1000
  Succeeded:      987
  Failed:          13
    - legacy-aix-1:   ssh handshake timeout (10s)
    - core-srx-2:     netconf authentication failed
    - edge-rtr-9:     command 'show crypto pki' returned 'Invalid input'
    - [10 more — see /var/log/triton/netscan-failures.log]

Findings submitted: 24,871
Pipeline jobs enqueued: 987
```

Failed devices are submitted as empty `ScanResult` with error metadata so they appear in the dashboard's Systems view as "scan failed — last attempt: <reason>". Makes fleet-wide failures visible.

## Licensing

**New feature gate:** `FeatureNetworkScan` — enterprise tier only.

Added to `internal/license/tier.go` alongside `FeatureServerMode` and `FeatureAgentMode`. Guard enforcement in `cmd/network_scan.go` via `EnforceFeature(FeatureNetworkScan)`.

**Note:** Per-scan and delta-scan licensing metering is **deferred to a separate phase** (user request). MVP gates the feature on tier, not per-scan count.

## Component Changes

| File / Package | Action | Responsibility |
|---|---|---|
| `pkg/scanner/fsadapter/reader.go` | Create | `FileReader` interface |
| `pkg/scanner/fsadapter/local_reader.go` | Create | `LocalReader` impl |
| `pkg/scanner/fsadapter/ssh_reader.go` | Create | `SshReader` impl with single-find optimization |
| `pkg/scanner/walker.go` | Modify | Accept `FileReader`; defaults to LocalReader |
| 15 Tier 1 scanner modules | Modify | `processFile` signature gains `FileReader` arg; swap `os.ReadFile` |
| `pkg/scanner/netadapter/runner.go` | Create | `CommandRunner`, `NetconfRunner` interfaces |
| `pkg/scanner/netadapter/transport/ssh.go` | Create | SSH transport with paging/timeout/enable-mode |
| `pkg/scanner/netadapter/transport/netconf.go` | Create | NETCONF over SSH (port 830) |
| `pkg/scanner/netadapter/cisco/cisco_iosxe.go` | Create | Cisco IOS-XE adapter + show parsers |
| `pkg/scanner/netadapter/juniper/junos.go` | Create | Junos adapter + XML parsers |
| `pkg/scanner/netscan/inventory.go` | Create | Inventory YAML loader + validator |
| `pkg/scanner/netscan/credentials.go` | Create | Encrypted credential store + CLI backing |
| `pkg/scanner/netscan/orchestrator.go` | Create | Worker pool + dispatch + failure isolation |
| `cmd/network_scan.go` | Create | `triton network-scan` Cobra command |
| `cmd/credential.go` | Create | `triton credential` subcommands |
| `internal/license/tier.go` | Modify | Add `FeatureNetworkScan` |
| `internal/license/guard.go` | Modify | Wire network-scan enforcement |
| `docs/examples/agentless/` | Create | Example inventory.yaml, Ansible playbook, setup script |
| `go.mod` | Modify | Add `golang.org/x/crypto/ssh` (verify present), NETCONF library |

## What Does NOT Change

- Existing `triton scan`, `triton agent` commands — fully backward compatible
- Scanner module detection logic — only file-access call sites change
- Findings model, scan submission API, ETL pipeline
- Report server, license server schemas
- Analytics dashboards, remediation UI, export functionality
- Local scan performance (LocalReader is a thin wrapper)

## Test Plan

### Unit
- FileReader implementations (mock SSH transport) — walk, read, stat
- Cisco/Juniper parsers — real `show`/XML output fixtures in `testdata/`
- Credential encryption round-trip — encrypt, reload, decrypt, verify
- Orchestrator — dedup, concurrency, per-device timeout, failure isolation

### Integration
- SSH scanner against `localhost:22` — proves SSH path works end-to-end
- Mock Cisco CLI server (goexpect-based) — validates parser against command flows
- Mock NETCONF server — validates Junos XML parsing

### Manual (MVP validation)
- Real Linux host via SSH — compare findings to local scan of same host (should match modulo path differences)
- Real Cisco IOS-XE device (lab or GNS3 simulator)
- Real Juniper vMX (free eval image)

## Rollback

All changes are additive. Remove `pkg/scanner/netscan/` + `pkg/scanner/netadapter/` + the new CLI commands to disable agentless. FileReader abstraction is harmless if unused — local scans default to LocalReader with zero overhead.

## Effort Estimate

| Component | Days |
|---|---|
| FileReader abstraction + walker refactor | 2 |
| 15 Tier 1 module adaptations (1-2 hours each) | 3 |
| SSH transport + LocalReader + SshReader | 2 |
| Cisco IOS-XE adapter (6 show-command parsers) | 4 |
| Juniper Junos adapter (NETCONF + 5 XML parsers) | 4 |
| Inventory + credential store + encryption + CLI | 4 |
| Orchestrator (worker pool, failure handling, lockout) | 2 |
| `triton network-scan` + `triton credential` CLI | 2 |
| Example Ansible playbook + onboarding docs | 1 |
| License enforcement + integration tests | 2 |
| **Total** | **26 days** |

## Future Phases

Explicitly out of MVP scope, flagged for follow-up:

1. **Delta scans** — only re-scan files changed since last run (via hash state on scanner host)
2. **Per-scan / fleet-size licensing** — meter scans and device count, enforce tier limits
3. **Windows via WinRM** — Kerberos/NTLM auth, PowerShell command execution, Windows-specific scanners
4. **Tier 2 scanners** — sudo-required: password_hash, auth_material, privileged process inspection
5. **More router vendors** — Arista EOS (eAPI), Huawei VRP, Palo Alto, Fortinet
6. **Auto-discovery** — ICMP sweep + SSH banner grab, AD/LDAP integration, CMDB import
7. **Scheduled scans per-group** — different cadences for production vs legacy
8. **External secrets managers** — HashiCorp Vault, AWS Secrets Manager integration
9. **Network-scan dashboard view** — fleet health summary, failed-device list, scan history per device
10. **Ansible Collection + Puppet Module + Chef Cookbook** — published to respective registries
