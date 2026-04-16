# PCert Parity Wave 2 — TLS Observer + Protocol Discovery

**Date:** 2026-04-16
**Branch:** `feat/pcert-parity-wave2`
**Scope:** 4 new scanner modules closing remaining PCert 4.5.5 discovery gaps

## Background

PR #64 (Wave 1) closed 8 crypto discovery gaps: archive extraction, JKS/JCEKS/BKS
keystore parsing, PKCS#7, encrypted key detection, Windows cert stores, expanded
passwords. Module count reached 51.

Wave 2 targets the remaining protocol-level discovery gaps: passive TLS wire
observation (pcap), FTPS certificate discovery, SSH certificate scanning, and LDIF
certificate extraction.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| CGO | Pure Go only (`CGO_ENABLED=0`) | Preserves scratch container image. `gopacket/pcapgo` for offline pcap; `AF_PACKET` for Linux live capture. macOS live capture deferred. |
| Fingerprints | JA3/JA3S + JA4/JA4S | JA3 for threat intel compatibility, JA4 for richer analysis. JA4X skipped — Triton already extracts full cert details. |
| Target type | New `TargetPcap` | Clean separation from `TargetNetwork`. CLI flags `--pcap-file` and `--pcap-interface` map directly. |
| Architecture | 4 independent modules | One module per file, following established pattern. No god-modules, no overloading existing scanners. |
| Shared code | Extract `tlsutil/chain.go` from `protocol.go` | Avoids duplicating cert chain walking in `ftps.go` and `tls_observer.go`. |

## Module 1: TLS Observer (`tls_observer.go`)

### Purpose

Passive TLS traffic observation via pcap file analysis or live network capture.
Extracts ClientHello/ServerHello metadata and computes JA3/JA3S/JA4/JA4S
fingerprints for PQC compliance assessment.

### Package Layout

```
pkg/scanner/
  tls_observer.go              Module impl, pcap file + AF_PACKET dispatch
  tls_observer_linux.go        AF_PACKET live capture (build-tagged)
  tls_observer_stub.go         Non-Linux live capture → skipped-finding
  internal/tlsparse/
    handshake.go               TLS record layer parser: ClientHello/ServerHello structs
    ja3.go                     JA3/JA3S computation (MD5 of canonical string)
    ja4.go                     JA4/JA4S computation (structured fingerprint string)
    fingerprint.go             Types: Fingerprint, ClientHelloInfo, ServerHelloInfo
    reader.go                  Unified packet source interface
    reader_linux.go            AF_PACKET raw socket reader (build-tagged)
    reader_stub.go             Non-Linux live: returns error
    testdata/
      clienthello.bin          Raw TLS record fixtures
      serverhello.bin
      sample.pcap              Small pcap with known JA3/JA4 values
```

### Data Flow

```
CLI --pcap-file / --pcap-interface
  → TargetPcap ScanTarget
    → TLSObserverModule.Scan()
      → tlsparse.NewReader(file or interface, BPF filter)
        → loop: reader.NextPacket()
          → tlsparse.ParseTLSRecord(payload)
            → ClientHello → extract fields → JA3() + JA4()
            → ServerHello → extract fields → JA3S() + JA4S()
          → group by TCP flow (srcIP:srcPort → dstIP:dstPort)
          → emit Finding per unique flow with fingerprints on CryptoAsset
```

### Design Details

- **BPF filter:** Default `tcp port 443`, overridable via `--pcap-filter`. Applied at pcapgo/AF_PACKET level.
- **Flow tracking:** Map keyed by `(srcIP, srcPort, dstIP, dstPort)`. Tracks until ServerHello received. Bounded at 10K concurrent flows.
- **Live capture window:** `--pcap-window` flag, default 30s (same pattern as `--ebpf-window`).
- **Privilege check:** Live capture requires `CAP_NET_RAW` on Linux. Module checks at scan start, emits skipped-finding if insufficient.
- **Profile:** Comprehensive only.
- **Tier:** Pro+.

### Findings Emitted (per unique TLS flow)

1. **Negotiated cipher** — cipher suite from ServerHello, classified via `crypto.ClassifyCryptoAsset`.
2. **Flow fingerprint** — JA3/JA3S/JA4/JA4S as `protocol_fingerprint` type asset.

## Module 2: FTPS (`ftps.go`)

### Purpose

Connects to FTP servers, upgrades to TLS via `AUTH TLS`, extracts server certificate
and negotiated cipher suite. Covers PCert's "FTPS Scan" feature.

### Scan Flow

1. Dial TCP to target (default port 21, also probes 990 for implicit FTPS).
2. Read FTP banner (220 response).
3. Send `AUTH TLS` command.
4. If `234` response → `tls.Client()` handshake, extract cert chain + cipher.
5. If rejected → try implicit TLS on port 990 (direct TLS, no `AUTH`).
6. Emit findings: server cert, cipher suite, TLS version.

### Design Details

- **Target type:** `TargetNetwork` (host:port, same as protocol.go).
- **Cert chain analysis:** Reuses shared `tlsutil.WalkCertChain()`.
- **Profile:** Standard.
- **Tier:** Pro+ (network scanning).
- **No new dependencies.**

## Module 3: SSH Certificate (`ssh_cert.go`)

### Purpose

Connects to SSH servers and extracts the host key. When the host key is an OpenSSH
certificate (e.g., `ssh-rsa-cert-v01@openssh.com`), parses validity period, CA key,
serial, and extensions. Covers PCert's "SSH Scan" feature.

### What's New vs Existing `key.go`

`key.go` finds SSH host key *files* on disk (`/etc/ssh/ssh_host_*_key`). This module
discovers SSH keys/certificates over the *network* — what the server actually presents
to clients during key exchange.

### Scan Flow

1. Dial TCP to target (default port 22).
2. `golang.org/x/crypto/ssh` handshake with `InsecureIgnoreHostKey()` callback.
3. Extract host key from `ssh.ConnMetadata`.
4. If `ssh.Certificate` type: parse validity, CA key type, serial, extensions.
5. Emit findings: host key algorithm + size, certificate metadata if present.

### Design Details

- **Target type:** `TargetNetwork`.
- **Profile:** Standard.
- **Tier:** Pro+.
- **No new dependencies** — `golang.org/x/crypto/ssh` already in go.mod.

## Module 4: LDIF (`ldif.go`)

### Purpose

Parses LDAP Data Interchange Format (`.ldif`) files and extracts base64-encoded
certificates from directory entries. Covers PCert's "LDIF Scan" feature.

### Scan Flow

1. Filesystem walk discovers `.ldif` files.
2. Line-by-line parser tracks current DN.
3. Detects `userCertificate::`, `cACertificate::`, `userSMIMECertificate::` attributes (double-colon = base64).
4. Collects continuation lines (leading single space per RFC 2849).
5. Base64-decode → `x509.ParseCertificate()`.
6. Emit finding per certificate with `Location = "ldif:<DN>"`.

### Design Details

- **Target type:** `TargetFilesystem` (discovered by walk, matched by `.ldif` extension).
- **Parser scope:** Minimal — only extracts certificate attributes. Not a full RFC 2849 implementation. Handles folded lines, base64 values, multi-valued attributes.
- **Profile:** Standard.
- **Tier:** Free (filesystem-only, no special capability).
- **No new dependencies.**

## Shared Extraction: `pkg/scanner/internal/tlsutil/`

Refactored from `protocol.go` to avoid duplication across `protocol.go`, `ftps.go`,
and `tls_observer.go`:

- `chain.go` — `WalkCertChain(certs []*x509.Certificate) []ChainEntry`
  - Labels: leaf/intermediate/root
  - Weak signature detection (SHA-1, MD5)
  - Expiry warning (30-day)
  - SAN extraction

This is a refactor of existing `protocol.go` code, not new logic.

## CLI Integration

### New Flags (`cmd/root.go`)

```
--pcap-file <path>          Path to .pcap/.pcapng file for offline analysis
--pcap-interface <name>     Network interface for live capture (e.g., eth0)
--pcap-window <duration>    Live capture duration (default 30s)
--pcap-filter <string>      BPF filter override (default "tcp port 443")
```

`--pcap-file` and `--pcap-interface` are mutually exclusive. If neither is set, the
TLS observer module is skipped.

### Target Injection

When `--pcap-file` or `--pcap-interface` is set, the engine adds a `TargetPcap` scan
target with `Value` = file path or `iface:<name>`.

## Model Changes

### New Target Type (`pkg/model/types.go`)

```go
TargetPcap ScanTargetType = "pcap"
```

### New CryptoAsset Fields

```go
JA3Fingerprint  string `json:"ja3_fingerprint,omitempty"`
JA3SFingerprint string `json:"ja3s_fingerprint,omitempty"`
JA4Fingerprint  string `json:"ja4_fingerprint,omitempty"`
JA4SFingerprint string `json:"ja4s_fingerprint,omitempty"`
SNI             string `json:"sni,omitempty"`
TLSFlowSource  string `json:"tls_flow_source,omitempty"`
```

## Report Rendering

- **HTML:** JA3/JA4 fingerprints in finding detail card. "TLS Flows" section for pcap-sourced findings.
- **CycloneDX JSON:** `triton:ja3`, `triton:ja3s`, `triton:ja4`, `triton:ja4s` properties.
- **CSV (Jadual 2):** JA3/JA4 columns after existing cipher columns. Empty when not pcap-sourced.
- **SARIF:** Fingerprints in `properties` bag.

## Doctor Checks

- Live pcap: `CAP_NET_RAW` capability (Linux) or root privilege message (macOS).
- FTPS, SSH, LDIF: No external tools needed.

## Testing Strategy

### Unit Tests

| Package/Module | Test File | Key Cases |
|----------------|-----------|-----------|
| `tlsparse/` | `handshake_test.go`, `ja3_test.go`, `ja4_test.go` | Known-answer vectors for JA3/JA4. Malformed records. Truncated packets. Empty extensions. GREASE handling. |
| `tls_observer` | `tls_observer_test.go` | Mock reader with fixture pcap. Flow tracking. 10K flow cap. Window timeout. Privilege check skip-finding. |
| `ftps` | `ftps_test.go` | Mock FTP server (explicit + implicit TLS). Banner parsing. Rejection. Cert extraction. |
| `ssh_cert` | `ssh_cert_test.go` | Mock SSH server. Plain host key vs OpenSSH certificate. Algorithm extraction. |
| `ldif` | `ldif_test.go` | Multi-entry LDIF with certs. Folded lines. Missing certs. Malformed base64. Multiple cert attributes per entry. |
| `tlsutil/chain` | `chain_test.go` | Migrated from protocol.go chain tests. |

### Coverage Target

- `tlsparse/`: >85%
- Each module: >80%

### Integration Tests

One test in `test/integration/` that runs a pcap file through the full scan pipeline
and verifies findings appear in the result JSON.

### E2E

No new E2E tests — modules don't affect web UI beyond existing finding display.

## New Dependency

- `github.com/gopacket/gopacket` — `pcapgo.Reader` (offline pcap) + `layers` (TCP/IP decoding). Pure Go, no CGO.

## Profile/Tier Summary

| Module | Profile | Tier | Privileges |
|--------|---------|------|------------|
| `tls_observer` | comprehensive | Pro+ | `CAP_NET_RAW` (live only) |
| `ftps` | standard | Pro+ | None |
| `ssh_cert` | standard | Pro+ | None |
| `ldif` | standard | Free | None |

## Deferred

- macOS live capture (needs libpcap/CGO)
- Windows live capture
- QUIC/HTTP3 fingerprinting (JA4H)
- JA4X certificate fingerprint (redundant with existing cert extraction)
- Full RFC 2849 LDIF parser (change records, modrdn, etc.)
- STARTTLS for SMTP/IMAP/POP3 (additional protocol upgrades)
