# TPM 2.0 Attestation Analyzer — Design

> **Status:** approved scope; ready for implementation plan. First hardware-root-of-trust scanner in the project.

## Why

Every PQC-inventory scanner shipped so far operates on software artefacts — keys on disk, crypto calls in binaries, certs in PEM files. The hardware root of trust (TPM) is invisible to all of them. That leaves significant false negatives:

- **Infineon ROCA TPMs (CVE-2017-15361)** — millions of Windows/Linux machines with vulnerable firmware-generated RSA keys. The existing `keyquality.go` catches keys extracted to disk; it cannot see keys sealed inside the TPM.
- **TPM 2.0 library bugs (CVE-2023-1017/1018)** — out-of-bounds read/write in the TCG reference library; shipped in most hardware TPMs since ~2015.
- **Measured-boot integrity** — event log hash algorithms directly affect boot-time attestation strength. A log that only extends SHA-1 banks is functionally broken.

This PR adds passive scanning of TPM artefacts in the filesystem. Active TPM device queries (via `/dev/tpm0`) are a deferred follow-up.

## Scope

**In scope (PR #1):**

| Signal | Source | Classification |
|---|---|---|
| Vendor + firmware version | `/sys/class/tpm/tpmN/device/caps` | Match against committed CVE registry |
| EK certificate | `/sys/class/tpm/tpmN/device/endorsement_key_cert` | Parse as X.509; reuse existing `crypto.ClassifyCryptoAsset` + `keyquality.Analyze` |
| Event log hash algorithms | `/sys/kernel/security/tpmN/binary_bios_measurements` | SHA-1 only → UNSAFE; SHA-256+ only → SAFE; mixed → TRANSITIONAL |

**Out of scope (deferred PRs):**
- Active TPM device queries (`/dev/tpm0`, TPM2_Quote, PCR reads) — needs root + `github.com/google/go-tpm` dep
- Windows TBS API, macOS TPM (T2) access
- PCR digest aggregation + comparison against reference measurements
- TPM presence/absence policy rule
- TCG Runtime Integrity Monitoring (IMA/EVM) log parsing
- Attestation key (AK) cert chain validation
- Event log playback + PCR quote signature verification

## Architecture

```
Engine dispatches tpm module (Linux only)
   ↓
walk /sys/class/tpm/ → list devices (tpm0, tpm1, …)
   ↓
per device:
   ↓
  read device/caps → (vendor, firmware version, TCG version)
   ↓
  LookupTPMFirmwareCVEs(vendor, firmwareVersion) → []CVE
   ↓
  emit device Finding with CVE-derived QualityWarnings
   ↓
  if endorsement_key_cert exists: parse → ClassifyCryptoAsset → keyquality.Analyze → emit EK cert Finding
   ↓
  if /sys/kernel/security/tpmN/binary_bios_measurements exists: parse TCG PFP binary log → classify by hash algorithms → emit event-log Finding
```

Non-Linux stub emits one skipped-finding. Comprehensive profile + Pro+ tier (mirrors `ebpf_trace`). No new external deps — TCG PFP format is parseable with `encoding/binary`; EK cert parsing uses stdlib `crypto/x509`.

## Package Layout

```
pkg/scanner/tpm.go                         # Module shell: Name/Category/ScanTargetType; dispatches to OS-specific scan()
pkg/scanner/tpm_linux.go                   # //go:build linux — real scan() driver
pkg/scanner/tpm_other.go                   # //go:build !linux — skipped-finding stub
pkg/scanner/tpm_test.go                    # module identity tests (all OS)
pkg/scanner/tpm_other_test.go              # //go:build !linux — stub behaviour

pkg/scanner/internal/tpmfs/
  types.go                                 # Device, EventLogEntry, ParsedLog, HashAlgo constants
  tpmfs.go                                 # //go:build linux — sysfs walker; root-injectable for tests
  tpmfs_test.go
  eventlog.go                              # TCG PFP binary log parser (portable, no build tag)
  eventlog_test.go
  ekcert.go                                # EK cert DER reader
  ekcert_test.go
  testdata/
    sysfs-infineon/                        # Hand-crafted fixture tree
      tpm0/
        tpm_version_major
        device/
          caps
          endorsement_key_cert              (DER)
    event-log-modern.bin                   # Real TCG log sample, SHA-256 only
    event-log-legacy.bin                   # Synthesised SHA-1-only log

pkg/crypto/tpm_firmware.go                 # CVE registry: vendor + firmware-version → CVE refs
pkg/crypto/tpm_firmware_test.go
```

### Modifications
- `pkg/scanner/engine.go` — append `NewTPMModule` factory after `NewEBPFTraceModule`
- `internal/scannerconfig/config.go` — append `"tpm"` to comprehensive `Modules` list
- `internal/scannerconfig/config_test.go` — NotContains/Contains assertions (quick/standard/comprehensive)
- `internal/license/tier.go` — append `"tpm"` to Pro+ allowlist
- `CLAUDE.md` — bullets under `pkg/scanner/` (`tpm.go`) and `pkg/crypto/` (`tpm_firmware.go`)

## sysfs Data Layout

```
/sys/class/tpm/tpm0/
  ├── tpm_version_major            "2" | "1.2"
  ├── device/
  │   ├── description              "TPM 2.0 Device"
  │   ├── caps                     (multiline text — primary source)
  │   └── endorsement_key_cert     (DER; present when TPM provisioned)
```

`caps` is a free-form text file with lines like:
```
Manufacturer: 0x49465800
TCG version: 2.0
Firmware version: 4.32.1.2
```

Parser splits lines on `:` (first colon), trims, matches keys `Manufacturer` / `TCG version` / `Firmware version`.

**Vendor ID table** (lookup on 4-byte ASCII decode of manufacturer hex):

| ID | Name |
|---|---|
| `IFX ` | Infineon |
| `INTC` | Intel |
| `NTC ` | Nuvoton |
| `STM ` | STMicroelectronics |
| `ATML` | Microchip (ex-Atmel) |
| `MSFT` | Microsoft (virtual / VM) |
| `GOOG` | Google (virtual / vTPM) |
| `AMD ` | AMD |

Unknown vendors pass through as the raw 4-char code.

## TPM Firmware CVE Registry

`pkg/crypto/tpm_firmware.go`:

```go
type TPMFirmwareCVE struct {
    Vendor      string   // "Infineon", "Intel", ...
    CVE         string   // "CVE-2017-15361"
    MinVersion  string   // inclusive; "" = any
    MaxVersion  string   // inclusive; "" = any
    Description string
    Severity    string   // CRITICAL | HIGH | MEDIUM
}

func LookupTPMFirmwareCVEs(vendor, firmwareVersion string) []TPMFirmwareCVE
```

Initial entries (~5):

| Vendor | CVE | Version range | Note |
|---|---|---|---|
| Infineon | CVE-2017-15361 | ≤ 4.33.4 | ROCA |
| *any TPM 2.0* | CVE-2023-1017 | TCG lib ≤ 1.59 | OOB write |
| *any TPM 2.0* | CVE-2023-1018 | TCG lib ≤ 1.59 | OOB read |
| Intel PTT | CVE-2017-5689 | Firmware TPM ≤ 11.6 | Management-adjacent |
| STMicro ST33 | CVE-2019-16863 | Firmware ≤ 73.04 | ECDSA nonce bias |

Version comparison: vendor-specific parsers for Infineon and Intel (dotted integer tuples); fallback to string equality for other vendors. PR #1 is explicit that only Infineon/Intel get range comparisons; the others use exact-match against the CVE entry's MinVersion.

## TCG Event Log Format

TCG PC Client Platform Firmware Profile (TPM 2.0) binary format:

```
Header (TCG_PCR_EVENT pseudo-event, 32 bytes + variable SpecID):
  PCRIndex       uint32 = 0
  EventType      uint32 = EV_NO_ACTION
  DigestSHA1     [20]byte
  EventSize      uint32
  EventData      [EventSize]byte  ← contains TCG_EfiSpecIDEventStruct

Then 0..N of TCG_PCR_EVENT2:
  PCRIndex       uint32
  EventType      uint32
  DigestCount    uint32
  Digests: [(AlgID uint16, [size]byte)] × DigestCount
  EventSize      uint32
  EventData      [EventSize]byte
```

TPM_ALG_ID → size:
- 0x0004 SHA-1: 20 bytes
- 0x000B SHA-256: 32 bytes
- 0x000C SHA-384: 48 bytes
- 0x000D SHA-512: 64 bytes
- 0x0012 SM3: 32 bytes

Parser walks the log, tracks per-event hash algorithm set. Classification rules:
- Any event with SHA-1 in its digest set AND NO event contains SHA-256+ → `UNSAFE: event log uses only SHA-1 banks`
- All events have at least one SHA-256+ digest AND no SHA-1 digests present → `SAFE: event log uses SHA-256 or stronger`
- Mixed (SHA-1 + SHA-256 banks co-exist) → `TRANSITIONAL: event log has both SHA-1 and modern banks`

## Finding Shapes

**Device finding** (always, when `/sys/class/tpm/tpmN/` exists):
```json
{
  "module": "tpm",
  "category": 5,
  "source": {
    "type": "file",
    "path": "/sys/class/tpm/tpm0",
    "detectionMethod": "sysfs",
    "evidence": "vendor=Infineon firmware=4.32.1.2 tcg-version=2.0"
  },
  "cryptoAsset": {
    "algorithm": "TPM2.0",
    "library": "Infineon TPM firmware",
    "language": "Firmware",
    "function": "Hardware root of trust",
    "pqcStatus": "UNSAFE",
    "qualityWarnings": [
      {"code": "FIRMWARE-CVE", "severity": "CRITICAL",
       "message": "Infineon ROCA vulnerable prime generation",
       "cve": "CVE-2017-15361"}
    ]
  },
  "confidence": 0.95
}
```

**EK cert finding** (when parseable): standard X.509 shape, `Function: "TPM endorsement key"`. Flows through `crypto.ClassifyCryptoAsset` + `keyquality.Analyze`.

**Event log finding** (when present):
```json
{
  "module": "tpm",
  "source": {
    "path": "/sys/kernel/security/tpm0/binary_bios_measurements",
    "detectionMethod": "tcg-pfp-log",
    "evidence": "47 events: 47 SHA-256, 47 SHA-1"
  },
  "cryptoAsset": {
    "algorithm": "Measured-Boot-Log",
    "library": "TCG PFP TPM 2.0",
    "pqcStatus": "TRANSITIONAL"
  }
}
```

## Engine Wiring

| Property | Value |
|---|---|
| Module name | `tpm` |
| Category | `model.CategoryPassiveFile` |
| Target | `model.TargetFilesystem` |
| Profile | `comprehensive` only |
| Tier | Pro+ (append to `internal/license/tier.go`) |
| Prereq | Linux + `/sys/class/tpm/` exists (silent no-findings when absent) |
| New CLI flags | none |
| Doctor check | none — module is quiet when no TPM present |

## Tests

| Layer | File | What |
|---|---|---|
| Unit — sysfs walker | `tpmfs/tpmfs_test.go` | fixture root injection; parses vendor/firmware; handles missing optional files |
| Unit — event log | `tpmfs/eventlog_test.go` | parse modern (SHA-256-only) + legacy (SHA-1-only) logs; algorithm classification |
| Unit — EK cert | `tpmfs/ekcert_test.go` | parse DER fixture; handle missing file gracefully |
| Unit — firmware CVE | `pkg/crypto/tpm_firmware_test.go` | Infineon 4.32.1 → CVE-2017-15361; fresh firmware → no hits; unknown vendor → no hits |
| Module — shared | `pkg/scanner/tpm_test.go` | module identity |
| Module — other | `pkg/scanner/tpm_other_test.go` | non-Linux stub emits skipped-finding |
| Integration | `test/integration/tpm_test.go` (`//go:build integration && linux`) | run against fixture root; assert all three finding types surface |

**Fixture root injection pattern:** mirrors `ebpftrace`'s `/proc/` handling. `tpmfs.Walk(sysRoot string, secRoot string)` takes root paths; production uses `/sys/class/tpm` + `/sys/kernel/security`, tests use `testdata/sysfs-infineon` + a tempdir with a binary log.

## Risks

- **EK cert path variation** — `device/endorsement_key_cert` is the 6.3+ kernel path; older kernels store the cert at TCG NVRAM index `0x01C00002` which sysfs doesn't expose directly. Parser probes `device/endorsement_key_cert` first; absence is not an error.
- **Event log truncation** — sysfs-exposed log can exceed 64KB. Parser uses `io.LimitReader` with a 16MB cap; overflow → `UNSAFE` finding noting truncation.
- **Vendor ID quirks** — manufacturer 4-char code is sometimes space-padded (`"IFX "`), sometimes packed (`"INTC"`). Lookup normalises.
- **Firmware-version parsing** — vendor-specific. PR #1 handles Infineon + Intel (dotted integers); other vendors fall back to exact string match against CVE entries.
- **Cert with no PublicKey** — some TPMs ship placeholder EK certs with self-signed `subjectPublicKeyInfo` that `x509.ParseCertificate` rejects. On parse failure the EK cert path silently skips (no finding), avoiding hard errors.

## Follow-up PRs

- Active `/dev/tpm0` queries for PCR readouts + TPM2_Quote verification (needs `go-tpm` dep + root)
- Windows TBS API + macOS T2 coverage
- PCR reference-value comparison (policy-engine territory)
- IMA/EVM measured-boot log parsing
- Attestation key (AK) cert chain validation
- Per-vendor firmware-version parsers for Nuvoton/STMicro/Atmel
- TPM2 command-response inspection via uprobes (overlaps with ebpf_trace; coordinate)

## Estimated Effort

~1 day subagent-driven. ~7 tasks:

1. Module skeleton + non-Linux stub + engine/profile/tier wiring
2. `pkg/scanner/internal/tpmfs/` types + sysfs walker + fixture
3. Firmware CVE registry
4. EK cert reader
5. Event log parser
6. Linux scan() driver composing all three + finding builders
7. Integration test + CLAUDE.md + memory
