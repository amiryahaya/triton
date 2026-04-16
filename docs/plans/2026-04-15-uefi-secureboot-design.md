# UEFI Secure Boot Key Inventory — Design

> **Status:** approved scope; ready for implementation plan. Sibling to PR #60 (TPM analyzer) — same pattern, different firmware subsystem.

## Why

Secure Boot is the other half of the hardware root of trust alongside the TPM. Its keys and revocation lists live in NVRAM variables exposed under `/sys/firmware/efi/efivars/`. Two classes of audit gap exist:

- **Weak root-of-trust keys** — PK/KEK/db X.509 certificates whose signing algorithm, key size, or expiry is materially weaker than the hardware they protect. Common findings on older hardware: SHA-1 PK signatures, RSA-2048 PKs from expired CAs.
- **Missing revocations** — the dbx (forbidden signatures DB) must include specific hashes for known exploits (BlackLotus CVE-2023-24932, BootHole CVE-2020-10713, Eclypsium Baton Drop CVE-2022-21894). Systems whose dbx lacks these are vulnerable even with Secure Boot nominally "enabled".

Without this module, Triton classifies a modern Linux server as "Secure Boot = enabled" and moves on. The module adds the inventory + CVE-revocation checks that answer "but is it *actually* locked down?"

## Scope

**In scope (PR #1):**

| Signal | Source |
|---|---|
| SecureBoot state (enabled/disabled) | `/sys/firmware/efi/efivars/SecureBoot-<guid>` (1 byte) |
| SetupMode state (provisioning open/closed) | `/sys/firmware/efi/efivars/SetupMode-<guid>` (1 byte) |
| PK certs (platform key) | `PK-<guid>` — parse EFI_SIGNATURE_LIST, extract X.509 certs |
| KEK certs (key exchange keys) | `KEK-<guid>` — same |
| db certs + hashes (allow list) | `db-<guid>` — cert findings + hash-count summary |
| dbx revocation presence | `dbx-<guid>` — cross-reference against committed CVE hash registry |

**Out of scope (deferred PRs):**

- Shim MokList / MokListX (machine owner keys) — different storage (`/var/lib/shim-signed/mok/`), different scope
- Active EFI variable modification tests
- UEFI firmware version CVE matching (that's `pkg/crypto/tpm_firmware.go`'s neighbour; could land as `uefi_firmware.go` in a follow-up)
- Windows Secure Boot enumeration via `Confirm-SecureBootUEFI` / WMI
- Boot Guard / Boot Policy attestation

## Architecture

```
Engine dispatches uefi module (Linux only)
   ↓
check /sys/firmware/efi/efivars/ exists (silent no-op if not)
   ↓
read + emit state findings:
   SecureBoot bool → SAFE when enabled, TRANSITIONAL when disabled
   SetupMode bool + SecureBoot pair → severity determined by combination
   ↓
per variable in {PK, KEK, db}:
   ReadVariable() strips 4-byte attribute prefix
   ParseSignatureList() walks EFI_SIGNATURE_LIST chain
   for each X.509 cert entry: build finding, classify via ClassifyCryptoAsset + keyquality.Analyze
   ↓
dbx:
   ReadVariable + ParseSignatureList
   compute SHA-256 set of hash entries
   LookupUEFICVEHashes() → report missing revocations as QualityWarnings
   ↓
emit aggregate dbx finding with entry-count + missing-CVE list
```

Non-Linux stub emits single skipped-finding. Comprehensive profile + Pro+ tier (mirrors `tpm` + `ebpf_trace`). No new external deps — EFI variable format parseable with `encoding/binary`; cert parsing uses stdlib `crypto/x509`.

## Package Layout

```
pkg/scanner/uefi.go                       # Module shell (all OS)
pkg/scanner/uefi_linux.go                 # //go:build linux — scan() driver
pkg/scanner/uefi_other.go                 # //go:build !linux — stub
pkg/scanner/uefi_test.go                  # module identity
pkg/scanner/uefi_other_test.go            # //go:build !linux stub behaviour
pkg/scanner/uefi_linux_test.go            # //go:build linux — fixture scan

pkg/scanner/internal/uefivars/
  types.go                                # SignatureEntry, SignatureType enum, GUID constants
  reader.go                               # ReadVariable (strip attributes), ReadBoolVariable
  reader_test.go
  parser.go                               # ParseSignatureList walker
  parser_test.go
  testdata/
    efivars/                              # Binary fixtures — see "Fixture strategy" below

pkg/crypto/uefi_cve_hashes.go             # SHA-256 revocation hash registry
pkg/crypto/uefi_cve_hashes_test.go
```

### Modifications

- `pkg/scanner/engine.go` — factory after `NewTPMModule`
- `pkg/scanner/engine_test.go` — bump count + append `"uefi"` to names list
- `internal/scannerconfig/config.go` — append `"uefi"` to comprehensive Modules + add `UEFIVarRoot string` test-hook field
- `internal/scannerconfig/config_test.go` — NotContains/Contains assertions
- `internal/license/tier.go` — append `"uefi"` to Pro+ allowlist
- `pkg/scanner/doctor.go` — add UEFI prereq check (Linux + `/sys/firmware/efi` exists)
- `CLAUDE.md` — bullets under `pkg/scanner/` and `pkg/crypto/`

### Boundary

`pkg/scanner/internal/uefivars/` is a pure parser — zero domain-string emission. PQC classification + CVE registry lookups + Finding construction stay in `pkg/scanner/uefi_linux.go`. Explicitly addresses the `ClassifyEventLog` domain-leakage finding from PR #60 review.

## EFI Variable File Format

Files under `/sys/firmware/efi/efivars/` have this layout:

```
Offset 0:   uint32  Attributes (little-endian; EFI_VARIABLE_NON_VOLATILE etc. — we don't interpret)
Offset 4:   []byte  Value
```

The 4-byte attribute prefix MUST be stripped before passing bytes to the signature-list parser. Code uses a named constant `efiAttributesPrefixLen = 4` to prevent silent drift.

For state variables (`SecureBoot`, `SetupMode`) the Value is exactly 1 byte (`0x00` or `0x01`); anything else is malformed and reported as an error.

## EFI_SIGNATURE_LIST Format

Per UEFI spec §32.4.1. A variable's Value is a chain of zero or more `EFI_SIGNATURE_LIST` records:

```
EFI_SIGNATURE_LIST:
  SignatureType        EFI_GUID    (16 bytes)    — X.509 or SHA-256 etc.
  SignatureListSize    uint32                     — total size of THIS list (header + data)
  SignatureHeaderSize  uint32                     — size of optional header after this struct (usually 0)
  SignatureSize        uint32                     — size of each signature entry inside this list
  SignatureHeader      [SignatureHeaderSize]byte  — optional, usually absent
  Signatures           [N]EFI_SIGNATURE_DATA      — N = (SignatureListSize - 28 - SignatureHeaderSize) / SignatureSize

EFI_SIGNATURE_DATA:
  SignatureOwner       EFI_GUID    (16 bytes)    — source identifier
  SignatureData        [SignatureSize-16]byte    — DER cert OR hash
```

Signature type GUIDs we handle:
- `EFI_CERT_X509_GUID` = `a5c059a1-94e4-4aa7-87b5-ab155c2bf072` → DER cert in SignatureData
- `EFI_CERT_SHA256_GUID` = `c1c41626-504c-4092-aca9-41f936934328` → 32-byte hash in SignatureData

Other types (SHA-1, RSA-2048 signatures) are recognised but skipped for classification in PR #1 — they'd need their own handlers. Parser emits them as `SignatureEntry{Type: "unknown", ...}` with a Debug warning so coverage gaps don't go silent.

## CVE Hash Registry

`pkg/crypto/uefi_cve_hashes.go`:

```go
type UEFIRevocation struct {
    CVE         string    // e.g. "CVE-2023-24932"
    SHA256Hex   string    // 64-char lowercase hex
    Description string
    Severity    string    // CRITICAL | HIGH | MEDIUM
    Source      string    // provenance: "Microsoft Security Update", "LVFS dbx update", etc.
}

// LookupMissingRevocations returns entries from the registry whose hashes
// are NOT present in the provided dbx hash set.
func LookupMissingRevocations(dbxHashes map[string]bool) []UEFIRevocation
```

**Initial registry (PR #1) — 3 entries, all sourced from Microsoft's published dbx update hashes:**

| CVE | Description | Severity | Source |
|---|---|---|---|
| CVE-2023-24932 | BlackLotus UEFI bootkit (Windows Boot Manager) | CRITICAL | Microsoft KB5025885 |
| CVE-2020-10713 | BootHole (GRUB2 buffer overflow → Secure Boot bypass) | CRITICAL | UEFI Revocation List updates 2020-07-29 + 2022-05-09 |
| CVE-2022-21894 | Eclypsium Baton Drop (Windows Boot Manager) | HIGH | Microsoft KB5022497 |

**Provenance note in comments:** each hash entry carries a link to the upstream advisory. The registry is intentionally conservative — adding a wrong hash would produce false negatives (a system appears patched when it isn't). Expansion to 5+ CVEs (adding CVE-2023-40547 shim httpboot, etc.) deferred to a follow-up after the data source pipeline is validated.

**Data source pipeline:** manually transcribed from Microsoft/UEFI Forum advisories for PR #1. A future PR will add an import script that consumes `dbxupdate.bin` from https://uefi.org/revocationlistfile and generates the Go source, reducing drift.

## Finding Shapes

### State findings (always emitted when /sys/firmware/efi/efivars exists)

```json
{
  "module": "uefi",
  "source": {
    "type": "file",
    "path": "/sys/firmware/efi/efivars/SecureBoot-...",
    "detectionMethod": "efivars-state",
    "evidence": "SecureBoot=1"
  },
  "cryptoAsset": {
    "algorithm": "Secure-Boot-State",
    "library": "UEFI",
    "language": "Firmware",
    "function": "Boot integrity",
    "pqcStatus": "SAFE"   // SAFE when enabled, TRANSITIONAL when disabled
  }
}
```

**SetupMode severity rule** (stateful, paired with SecureBoot):
- `SecureBoot=1, SetupMode=0` → SAFE (normal production state)
- `SecureBoot=0, SetupMode=0` → TRANSITIONAL (locked but disabled; user choice)
- `SecureBoot=0, SetupMode=1` → HIGH warning (not yet provisioned; any key may be written — acceptable only on an unprovisioned machine)
- `SecureBoot=1, SetupMode=1` → CRITICAL (logically impossible per spec; firmware bug or tampering)

### Cert findings (one per X.509 cert across PK/KEK/db)

Standard cert-scanner shape. `Source.Path` identifies the variable + list-index + cert-index for traceability:

```
/sys/firmware/efi/efivars/PK-<guid>  [list=0, cert=0]
/sys/firmware/efi/efivars/db-<guid>  [list=2, cert=1]
```

`Evidence` includes the SignatureOwner GUID (e.g., Microsoft = `77fa9abd-0359-4d32-bd60-28f4e78f784b`) so auditors can track attribution.

Each cert flows through `crypto.ClassifyCryptoAsset` + `keyquality.Analyze`. A SHA-1-signed PK finds up as `PQCStatus=DEPRECATED` with existing sigalg classification; a ROCA-suspected cert picks up a QualityWarning automatically.

### dbx aggregate finding

```json
{
  "module": "uefi",
  "source": {
    "path": "/sys/firmware/efi/efivars/dbx-...",
    "detectionMethod": "efivars-dbx",
    "evidence": "1247 entries; missing 2 CVE revocations"
  },
  "cryptoAsset": {
    "algorithm": "UEFI-dbx",
    "library": "UEFI",
    "language": "Firmware",
    "function": "Revocation list",
    "pqcStatus": "UNSAFE",  // if any CRITICAL CVE revocation is missing
    "qualityWarnings": [
      {"code": "DBX-MISSING", "severity": "CRITICAL",
       "cve": "CVE-2023-24932",
       "message": "BlackLotus UEFI bootkit revocation missing from dbx"}
    ]
  }
}
```

`PQCStatus` derivation: worst severity among missing revocations (CRITICAL → UNSAFE, HIGH → DEPRECATED, MEDIUM → TRANSITIONAL, none missing → SAFE). Uses the same `worstSeverity` helper pattern added in PR #60.

## Engine Wiring

| Property | Value |
|---|---|
| Module name | `uefi` |
| Category | `model.CategoryPassiveFile` |
| Target | `model.TargetFilesystem` |
| Profile | `comprehensive` only |
| Tier | Pro+ |
| Prereq | Linux + `/sys/firmware/efi` exists (silent no-op when absent) |
| New CLI flags | none |
| Doctor check | one-line presence check |

## Tests

| Layer | File | What |
|---|---|---|
| Unit — variable reader | `uefivars/reader_test.go` | strips 4-byte prefix; bool variables; missing files |
| Unit — signature list parser | `uefivars/parser_test.go` | X.509 cert entries; SHA-256 hash entries; chained lists; truncation rejection |
| Unit — CVE registry | `pkg/crypto/uefi_cve_hashes_test.go` | known-missing produces warning; all-present returns empty |
| Module shared | `uefi_test.go` | identity |
| Module Linux | `uefi_linux_test.go` | scan fixture tree; asserts state + cert + dbx findings |
| Module other | `uefi_other_test.go` | skipped-finding stub |
| Integration | `test/integration/uefi_test.go` | `//go:build integration`, runtime skip non-Linux |

### Fixture strategy

Binary fixtures synthesised via a committed Go helper (`uefivars/testdata/generate_test.go`, build-tag `ignore`) that:
1. Writes tiny state variables (1-byte body + 4-byte attribute prefix)
2. Builds an EFI_SIGNATURE_LIST containing a freshly-generated RSA-2048 cert (for PK/KEK/db tests)
3. Builds a dbx fixture with one known-CVE hash and one unknown hash

Committed binary outputs under `testdata/efivars/` match real kernel layout file names. The helper is regenerated deterministically — no `dotnet`/`efi-setup` toolchain needed.

**Coverage target:** ≥ 80% on `pkg/scanner/internal/uefivars/` and `pkg/crypto/`. Explicit table tests for the SetupMode/SecureBoot combination matrix (4 cases).

## Risks

- **efivarfs immutability flag** — some distros mount efivarfs with files `chattr +i`. Our scanner reads only; documented in code comment. No write attempts.
- **Attribute-prefix silent drift** — the 4-byte prefix is easy to forget. Named constant + explicit test covers.
- **Multiple certs per SIGNATURE_LIST** — the parser correctly iterates all entries per list; traceability via `Source.Path` suffix `[list=N, cert=M]`.
- **CVE hash registry accuracy** — conservative 3-entry start. Wrong hash → false negative (dangerous). All entries carry source provenance in code comments; a future PR adds automated import from UEFI Revocation List Files.
- **SetupMode on fresh provisioning workstations** — the stateful severity matrix correctly treats `SecureBoot=0, SetupMode=1` as HIGH (not CRITICAL), recognising this is normal pre-provisioning state.
- **Per-cert Source.Path convention** — the `[list=N, cert=M]` suffix lives in Source.Path string. If downstream consumers parse Source.Path for the filesystem path, they'll trip over the suffix. Alternative: put the index in Evidence. Design chooses Path for grep-ability; implementer should note this in report-rendering code.

## Follow-up PRs

- UEFI firmware version CVE matching (sibling to `tpm_firmware.go`)
- Automated CVE hash import from https://uefi.org/revocationlistfile `dbxupdate.bin`
- Shim MokList / MokListX scanning
- Windows Secure Boot via WMI
- Handlers for RSA-2048-signed and SHA-1 signature types in parser (currently emitted as "unknown" with debug warning)
- Active EFI variable tamper detection (sig-check the Authenticated Variables)
- Boot Guard / Boot Policy attestation

## Estimated Effort

~1 day subagent-driven. ~7 tasks:

1. Module skeleton + non-Linux stub + engine wiring (mirrors TPM Task 1)
2. `uefivars/` types + reader (attribute-prefix strip, bool)
3. CVE hash registry (`pkg/crypto/uefi_cve_hashes.go`)
4. EFI_SIGNATURE_LIST parser
5. Fixture generator + committed binaries
6. Linux scan() driver composing state + cert + dbx findings
7. Integration test + doctor.go entry + CLAUDE.md + memory
