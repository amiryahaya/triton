# PCert Parity Sprint — Design Spec

**Date:** 2026-04-16
**Goal:** Close the 8 cryptographic asset discovery gaps between Triton and PCert 4.5.5 so Triton produces equivalent or greater finding counts on the same target.

## Background

PCert (Projekt Zertifikat, Data-Warehouse GmbH) is a Java/BouncyCastle enterprise certificate discovery and lifecycle management tool. When scanning the same host, PCert produces significantly more findings than Triton because it:

1. Fully extracts certificates from Java keystores (JKS/JCEKS/BKS)
2. Scans inside archives (JAR/ZIP/TAR)
3. Properly parses PKCS#7 certificate bundles
4. Enumerates all Windows certificate stores (not just Root)
5. Tries more passwords on PKCS#12 containers
6. Reports encrypted private keys instead of silently skipping them
7. Detects JCEKS/BKS keystore formats
8. Scans remote filesystems over SSH

Triton's advantage is breadth (30 scanner modules, PQC classification, SBOM/CBOM output, policy engine). This sprint closes the depth gap on certificate/key discovery without touching Triton's existing strengths.

## Approach

Enhance existing modules (Approach A). Minimal new files — follows existing patterns. One new module (`archive.go`), four enhanced modules (`certificate.go`, `key.go`, `certstore.go`), cross-cutting SSH compatibility.

## Section 1: JKS/JCEKS/BKS Full Keystore Parsing

**File:** `pkg/scanner/certificate.go`

### Current State

`certificate.go` detects JKS by magic bytes (`0xFEEDFEED`) but emits a single opaque "container" finding. JCEKS and BKS are not detected.

### Changes

- **JKS/JCEKS parsing**: Shell out to `keytool -list -rfc -keystore <path> -storepass <pw>`. Same approach already used in `certstore.go` for cacerts. The output is PEM — feed through existing `parsePEMCerts()` logic.
- **BKS parsing**: Use `keytool` with `-storetype BKS -providerpath <bcprov.jar> -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider`. Only if BouncyCastle JAR is discoverable on the host. If not, emit a "tool unavailable" finding (same pattern as `codesign_pe_jar.go`).
- **Password list**: Try passwords in order: user-configured (`--keystore-passwords` / `TRITON_KEYSTORE_PASSWORDS` comma-separated), then built-in defaults (`""`, `"changeit"`, `"changeme"`, `"password"`, `"secret"`, `"triton"`, `"server"`, `"client"`, `"keystore"`).
- **keytool discovery**: Reuse JDK discovery logic from `certstore.go` (`discoverJavaCacerts` paths to derive keytool binary path). Fall back to `keytool` on PATH.
- **Safety**: `cmdRunnerLimited` + 30s timeout (same as `certstore.go`). Cap stdout at 32MB.
- **Fail-open**: If no password works, emit a finding with `Evidence: "password-protected keystore (could not decrypt)"` and classification `Unknown`.
- **Storetype flag**: `-storetype JKS` for `.jks`, `-storetype JCEKS` for `.jceks`, `-storetype BKS` for `.bks`. For `.keystore`/`.truststore`, omit flag (let keytool auto-detect).

### Finding Impact

A single cacerts file: 1 opaque finding becomes ~130 individual cert findings. Each `.jks` with N certs becomes N findings.

## Section 2: Archive Extraction (JAR/ZIP/TAR)

**File:** New `pkg/scanner/archive.go`

### Current State

Triton walks the filesystem and only processes individual files. Certificates, keys, and keystores inside archives are invisible.

### Changes

- **New module**: `ArchiveModule` implementing `Module`, `FileReaderAware`, `FileMetrics`.
- **File matching**: `.jar`, `.war`, `.ear`, `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`.
- **Two-level extraction**: Opens the archive, scans contents for cert/key/keystore files. If a nested archive is found (e.g., JAR inside WAR), opens that too. Stops at level 2. No deeper recursion.
- **In-memory extraction**: Go stdlib `archive/zip` and `archive/tar` + `compress/gzip` / `compress/bzip2`. No temp files on disk.
- **Safety guards**:
  - Per-entry size cap: 50MB (skip entries larger)
  - Total extraction cap: 256MB per archive (stop extracting after)
  - Max entries per archive: 10,000 (zip bomb protection)
  - Nesting depth hard-capped at 2
- **Delegates to existing parsers**: Extracted bytes are fed through `parseCertificateFile()` and `parseKeyFile()` logic from `certificate.go` and `key.go`. Archive module discovers, existing parsers classify.
- **Finding paths**: Reported as `outer.war!/inner.jar!/cert.pem` (bang-separated, standard JAR URL convention).
- **Profile gating**: Standard + Comprehensive profiles only (not Quick).
- **FileReaderAware**: Uses injected reader for archive file I/O so SSH remote scanning works.

### Finding Impact

A typical Java webapp WAR with 30 JARs containing `META-INF/` certs/keystores: 0 findings becomes potentially dozens.

## Section 3: PKCS#7 Proper Parsing

**File:** `pkg/scanner/certificate.go`

### Current State

`.p7b`/`.p7c` files are extension-matched but parsing falls through to crude PEM/DER single-cert fallback. A PKCS#7 bundle with a 5-cert chain yields 0-1 findings.

### Changes

- **New dependency**: `go.mozilla.org/pkcs7` — parses SignedData structures, exposes `.Certificates` slice.
- **Parse flow in `parseCertificateFile()`**: For `.p7b`/`.p7c` files, try PKCS#7 parse first (both PEM-wrapped and raw DER). Each certificate in the bundle becomes its own finding. Fall back to current PEM/DER logic only if PKCS#7 parse fails.
- **No new module** — parser enhancement inside existing certificate module.

### Finding Impact

A `.p7b` with a 5-cert chain: 5 findings instead of 0-1.

## Section 4: Windows Intermediate/Personal Certificate Stores

**File:** `pkg/scanner/certstore.go`

### Current State

Only reads `Cert:\LocalMachine\Root` (trust anchors). Intermediate CAs and personal/machine certs are missed.

### Changes

- **New stores**: `Cert:\LocalMachine\CA` (intermediate CAs), `Cert:\LocalMachine\My` (machine personal certs), `Cert:\CurrentUser\Root` (user trust anchors), `Cert:\CurrentUser\My` (user personal certs).
- **Implementation**: Same PowerShell + `cmdRunnerLimited` pattern, one call per store. Each store gets a distinct `sourcePath` (e.g., `os:certstore:windows:LocalMachine\CA`).
- **Purpose field differentiation**: "Intermediate CA (Windows)", "Machine certificate (Windows)", "User trust anchor (Windows)", "User certificate (Windows)".
- **Safety**: Same 16MB stdout cap and 30s timeout per store. 5 total store calls (was 1).
- **No new module** — enhancement to existing `certstore.go`.

### Finding Impact

Typical enterprise Windows host: 30-50 intermediate CAs + 5-10 personal certs = 40-60 new findings.

## Section 5: Expanded PKCS#12 Password Support

**File:** `pkg/scanner/certificate.go`

### Current State

`parsePKCS12()` tries only 3 hardcoded passwords: `""`, `"changeit"`, `"changeme"`. Custom-protected containers yield 0 findings.

### Changes

- **Built-in dictionary expansion**: `"password"`, `"secret"`, `"triton"`, `"server"`, `"client"`, `"keystore"`. Total built-in list: ~10 passwords.
- **User-configured passwords**: New `--keystore-passwords` CLI flag and `TRITON_KEYSTORE_PASSWORDS` env var (comma-separated). Prepended to built-in list.
- **Shared password source**: `keystorePasswords()` helper merges user + built-in lists. Used by both PKCS#12 parsing and keytool-based keystore parsing (Section 1). Single source of truth.
- **Fail-open**: If no password works, emit a finding with `Evidence: "password-protected container (could not decrypt)"` and classification `Unknown`. Container is visible even if unopenable.
- **Performance**: Short-circuit on first success. ~1ms per PKCS#12 decode attempt, ~10ms total for 10 passwords.

### Finding Impact

Previously invisible password-protected containers now produce either full cert findings (password matches) or a "locked container" finding (password fails). Zero silent misses.

## Section 6: Encrypted Private Key Detection

**File:** `pkg/scanner/key.go`

### Current State

Encrypted PEM private keys (`BEGIN ENCRYPTED PRIVATE KEY`, RFC 1423 encrypted `BEGIN RSA PRIVATE KEY`) are silently skipped. No finding emitted.

### Changes

- **RFC 1423 detection**: When PEM block has `Proc-Type: 4,ENCRYPTED` header, emit a finding. Parse `DEK-Info` header for encryption algorithm (e.g., `DEK-Info: AES-256-CBC,<iv>` reports "AES-256-CBC encrypted RSA private key").
- **PKCS#8 encrypted**: PEM type `ENCRYPTED PRIVATE KEY` — parse outer ASN.1 to extract encryption OID without decrypting.
- **OpenSSH encrypted**: `BEGIN OPENSSH PRIVATE KEY` with `bcrypt` KDF — detect via cipher name in binary header. Report `Unknown (encrypted OpenSSH)` with cipher noted in evidence.
- **Finding fields**: `Algorithm` = outer key type if detectable from PEM header (e.g., `RSA`), `Evidence` = encryption details, `KeySize` = 0 (unknown without decryption).
- **PQC classification**: `UNKNOWN` — keys exist, can't assess, need manual review.
- **No decryption attempted** — security boundary. Just surface the finding.

### Finding Impact

Every encrypted `.key` file goes from invisible to a visible finding flagged for review.

## Section 7: JCEKS/BKS Format Detection

**File:** `pkg/scanner/certificate.go`

### Current State

Only `.jks` is matched by `isCertificateFile()`. JCEKS, BKS, and generic keystore files are invisible.

### Changes

- **New extensions in `isCertificateFile()`**: `.jceks`, `.bks`, `.uber`, `.keystore`, `.truststore`.
- **Magic byte detection**:
  - JCEKS: `0xCECECECE` (first 4 bytes)
  - BKS v1: BouncyCastle store marker bytes
  - Unknown format: try keytool anyway (auto-detect)
- **keytool storetype flag**: `-storetype JCEKS` for `.jceks`, `-storetype BKS` for `.bks` (with BouncyCastle provider if available). For `.keystore`/`.truststore`, omit flag.
- **Fallback**: If keytool can't parse, emit "detected but unparseable keystore" finding.
- **No new module** — extends `certificate.go` alongside Section 1.

### Finding Impact

Enterprise Java apps using JCEKS (JMS/JDBC credential stores) and BouncyCastle keystores become visible.

## Section 8: SSH Remote FS Compatibility

**Scope:** Cross-cutting concern across Sections 1-7.

### Current State

`fsadapter.SshReader` already implements the full `FileReader` interface. The engine injects it into `FileReaderAware` modules. `network-scan` CLI command provides the user-facing workflow.

### Changes

- **`archive.go`**: Must implement `FileReaderAware`. Read archive bytes via `reader.ReadFile()`, process in-memory with `archive/zip` from `bytes.Reader`. Never use `os.Open` or `zip.OpenReader`.
- **`certificate.go` keytool shelling**: When `reader` is non-local (SSH), keytool is not available locally for the remote file. Two options:
  - If module also implements `CommandRunnerAware` and a runner is injected, run `keytool` on the remote host.
  - Otherwise, read raw keystore bytes, emit "keystore detected, requires keytool on target host for full parsing" finding.
- **`certstore.go` Windows stores**: Uses `cmdRunner` for local PowerShell. Remote Windows cert store scanning remains local-only for now (acceptable — PCert also requires local/agent access for registry stores).
- **`key.go` encrypted key detection**: Pure byte parsing, already uses `reader.ReadFile()` via walker. No changes needed — works over SSH automatically.

## New CLI Flag

```
--keystore-passwords string   Comma-separated passwords to try on keystores/PKCS#12 (env: TRITON_KEYSTORE_PASSWORDS)
```

Added to `cmd/root.go` alongside existing scan flags.

## New Dependency

```
go.mozilla.org/pkcs7    # PKCS#7 SignedData parser (Section 3)
```

## Profile Gating

| Module/Feature | Quick | Standard | Comprehensive |
|---|---|---|---|
| JKS/JCEKS/BKS parsing (Section 1) | Yes (already in cert module) | Yes | Yes |
| Archive extraction (Section 2) | No | Yes | Yes |
| PKCS#7 parsing (Section 3) | Yes (already in cert module) | Yes | Yes |
| Windows extra stores (Section 4) | Yes (already in certstore) | Yes | Yes |
| Password expansion (Section 5) | Yes | Yes | Yes |
| Encrypted key detection (Section 6) | Yes (already in key module) | Yes | Yes |
| JCEKS/BKS detection (Section 7) | Yes (already in cert module) | Yes | Yes |

## Testing Strategy

- **TDD throughout**: Red, Green, Refactor for every change.
- **Unit tests**: Per-section in existing `_test.go` files + new `archive_test.go`.
  - Keystore parsing: embed small JKS/JCEKS test fixtures, mock keytool via `cmdRunner`.
  - Archive extraction: create in-memory ZIP/TAR with embedded certs, test 2-level nesting, test zip bomb guards.
  - PKCS#7: embed `.p7b` test fixture with multi-cert chain.
  - Windows stores: mock PowerShell output for each store path.
  - Password expansion: test priority order, env var parsing, fail-open behavior.
  - Encrypted keys: embed encrypted PEM fixtures (RFC 1423, PKCS#8, OpenSSH).
- **Integration tests**: New test file `test/integration/pcert_parity_test.go` — end-to-end scan of a directory containing all target file types, verify finding counts match expectations.
- **Coverage target**: >80% per section.

## Module Count

After this sprint: 31 modules (30 existing + 1 new `archive`).

## Files Changed

| File | Change Type |
|---|---|
| `pkg/scanner/certificate.go` | Enhanced (Sections 1, 3, 5, 7) |
| `pkg/scanner/key.go` | Enhanced (Section 6) |
| `pkg/scanner/certstore.go` | Enhanced (Section 4) |
| `pkg/scanner/archive.go` | New (Section 2) |
| `pkg/scanner/archive_test.go` | New |
| `pkg/scanner/certificate_test.go` | Enhanced |
| `pkg/scanner/key_test.go` | Enhanced |
| `pkg/scanner/certstore_test.go` | Enhanced |
| `pkg/scanner/engine.go` | Register archive module |
| `cmd/root.go` | `--keystore-passwords` flag |
| `internal/scannerconfig/config.go` | `KeystorePasswords []string` field |
| `test/integration/pcert_parity_test.go` | New integration tests |
| `go.mod` / `go.sum` | `go.mozilla.org/pkcs7` |

## Out of Scope

- Certificate lifecycle management (exchange, revoke, SCEP, CMC) — PCert's core differentiator, not relevant for Triton's assessment mission.
- PCAP file scanning — niche use case, low ROI.
- Android USB scanning — no Go library support, very niche.
- FTPS scanning — low demand, can add later if needed.
- Decrypting encrypted private keys — security boundary, report presence only.
