# Key Quality Analyzer — Design

> **Status:** approved scope; ready for implementation plan. Finds broken keys among SAFE-classified findings — complements existing algorithm-family PQC classification with material-level quality audits.

## Why

Every scanner Triton ships today classifies crypto assets by *algorithm family*: an RSA-2048 key with a strong algorithm gets `PQCStatus: TRANSITIONAL` regardless of whether its key material is actually sound. That produces false negatives on well-known catastrophic failure modes:

- **ROCA (CVE-2017-15361)** — Infineon-generated RSA keys with compromised prime structure, millions affected across TPMs and national ID cards.
- **Debian weak PRNG (CVE-2008-0166)** — 32,768 predictable keys per (arch, size) pair from the 2006-2008 OpenSSL bug.
- **Small prime factors** — malformed or sabotaged RSA keys whose modulus is trivially factorable.
- **Claimed-vs-actual key size mismatch** — honest parse bugs or malicious labelling ship keys that don't match their declared size.

For a tool auditing PQC readiness, "you have RSA-2048 in production" is useful but incomplete when some of those keys are effectively zero-security. This PR adds four fast, offline, per-key checks to surface these failures as quality warnings on existing findings.

## Scope

**In scope (PR #1):**

| Check | Method |
|---|---|
| ROCA | Nemec et al. discriminant test on RSA modulus |
| Debian weak keys | SHA-1 fingerprint lookup against embedded blocklist (RSA-1024, RSA-2048, DSA-1024, DSA-2048) |
| Small prime factors | Trial-divide RSA modulus by primes ≤ 10000 |
| Size mismatch | Compare reported `keySize` vs actual modulus bit length |
| Integration | Inline call from existing `key.go` + `certificate.go`; warnings attached to `CryptoAsset.QualityWarnings` |
| HTML report | ⚠ badge + warning text below CBOM row |
| CycloneDX | Emit warnings as vulnerability refs where CVE exists |

**Out of scope (deferred PRs):**
- Shared-prime GCD (pairwise cross-key analysis, O(n²) compute)
- Full Miller-Rabin primality of factors (needs private key material)
- DSA nonce reuse (needs signed-message corpus)
- ECDSA weak/twisted curve parameter validation
- Online blocklist fetch (haveibeenpwned-keys); offline-only for v1
- Policy engine integration (feeding warnings into `.policy.yaml` rules)
- Key rotation hints from cert expiry

## Architecture

```
Existing key.go / certificate.go parses a public key
   ↓
  keyquality.Analyze(pub, algo, keySize) []Warning
   ↓              ↓              ↓              ↓
  ROCA       Debian blocklist  Small primes  Size check
   ↓              ↓              ↓              ↓
  Warning list → flatten to []string → CryptoAsset.QualityWarnings
   ↓
HTML renderer shows ⚠ + warning text; CycloneDX emits vuln refs
```

No new scanner module. No engine/profile/tier changes. Quality checks run whenever `certificates` or `keys` modules run, across all tiers. Performance budget: <4ms per key, ~40s for a scan with 10K certs.

## Package Layout

```
pkg/crypto/keyquality/
  keyquality.go                  # Public API: Analyze(pub, algo, keySize) []Warning; Warning type
  keyquality_test.go             # Composed integration tests across checkers
  roca.go                        # ROCA discriminant test
  roca_test.go
  debian.go                      # Debian blocklist lookup + embedded gz data
  debian_test.go
  smallprime.go                  # Trial division by small primes
  smallprime_test.go
  sizecheck.go                   # Claimed vs actual key size
  sizecheck_test.go
  testdata/
    roca-vuln-modulus.hex        # Known-vulnerable Infineon modulus (from Nemec test vectors)
    debian-weak-rsa2048.pem      # One known-weak fingerprint from Bello's list
    blocklist-rsa-1024.gz        # ~8KB gzipped SHA-1 fingerprints
    blocklist-rsa-2048.gz
    blocklist-dsa-1024.gz
    blocklist-dsa-2048.gz
```

### Modified files

- `pkg/model/types.go` — add `QualityWarnings []string \`json:"qualityWarnings,omitempty"\`` to `CryptoAsset`.
- `pkg/scanner/key.go` — after parsing each key, call `keyquality.Analyze` and attach warnings.
- `pkg/scanner/certificate.go` — same; extract the public key via `x509.Certificate.PublicKey` and analyze.
- `pkg/report/generator.go` — HTML: ⚠ badge + warning list under CBOM rows that have quality warnings.
- `pkg/report/cyclonedx.go` — emit `properties` or `vulnerability` ref per warning with a CVE.
- `CLAUDE.md` — add bullet under `pkg/crypto/` for `keyquality/`.

## API

```go
// Warning is one key-material quality failure.
type Warning struct {
    Code     string // "ROCA", "DEBIAN-WEAK", "SMALL-PRIME", "SIZE-MISMATCH"
    Severity string // "CRITICAL", "HIGH", "MEDIUM"
    Message  string // Human-readable description
    CVE      string // Optional, e.g. "CVE-2017-15361"
}

// Analyze runs all applicable checks on a parsed public key.
// algo is the classification's algorithm string ("RSA", "DSA", "ECDSA", ...).
// keySize is the reported key size from the caller.
// Non-applicable checks silently skip (e.g., ROCA only runs on RSA keys).
func Analyze(pub crypto.PublicKey, algo string, keySize int) []Warning
```

Warnings are flattened to strings for `CryptoAsset.QualityWarnings`:
```
"[CRITICAL] ROCA vulnerability (CVE-2017-15361): modulus matches Infineon weak-prime structure"
```

## Checker Details

### ROCA discriminant (`roca.go`)

Port of `crocs-muni/roca` discriminant check. The test: for each of 17 small primes from a fixed generator set, check whether the modulus matches the form `65537^a · 2^b (mod prime)` that Infineon primes produce. Any mismatch → key is NOT ROCA. All matches → key IS ROCA (or the ~0.05% false positive).

- Input: `*rsa.PublicKey`
- Output: zero warnings if not-ROCA, one `CRITICAL` warning if suspected
- Per-key cost: ~0.5ms (17 modular exponentiations on ~2048-bit modulus)
- Reference: Nemec et al. "The Return of Coppersmith's Attack: Practical Factorization of Widely Used RSA Moduli" (CCS 2017)

### Debian blocklist (`debian.go`)

Four embedded `.gz` blobs from the Debian `openssl-blacklist` package: SHA-1 fingerprints of every public key the broken PRNG could produce. Load once at package init into four `map[[20]byte]struct{}` sets.

Lookup:
1. Marshal public key to DER.
2. Compute SHA-1(DER).
3. Check the appropriate set (RSA-1024, RSA-2048, DSA-1024, DSA-2048).

Per-key cost: <0.1ms. Binary size impact: ~32KB gzipped.

### Small prime trial division (`smallprime.go`)

For RSA, trial-divide modulus by every prime ≤ 10000 (1229 primes). Any hit → key is catastrophically broken. Returns specific factor in warning message.

- Per-key cost: <1ms
- Table of primes is generated once (committed const)

### Size mismatch (`sizecheck.go`)

Compare `keySize` parameter (from caller) against `pub.(*rsa.PublicKey).N.BitLen()` (actual modulus bits).

Rule set:
- Tolerance: ±1 bit (catches honest 2047-bit keys that are legitimate)
- Threshold: if `|claimed - actual| ≥ 16`, emit `HIGH` warning with both values
- Special case: claimed ≥ 2048 but actual < 1024 → `CRITICAL`

## Warning Output Shape on CryptoAsset

```json
{
  "algorithm": "RSA",
  "keySize": 2048,
  "pqcStatus": "TRANSITIONAL",
  "qualityWarnings": [
    "[CRITICAL] ROCA vulnerability (CVE-2017-15361): modulus matches Infineon weak-prime structure",
    "[HIGH] Size mismatch: claimed 2048 bits, actual modulus 1024 bits"
  ]
}
```

The `PQCStatus` is NOT modified — separation of concerns. Algorithm-family classification stays in `pkg/crypto/ClassifyAlgorithm`. Quality is orthogonal.

## HTML Report

Per-finding row in the CBOM table gains a ⚠ badge when `len(QualityWarnings) > 0`. Below the row, a small details block lists warnings. Visual treatment mirrors the existing hybrid-badge pattern.

CSS additions (inline, ~6 lines) sufficient; no JS needed.

## CycloneDX

For warnings with non-empty CVE, emit a `vulnerabilities` entry on the component:
```json
{
  "id": "CVE-2017-15361",
  "ratings": [{"severity": "critical"}],
  "source": {"name": "NVD"}
}
```
For warnings without a CVE (SIZE-MISMATCH), emit a `properties` entry:
```json
{
  "name": "triton:quality-warning",
  "value": "[HIGH] Size mismatch: ..."
}
```

## Tests

| Layer | File | Coverage |
|---|---|---|
| Unit — ROCA | `roca_test.go` | known Infineon modulus triggers; fresh RSA-2048 does not; false-positive rate ≤ 0.1% over 1000 random moduli |
| Unit — Debian | `debian_test.go` | known-weak fingerprint hits; fresh key does not; DSA fingerprint hits DSA list not RSA |
| Unit — Small prime | `smallprime_test.go` | `p · q` where p is a small prime triggers with specific factor; real RSA-2048 does not |
| Unit — Size | `sizecheck_test.go` | 2048-claimed/1024-actual triggers; 2047-claimed/2047-actual does not (off-by-1 tolerance) |
| Unit — Analyze | `keyquality_test.go` | ECDSA keys → no RSA checks run; all four RSA checks compose; zero warnings on a clean key |
| Integration | `pkg/scanner/key_test.go` / `certificate_test.go` | parse fixture ROCA PEM → finding has QualityWarnings |

Coverage target: ≥ 85% on `pkg/crypto/keyquality/`.

## Fixtures

- `roca-vuln-modulus.hex` — published Nemec test vector (public domain)
- `debian-weak-rsa2048.pem` — regenerated RSA key from Bello's well-known seeds (public)
- Blocklist `.gz` files — sourced from `openssl-blacklist` Debian package (CC0)

Generator scripts for regeneration committed but NOT run at test time.

## Risks

- **ROCA false positives** — documented ~0.05% rate per the paper. Warning text uses "suspected" language and references the CVE for manual verification.
- **Debian blocklist data provenance** — we ship a committed copy. An updated blocklist would require a PR to refresh. Not expected (the PRNG bug was fixed in 2008).
- **Non-RSA keys** — ROCA/Debian/small-prime all skip silently; size-mismatch runs universally. Explicitly tested.
- **Public-key extraction from certs** — type switch handles `*rsa.PublicKey` / `*ecdsa.PublicKey` / `ed25519.PublicKey`; unknown types skip all RSA-specific checks.
- **Performance on huge scans** — 4ms × 10K keys = 40s worst case. Acceptable; no gating.

## Follow-up PRs

- Shared-prime GCD analysis (batch post-processing, not per-key)
- Online blocklist fetch (haveibeenpwned-keys)
- ECDSA weak-curve validation
- Policy engine rule for "reject scan if any CRITICAL quality warning"
- Key rotation hints via cert age + expiry window
- Full Miller-Rabin primality test when private keys are available (filesystem key scan, not cert extraction)

## Estimated Effort

~1 day subagent-driven. ~7 tasks:

1. Package skeleton + `Warning`/`Analyze` composed API
2. Size mismatch checker (simplest; establishes the integration test pattern)
3. Small prime trial division
4. ROCA discriminant test (+ committed test vectors)
5. Debian blocklist (+ embedded `.gz` loading)
6. Wire into `key.go` + `certificate.go` + model field
7. HTML + CycloneDX reporting + CLAUDE.md + memory
