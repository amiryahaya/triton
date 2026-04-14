# ASN.1 OID Byte Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a scanner module that walks executable binaries (ELF/Mach-O/PE) looking for DER-encoded OIDs embedded in read-only data sections, decodes them, classifies via the existing OID registry, and emits Findings — catching crypto that Triton's string/regex matchers miss in stripped or obfuscated binaries.

**Architecture:**
1. Expand `pkg/crypto/oid.go` coverage from ~60 to ~200 OIDs (add symmetric, hash, DH/DSA, curves, Kerberos, PKCS families).
2. Add `pkg/crypto/asn1.go` with exported `FindOIDsInBuffer(b []byte) []FoundOID` that scans arbitrary byte slices for valid DER OID patterns (`0x06 <len> <content>`) with false-positive filtering.
3. New scanner module `pkg/scanner/asn1_oid.go` that (a) detects binary format, (b) extracts read-only sections via `debug/elf`, `debug/macho`, `debug/pe`, (c) runs the OID pattern scanner, (d) emits Findings with `DetectionMethod: "asn1-oid"`.
4. Register in engine under the comprehensive profile only (heavy scan); gated to Pro+ license tier.

**Tech Stack:** Go 1.25, stdlib `debug/elf` + `debug/macho` + `debug/pe` (no new deps), existing `pkg/crypto` registry, existing Module interface.

---

## Pre-flight

**Verify current state:**
- [ ] **Step 0: Read `pkg/crypto/oid.go`, `pkg/scanner/engine.go`, `pkg/scanner/binary.go`, `pkg/model/types.go`** to confirm the shapes referenced below still match.

```bash
# Confirm baseline compiles and tests pass before starting
make test
```
Expected: PASS across all packages.

---

## Phase 1 — Expand OID Registry Coverage

The current registry is PQC-heavy (60 entries) but thin on classical/symmetric. Fill out the map so the byte scanner has something to classify against. Split into a separate file to keep `oid.go` readable.

### Task 1: Move existing OID entries out of `init()` into data files

**Files:**
- Modify: `pkg/crypto/oid.go` (remove inline entries from `init()`, keep only init wiring + helper functions)
- Create: `pkg/crypto/oid_data_pqc.go` (NIST PQC + composite entries, extracted from current `init()`)
- Create: `pkg/crypto/oid_data_classical.go` (existing classical entries, extracted)

- [ ] **Step 1: Write failing test that asserts registry size ≥ 60 after refactor**

Create `pkg/crypto/oid_data_test.go`:
```go
package crypto

import "testing"

func TestOIDRegistryMinimumCoverage(t *testing.T) {
    if len(oidRegistry) < 60 {
        t.Fatalf("expected registry size >= 60, got %d", len(oidRegistry))
    }
    // Spot-check critical entries
    must := []string{
        "2.16.840.1.101.3.4.4.1",   // ML-KEM-512
        "2.16.840.1.101.3.4.3.17",  // ML-DSA-44
        "1.2.840.113549.1.1.11",    // sha256WithRSAEncryption
        "1.3.101.112",              // Ed25519
    }
    for _, oid := range must {
        if _, ok := oidRegistry[oid]; !ok {
            t.Errorf("missing critical OID: %s", oid)
        }
    }
}
```

- [ ] **Step 2: Run test — expect PASS (registry already has these)**

```bash
go test -v -run TestOIDRegistryMinimumCoverage ./pkg/crypto
```
Expected: PASS.

- [ ] **Step 3: Split the registry data**

In `pkg/crypto/oid_data_pqc.go`:
```go
package crypto

// pqcOIDs returns the NIST FIPS 203/204/205/206 OIDs plus IETF LAMPS composite OIDs.
// Kept in its own file so new PQC entries can be added without churning oid.go.
func pqcOIDs() map[string]OIDEntry {
    return map[string]OIDEntry{
        // ML-KEM (FIPS 203)
        "2.16.840.1.101.3.4.4.1": {OID: "2.16.840.1.101.3.4.4.1", Algorithm: "ML-KEM-512", Family: "Lattice", KeySize: 512, Status: SAFE},
        "2.16.840.1.101.3.4.4.2": {OID: "2.16.840.1.101.3.4.4.2", Algorithm: "ML-KEM-768", Family: "Lattice", KeySize: 768, Status: SAFE},
        "2.16.840.1.101.3.4.4.3": {OID: "2.16.840.1.101.3.4.4.3", Algorithm: "ML-KEM-1024", Family: "Lattice", KeySize: 1024, Status: SAFE},

        // ML-DSA (FIPS 204)
        "2.16.840.1.101.3.4.3.17": {OID: "2.16.840.1.101.3.4.3.17", Algorithm: "ML-DSA-44", Family: "Lattice", Status: SAFE},
        "2.16.840.1.101.3.4.3.18": {OID: "2.16.840.1.101.3.4.3.18", Algorithm: "ML-DSA-65", Family: "Lattice", Status: SAFE},
        "2.16.840.1.101.3.4.3.19": {OID: "2.16.840.1.101.3.4.3.19", Algorithm: "ML-DSA-87", Family: "Lattice", Status: SAFE},

        // SLH-DSA (FIPS 205) — 12 variants
        "2.16.840.1.101.3.4.3.20": {OID: "2.16.840.1.101.3.4.3.20", Algorithm: "SLH-DSA-SHA2-128s", Family: "Hash-Based", KeySize: 128, Status: SAFE},
        "2.16.840.1.101.3.4.3.21": {OID: "2.16.840.1.101.3.4.3.21", Algorithm: "SLH-DSA-SHA2-128f", Family: "Hash-Based", KeySize: 128, Status: SAFE},
        "2.16.840.1.101.3.4.3.22": {OID: "2.16.840.1.101.3.4.3.22", Algorithm: "SLH-DSA-SHA2-192s", Family: "Hash-Based", KeySize: 192, Status: SAFE},
        "2.16.840.1.101.3.4.3.23": {OID: "2.16.840.1.101.3.4.3.23", Algorithm: "SLH-DSA-SHA2-192f", Family: "Hash-Based", KeySize: 192, Status: SAFE},
        "2.16.840.1.101.3.4.3.24": {OID: "2.16.840.1.101.3.4.3.24", Algorithm: "SLH-DSA-SHA2-256s", Family: "Hash-Based", KeySize: 256, Status: SAFE},
        "2.16.840.1.101.3.4.3.25": {OID: "2.16.840.1.101.3.4.3.25", Algorithm: "SLH-DSA-SHA2-256f", Family: "Hash-Based", KeySize: 256, Status: SAFE},
        "2.16.840.1.101.3.4.3.26": {OID: "2.16.840.1.101.3.4.3.26", Algorithm: "SLH-DSA-SHAKE-128s", Family: "Hash-Based", KeySize: 128, Status: SAFE},
        "2.16.840.1.101.3.4.3.27": {OID: "2.16.840.1.101.3.4.3.27", Algorithm: "SLH-DSA-SHAKE-128f", Family: "Hash-Based", KeySize: 128, Status: SAFE},
        "2.16.840.1.101.3.4.3.28": {OID: "2.16.840.1.101.3.4.3.28", Algorithm: "SLH-DSA-SHAKE-192s", Family: "Hash-Based", KeySize: 192, Status: SAFE},
        "2.16.840.1.101.3.4.3.29": {OID: "2.16.840.1.101.3.4.3.29", Algorithm: "SLH-DSA-SHAKE-192f", Family: "Hash-Based", KeySize: 192, Status: SAFE},
        "2.16.840.1.101.3.4.3.30": {OID: "2.16.840.1.101.3.4.3.30", Algorithm: "SLH-DSA-SHAKE-256s", Family: "Hash-Based", KeySize: 256, Status: SAFE},
        "2.16.840.1.101.3.4.3.31": {OID: "2.16.840.1.101.3.4.3.31", Algorithm: "SLH-DSA-SHAKE-256f", Family: "Hash-Based", KeySize: 256, Status: SAFE},

        // FN-DSA (FIPS 206, provisional)
        "2.16.840.1.101.3.4.3.32": {OID: "2.16.840.1.101.3.4.3.32", Algorithm: "FN-DSA-512", Family: "Lattice", KeySize: 512, Status: SAFE},
        "2.16.840.1.101.3.4.3.33": {OID: "2.16.840.1.101.3.4.3.33", Algorithm: "FN-DSA-1024", Family: "Lattice", KeySize: 1024, Status: SAFE},

        // Composite Signatures (IETF LAMPS draft-ietf-lamps-pq-composite-sigs)
        "2.16.840.1.114027.80.8.1.1":  {OID: "2.16.840.1.114027.80.8.1.1", Algorithm: "ML-DSA-44-RSA-2048", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.2":  {OID: "2.16.840.1.114027.80.8.1.2", Algorithm: "ML-DSA-44-RSA-2048-PSS", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.3":  {OID: "2.16.840.1.114027.80.8.1.3", Algorithm: "ML-DSA-44-Ed25519", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.4":  {OID: "2.16.840.1.114027.80.8.1.4", Algorithm: "ML-DSA-44-ECDSA-P256", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.5":  {OID: "2.16.840.1.114027.80.8.1.5", Algorithm: "ML-DSA-65-RSA-3072", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.6":  {OID: "2.16.840.1.114027.80.8.1.6", Algorithm: "ML-DSA-65-RSA-3072-PSS", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.7":  {OID: "2.16.840.1.114027.80.8.1.7", Algorithm: "ML-DSA-65-RSA-4096", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.8":  {OID: "2.16.840.1.114027.80.8.1.8", Algorithm: "ML-DSA-65-RSA-4096-PSS", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.9":  {OID: "2.16.840.1.114027.80.8.1.9", Algorithm: "ML-DSA-65-ECDSA-P384", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.10": {OID: "2.16.840.1.114027.80.8.1.10", Algorithm: "ML-DSA-65-Ed25519", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.11": {OID: "2.16.840.1.114027.80.8.1.11", Algorithm: "ML-DSA-87-ECDSA-P384", Family: "Composite", Status: SAFE},
        "2.16.840.1.114027.80.8.1.12": {OID: "2.16.840.1.114027.80.8.1.12", Algorithm: "ML-DSA-87-Ed448", Family: "Composite", Status: SAFE},
    }
}
```

In `pkg/crypto/oid_data_classical.go`:
```go
package crypto

// classicalOIDs returns the pre-PQC OIDs already recognized by Triton.
// New entries added in Task 2.
func classicalOIDs() map[string]OIDEntry {
    return map[string]OIDEntry{
        "1.2.840.113549.1.1.1":  {OID: "1.2.840.113549.1.1.1", Algorithm: "RSA", Family: "RSA", Status: TRANSITIONAL},
        "1.2.840.113549.1.1.11": {OID: "1.2.840.113549.1.1.11", Algorithm: "SHA256-RSA", Family: "RSA", Status: TRANSITIONAL},
        "1.2.840.113549.1.1.12": {OID: "1.2.840.113549.1.1.12", Algorithm: "SHA384-RSA", Family: "RSA", Status: TRANSITIONAL},
        "1.2.840.113549.1.1.13": {OID: "1.2.840.113549.1.1.13", Algorithm: "SHA512-RSA", Family: "RSA", Status: TRANSITIONAL},
        "1.2.840.10045.2.1":     {OID: "1.2.840.10045.2.1", Algorithm: "EC", Family: "ECDSA", Status: TRANSITIONAL},
        "1.3.101.112":           {OID: "1.3.101.112", Algorithm: "Ed25519", Family: "EdDSA", KeySize: 256, Status: TRANSITIONAL},
        "1.3.101.113":           {OID: "1.3.101.113", Algorithm: "Ed448", Family: "EdDSA", KeySize: 448, Status: TRANSITIONAL},
    }
}
```

In `pkg/crypto/oid.go`, replace the `init()` body with:
```go
func init() {
    oidRegistry = make(map[string]OIDEntry)
    for oid, entry := range classicalOIDs() {
        oidRegistry[oid] = entry
    }
    for oid, entry := range pqcOIDs() {
        oidRegistry[oid] = entry
    }

    // Build reverse map
    reverseOIDMap = make(map[string]string, len(oidRegistry))
    for oid, entry := range oidRegistry {
        reverseOIDMap[entry.Algorithm] = oid
    }
}
```

Also delete the now-duplicated inline entries from `oid.go`.

- [ ] **Step 4: Run all crypto package tests — expect PASS (pure refactor, no behavior change)**

```bash
go test -v ./pkg/crypto/...
```
Expected: all existing tests still PASS, plus new `TestOIDRegistryMinimumCoverage`.

- [ ] **Step 5: Commit**

```bash
git add pkg/crypto/oid.go pkg/crypto/oid_data_pqc.go pkg/crypto/oid_data_classical.go pkg/crypto/oid_data_test.go
git commit -m "refactor(crypto): split OID registry into pqc + classical data files"
```

---

### Task 2: Add ~140 classical-crypto OIDs (symmetric, hash, DH, DSA, curves, Kerberos)

**Files:**
- Modify: `pkg/crypto/oid_data_classical.go`
- Modify: `pkg/crypto/oid_data_test.go`

- [ ] **Step 1: Write failing test requiring 200-entry coverage + representative entries**

In `pkg/crypto/oid_data_test.go`, add:
```go
func TestOIDRegistryExpandedCoverage(t *testing.T) {
    if len(oidRegistry) < 200 {
        t.Fatalf("expected registry size >= 200 after expansion, got %d", len(oidRegistry))
    }

    // Representative entries across families
    cases := []struct {
        oid     string
        wantAlg string
    }{
        // Hash families
        {"1.2.840.113549.2.5", "MD5"},
        {"1.3.14.3.2.26", "SHA-1"},
        {"2.16.840.1.101.3.4.2.1", "SHA-256"},
        {"2.16.840.1.101.3.4.2.8", "SHA3-256"},
        // Symmetric
        {"2.16.840.1.101.3.4.1.2", "AES-128-CBC"},
        {"2.16.840.1.101.3.4.1.42", "AES-256-CBC"},
        {"2.16.840.1.101.3.4.1.46", "AES-256-GCM"},
        {"1.2.840.113549.3.7", "3DES-CBC"},
        // EC curves
        {"1.2.840.10045.3.1.7", "ECDSA-P256"},
        {"1.3.132.0.34", "ECDSA-P384"},
        {"1.3.132.0.35", "ECDSA-P521"},
        // Diffie-Hellman
        {"1.2.840.113549.1.3.1", "DH"},
        // DSA
        {"1.2.840.10040.4.1", "DSA"},
        // Kerberos
        {"1.2.840.113554.1.2.2", "Kerberos"},
        // RSA-PSS / OAEP
        {"1.2.840.113549.1.1.10", "RSA-PSS"},
        {"1.2.840.113549.1.1.7", "RSA-OAEP"},
    }
    for _, c := range cases {
        entry, ok := oidRegistry[c.oid]
        if !ok {
            t.Errorf("missing OID %s (%s)", c.oid, c.wantAlg)
            continue
        }
        if entry.Algorithm != c.wantAlg {
            t.Errorf("OID %s: got algorithm %q, want %q", c.oid, entry.Algorithm, c.wantAlg)
        }
    }
}
```

- [ ] **Step 2: Run test — expect FAIL**

```bash
go test -v -run TestOIDRegistryExpandedCoverage ./pkg/crypto
```
Expected: FAIL with "missing OID ..." across most entries.

- [ ] **Step 3: Expand `classicalOIDs()` in `pkg/crypto/oid_data_classical.go`**

Add entries for these families (full dotted-form OIDs from NIST CSRC + RFC 5280 + RFC 3279). Final file should include at least:

**Hash functions** (SAFE/DEPRECATED/UNSAFE per existing classifier):
- `1.2.840.113549.2.5` — MD5 (UNSAFE)
- `1.2.840.113549.2.2` — MD2 (UNSAFE)
- `1.3.14.3.2.26` — SHA-1 (DEPRECATED)
- `2.16.840.1.101.3.4.2.1` — SHA-256 (TRANSITIONAL)
- `2.16.840.1.101.3.4.2.2` — SHA-384 (SAFE)
- `2.16.840.1.101.3.4.2.3` — SHA-512 (SAFE)
- `2.16.840.1.101.3.4.2.4` — SHA-224 (TRANSITIONAL)
- `2.16.840.1.101.3.4.2.7` — SHA3-224 (SAFE)
- `2.16.840.1.101.3.4.2.8` — SHA3-256 (SAFE)
- `2.16.840.1.101.3.4.2.9` — SHA3-384 (SAFE)
- `2.16.840.1.101.3.4.2.10` — SHA3-512 (SAFE)
- `2.16.840.1.101.3.4.2.11` — SHAKE128 (SAFE)
- `2.16.840.1.101.3.4.2.12` — SHAKE256 (SAFE)
- `1.3.36.3.2.1` — RIPEMD-160 (DEPRECATED)

**HMAC**:
- `1.2.840.113549.2.7` — HMAC-SHA1 (DEPRECATED)
- `1.2.840.113549.2.9` — HMAC-SHA256 (TRANSITIONAL)
- `1.2.840.113549.2.10` — HMAC-SHA384 (SAFE)
- `1.2.840.113549.2.11` — HMAC-SHA512 (SAFE)

**Symmetric** (AES via NIST CSRC `2.16.840.1.101.3.4.1.x`):
- `.1` AES-128-ECB, `.2` AES-128-CBC, `.3` AES-128-OFB, `.4` AES-128-CFB, `.6` AES-128-GCM, `.7` AES-128-CCM
- `.21` AES-192-ECB, `.22` AES-192-CBC, `.26` AES-192-GCM, `.27` AES-192-CCM
- `.41` AES-256-ECB, `.42` AES-256-CBC, `.46` AES-256-GCM, `.47` AES-256-CCM
- `1.2.840.113549.3.7` — 3DES-CBC (DEPRECATED)
- `1.2.840.113549.3.2` — RC2-CBC (UNSAFE)
- `1.2.840.113549.3.4` — RC4 (UNSAFE)
- `1.3.14.3.2.7` — DES-CBC (UNSAFE)

**RSA signature variants**:
- `1.2.840.113549.1.1.2` — MD2-RSA (UNSAFE)
- `1.2.840.113549.1.1.4` — MD5-RSA (UNSAFE)
- `1.2.840.113549.1.1.5` — SHA1-RSA (DEPRECATED)
- `1.2.840.113549.1.1.7` — RSA-OAEP (TRANSITIONAL)
- `1.2.840.113549.1.1.10` — RSA-PSS (TRANSITIONAL)
- `1.2.840.113549.1.1.14` — SHA224-RSA (TRANSITIONAL)

**EC named curves** (`1.2.840.10045.3.1.x` prime, `1.3.132.0.x` SEC):
- `1.2.840.10045.3.1.1` — ECDSA-P192 (UNSAFE)
- `1.2.840.10045.3.1.7` — ECDSA-P256 (TRANSITIONAL)
- `1.3.132.0.33` — ECDSA-P224 (DEPRECATED)
- `1.3.132.0.34` — ECDSA-P384 (SAFE)
- `1.3.132.0.35` — ECDSA-P521 (SAFE)
- `1.3.132.0.10` — secp256k1 (TRANSITIONAL)
- Brainpool: `1.3.36.3.3.2.8.1.1.7` — brainpoolP256r1, `.11` — brainpoolP384r1, `.13` — brainpoolP512r1 (all TRANSITIONAL)

**ECDSA-with-hash** (`1.2.840.10045.4.x`):
- `.1` ECDSA-SHA1 (DEPRECATED)
- `.3.1` ECDSA-SHA224, `.3.2` ECDSA-SHA256, `.3.3` ECDSA-SHA384, `.3.4` ECDSA-SHA512

**DSA**:
- `1.2.840.10040.4.1` — DSA (DEPRECATED)
- `1.2.840.10040.4.3` — DSA-SHA1 (DEPRECATED)
- `2.16.840.1.101.3.4.3.1` — DSA-SHA224, `.2` DSA-SHA256

**Diffie-Hellman**:
- `1.2.840.113549.1.3.1` — DH (TRANSITIONAL)
- `1.2.840.10046.2.1` — DH-ANSIX9.42

**Kerberos / PKIX auth**:
- `1.2.840.113554.1.2.2` — Kerberos
- `1.2.840.113554.1.2.2.3` — Kerberos-SPNEGO

**PKCS#7/CMS content types**:
- `1.2.840.113549.1.7.1` — PKCS7-Data
- `1.2.840.113549.1.7.2` — PKCS7-SignedData
- `1.2.840.113549.1.7.3` — PKCS7-EnvelopedData
- `1.2.840.113549.1.9.16.3.6` — CMS-3DES-wrap
- `2.16.840.1.101.3.4.1.5` — AES-128-wrap, `.25` AES-192-wrap, `.45` AES-256-wrap

**KDF**:
- `1.2.840.113549.1.5.12` — PBKDF2
- `1.2.840.113549.1.9.16.3.9` — HKDF

**LMS / XMSS** (stateful hash-based signatures, SAFE):
- `1.2.840.113549.1.9.16.3.17` — HSS-LMS
- `0.4.0.127.0.15.1.1.13.0` — XMSS
- `0.4.0.127.0.15.1.1.14.0` — XMSS-MT

Use this reference format for each entry:
```go
"<oid>": {OID: "<oid>", Algorithm: "<name>", Family: "<family>", KeySize: <bits>, Status: <SAFE|TRANSITIONAL|DEPRECATED|UNSAFE>},
```

Family values to use: `"AES"`, `"3DES"`, `"DES"`, `"RC4"`, `"RC2"`, `"RSA"`, `"ECDSA"`, `"EdDSA"`, `"DSA"`, `"DH"`, `"SHA"`, `"SHA3"`, `"MD5"`, `"MD4"`, `"RIPEMD"`, `"HMAC"`, `"Kerberos"`, `"PKCS7"`, `"KDF"`, `"Hash-Based"`, `"Lattice"`, `"Composite"`.

Status assignment rules (match existing `pqc.go` classifier semantics):
- MD2/MD4/MD5/DES/RC2/RC4/RSA<1024/ECDSA-P192 → `UNSAFE`
- SHA-1/3DES/DSA/RIPEMD/ECDSA-P224/brainpool → `DEPRECATED`
- SHA-224/SHA-256/RSA (generic)/ECDSA-P256/DH/HMAC-SHA256 → `TRANSITIONAL`
- SHA-384/SHA-512/SHA3-*/AES-192/AES-256/ECDSA-P384/ECDSA-P521/Ed25519/Ed448/HSS-LMS/XMSS → `SAFE`

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test -v -run 'TestOIDRegistry' ./pkg/crypto
```
Expected: PASS (registry ≥ 200, all required OIDs present with correct algorithms).

- [ ] **Step 5: Run full crypto package to check for regressions**

```bash
go test ./pkg/crypto/...
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/crypto/oid_data_classical.go pkg/crypto/oid_data_test.go
git commit -m "feat(crypto): expand OID registry with ~140 classical crypto OIDs"
```

---

## Phase 2 — DER Byte Scanner Primitive

Build the exported function that scans an arbitrary buffer for DER-encoded OIDs. This is the core primitive the scanner module consumes.

### Task 3: Create `FindOIDsInBuffer` with false-positive filtering

**Files:**
- Create: `pkg/crypto/asn1.go`
- Create: `pkg/crypto/asn1_test.go`

- [ ] **Step 1: Write failing test with hand-crafted byte buffers**

Create `pkg/crypto/asn1_test.go`:
```go
package crypto

import (
    "bytes"
    "testing"
)

func TestFindOIDsInBuffer_Basic(t *testing.T) {
    // DER-encoded OID for sha256WithRSAEncryption (1.2.840.113549.1.1.11)
    // Tag=0x06, Len=9, Content=2A 86 48 86 F7 0D 01 01 0B
    sha256RSA := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}

    // ML-KEM-512 OID (2.16.840.1.101.3.4.4.1)
    // Tag=0x06, Len=9, Content=60 86 48 01 65 03 04 04 01
    mlkem := []byte{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01}

    // Embed them with junk in between (simulates binary .rodata layout)
    buf := bytes.Buffer{}
    buf.Write([]byte("random string data here xxxxx"))
    buf.Write(sha256RSA)
    buf.Write([]byte{0x00, 0xFF, 0x42, 0x17, 0xAB})
    buf.Write(mlkem)
    buf.Write([]byte("more junk"))

    found := FindOIDsInBuffer(buf.Bytes())

    wantOIDs := map[string]bool{
        "1.2.840.113549.1.1.11":  false,
        "2.16.840.1.101.3.4.4.1": false,
    }
    for _, f := range found {
        if _, ok := wantOIDs[f.OID]; ok {
            wantOIDs[f.OID] = true
        }
    }
    for oid, seen := range wantOIDs {
        if !seen {
            t.Errorf("missing expected OID: %s", oid)
        }
    }
}

func TestFindOIDsInBuffer_RejectsGarbage(t *testing.T) {
    // Random bytes with scattered 0x06 bytes but no valid OID structure
    garbage := []byte{
        0x06, 0x03, 0xFF, 0xFF, 0xFF, // first arc would be invalid
        0x06, 0x02, 0x2A, 0x86,       // truncated - last byte has continuation bit set
        0x06, 0x00,                    // zero length
        0x06, 0x50, 0x2A,              // length claims 80 bytes but only 1 follows
    }
    found := FindOIDsInBuffer(garbage)
    if len(found) != 0 {
        t.Errorf("expected no OIDs from garbage, got %d: %+v", len(found), found)
    }
}

func TestFindOIDsInBuffer_DedupesByOffset(t *testing.T) {
    // Same OID byte pattern repeated
    sha256RSA := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}
    buf := append(append([]byte{}, sha256RSA...), sha256RSA...)

    found := FindOIDsInBuffer(buf)
    // Two distinct hits at different offsets
    if len(found) != 2 {
        t.Errorf("expected 2 hits, got %d", len(found))
    }
    if found[0].Offset == found[1].Offset {
        t.Errorf("expected distinct offsets, got %d and %d", found[0].Offset, found[1].Offset)
    }
}

func TestFindOIDsInBuffer_RejectsInvalidFirstArc(t *testing.T) {
    // OID claiming first arc = 3 (invalid — must be 0, 1, or 2)
    // First content byte = 3*40 + 0 = 120 (0x78), which decodes to first arc 3 under normal rules...
    // But our decoder produces arc 3.0. We should reject because X.690 limits first arc to 0/1/2.
    badFirstArc := []byte{0x06, 0x03, 0x78, 0x01, 0x02}
    found := FindOIDsInBuffer(badFirstArc)
    if len(found) != 0 {
        t.Errorf("expected rejection of invalid first arc, got %d hits", len(found))
    }
}
```

- [ ] **Step 2: Run test — expect FAIL (function not defined)**

```bash
go test -v -run TestFindOIDsInBuffer ./pkg/crypto
```
Expected: FAIL with "undefined: FindOIDsInBuffer".

- [ ] **Step 3: Implement `pkg/crypto/asn1.go`**

```go
package crypto

import (
    "strconv"
    "strings"
)

// FoundOID represents a single OID discovered in a byte buffer.
type FoundOID struct {
    OID    string // Dotted decimal form, e.g. "1.2.840.113549.1.1.11"
    Offset int    // Byte offset in the source buffer where the OID DER tag began
    Length int    // Total DER byte length (tag + length + content)
}

// Validity limits for DER OID filtering. Tuned to reject obvious false positives
// without excluding real crypto OIDs. OIDs in the crypto domain have
// 3-20 arcs with content length 3-30 bytes.
const (
    minOIDContentLen = 3
    maxOIDContentLen = 30
    minArcCount      = 3
    maxArcCount      = 20
)

// FindOIDsInBuffer scans buf for DER-encoded OBJECT IDENTIFIER tags (0x06)
// and returns every hit whose decoded form passes false-positive filters.
// The scanner is byte-offset-based — it does not assume structural ASN.1
// context around the tag, which is what makes it useful for walking .rodata
// sections of stripped binaries where OIDs are embedded as table entries.
func FindOIDsInBuffer(buf []byte) []FoundOID {
    var out []FoundOID
    n := len(buf)
    for i := 0; i < n-1; i++ {
        if buf[i] != 0x06 {
            continue
        }
        oid, total, ok := tryDecodeOIDAt(buf, i)
        if !ok {
            continue
        }
        out = append(out, FoundOID{OID: oid, Offset: i, Length: total})
        // Do NOT skip to i+total — overlapping valid OIDs are rare, but
        // advancing by 1 makes the scan strictly inclusive at the cost of a
        // few wasted cycles on 9-byte buffers. That's fine.
    }
    return out
}

// tryDecodeOIDAt attempts to decode a DER OID starting at offset. Returns
// the OID, total bytes consumed (tag+len+content), and ok=false if any
// validity rule fails.
func tryDecodeOIDAt(buf []byte, offset int) (string, int, bool) {
    if offset+2 > len(buf) || buf[offset] != 0x06 {
        return "", 0, false
    }

    // Length parsing — only short form accepted. Long form is legal DER but
    // rare for OIDs (all real crypto OIDs fit in <128 content bytes) and
    // accepting it would widen the false-positive surface dramatically.
    lenByte := buf[offset+1]
    if lenByte&0x80 != 0 {
        return "", 0, false
    }
    contentLen := int(lenByte)
    if contentLen < minOIDContentLen || contentLen > maxOIDContentLen {
        return "", 0, false
    }
    if offset+2+contentLen > len(buf) {
        return "", 0, false
    }

    content := buf[offset+2 : offset+2+contentLen]

    // Continuation-bit sanity: last byte of content MUST have high bit clear
    // (it terminates the last arc). If not, this isn't a valid OID.
    if content[len(content)-1]&0x80 != 0 {
        return "", 0, false
    }

    // First-arc validation: X.690 restricts first arc to {0, 1, 2}.
    first := int(content[0])
    firstArc := first / 40
    secondArc := first % 40
    if firstArc > 2 {
        return "", 0, false
    }
    if firstArc < 2 && secondArc >= 40 {
        return "", 0, false
    }

    // Decode arcs
    arcs := make([]string, 0, 8)
    arcs = append(arcs, strconv.Itoa(firstArc), strconv.Itoa(secondArc))
    var v uint64
    for i := 1; i < len(content); i++ {
        if v > (1 << 56) { // overflow guard
            return "", 0, false
        }
        v = (v << 7) | uint64(content[i]&0x7F)
        if content[i]&0x80 == 0 {
            arcs = append(arcs, strconv.FormatUint(v, 10))
            v = 0
        }
    }

    if len(arcs) < minArcCount || len(arcs) > maxArcCount {
        return "", 0, false
    }

    return strings.Join(arcs, "."), 2 + contentLen, true
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test -v -run TestFindOIDsInBuffer ./pkg/crypto
```
Expected: all four sub-tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/crypto/asn1.go pkg/crypto/asn1_test.go
git commit -m "feat(crypto): add FindOIDsInBuffer for binary OID discovery"
```

---

### Task 4: Add `ClassifyFoundOIDs` to attach registry metadata

**Files:**
- Modify: `pkg/crypto/asn1.go`
- Modify: `pkg/crypto/asn1_test.go`

- [ ] **Step 1: Write failing test**

Append to `pkg/crypto/asn1_test.go`:
```go
func TestClassifyFoundOIDs(t *testing.T) {
    found := []FoundOID{
        {OID: "1.2.840.113549.1.1.11", Offset: 100},  // SHA256-RSA (registered)
        {OID: "2.16.840.1.101.3.4.4.1", Offset: 200}, // ML-KEM-512 (registered)
        {OID: "9.9.9.9.9.9", Offset: 300},            // unknown (valid-looking but not in registry)
    }

    classified := ClassifyFoundOIDs(found)

    if len(classified) != 2 {
        t.Fatalf("expected 2 classified results (unknown filtered out), got %d", len(classified))
    }
    if classified[0].Entry.Algorithm != "SHA256-RSA" {
        t.Errorf("first entry: got %q, want SHA256-RSA", classified[0].Entry.Algorithm)
    }
    if classified[1].Entry.Algorithm != "ML-KEM-512" {
        t.Errorf("second entry: got %q, want ML-KEM-512", classified[1].Entry.Algorithm)
    }
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
go test -v -run TestClassifyFoundOIDs ./pkg/crypto
```
Expected: FAIL — undefined.

- [ ] **Step 3: Implement in `pkg/crypto/asn1.go`**

Append:
```go
// ClassifiedOID pairs a byte-scanner hit with its registry metadata.
type ClassifiedOID struct {
    FoundOID
    Entry OIDEntry
}

// ClassifyFoundOIDs filters a slice of FoundOID down to entries present in
// the OID registry and attaches their metadata. Unknown OIDs are dropped —
// emitting them would create unclassifiable findings that can't be acted on.
func ClassifyFoundOIDs(found []FoundOID) []ClassifiedOID {
    out := make([]ClassifiedOID, 0, len(found))
    for _, f := range found {
        entry, ok := oidRegistry[f.OID]
        if !ok {
            continue
        }
        out = append(out, ClassifiedOID{FoundOID: f, Entry: entry})
    }
    return out
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
go test -v -run TestClassifyFoundOIDs ./pkg/crypto
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/crypto/asn1.go pkg/crypto/asn1_test.go
git commit -m "feat(crypto): add ClassifyFoundOIDs to join byte hits with registry"
```

---

## Phase 3 — Binary Section Extraction

Walk ELF, Mach-O, PE files and extract the read-only / read-only-data sections as byte slices that the OID scanner can consume. All three use Go stdlib (`debug/elf`, `debug/macho`, `debug/pe`).

### Task 5: ELF section walker

**Files:**
- Create: `pkg/scanner/binsections/binsections.go`
- Create: `pkg/scanner/binsections/elf.go`
- Create: `pkg/scanner/binsections/elf_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/scanner/binsections/elf_test.go`:
```go
package binsections

import (
    "os"
    "runtime"
    "testing"
)

func TestExtractELFSections_Self(t *testing.T) {
    if runtime.GOOS != "linux" {
        t.Skip("ELF test requires a Linux host with the test binary as ELF")
    }
    exe, err := os.Executable()
    if err != nil {
        t.Fatal(err)
    }

    sections, err := ExtractELFSections(exe)
    if err != nil {
        t.Fatalf("ExtractELFSections(%s) failed: %v", exe, err)
    }

    // Go binaries always have .rodata and .go.buildinfo.
    names := map[string]bool{}
    for _, s := range sections {
        names[s.Name] = true
    }
    if !names[".rodata"] {
        t.Errorf("expected .rodata section, got section names: %v", keys(names))
    }
}

func keys(m map[string]bool) []string {
    out := make([]string, 0, len(m))
    for k := range m {
        out = append(out, k)
    }
    return out
}
```

Create `pkg/scanner/binsections/binsections.go` (shared types only):
```go
// Package binsections extracts read-only data sections from ELF, Mach-O, and PE
// binaries. Used by the OID byte scanner to scope its search to sections that
// legitimately contain constant data (avoiding code, stacks, heaps).
package binsections

// Section is a named read-only byte region extracted from a binary.
type Section struct {
    Name string
    Data []byte
}
```

- [ ] **Step 2: Run — expect FAIL (undefined)**

```bash
go test -v -run TestExtractELFSections_Self ./pkg/scanner/binsections
```
Expected: FAIL — undefined function.

- [ ] **Step 3: Implement `pkg/scanner/binsections/elf.go`**

```go
package binsections

import (
    "debug/elf"
    "fmt"
)

// elfReadOnlySections lists section names commonly holding constant data
// where OIDs and other embedded literals live. Scanning only these sections
// (vs the whole file) cuts false positives from .text (code) and .data
// (mutable globals) by ~100x.
var elfReadOnlySections = map[string]bool{
    ".rodata":         true,
    ".rodata1":        true,
    ".data.rel.ro":    true,
    ".data.rel.ro.local": true,
    ".gnu.linkonce.r": true,
}

// ExtractELFSections opens path as ELF and returns a Section for each
// read-only data section. Returns a non-nil error if the file is not valid
// ELF or cannot be read.
func ExtractELFSections(path string) ([]Section, error) {
    f, err := elf.Open(path)
    if err != nil {
        return nil, fmt.Errorf("elf.Open %s: %w", path, err)
    }
    defer f.Close()

    out := make([]Section, 0, 4)
    for _, s := range f.Sections {
        if !elfReadOnlySections[s.Name] {
            continue
        }
        // SHT_NOBITS sections have no on-disk bytes — skip.
        if s.Type == elf.SHT_NOBITS {
            continue
        }
        data, err := s.Data()
        if err != nil {
            continue
        }
        out = append(out, Section{Name: s.Name, Data: data})
    }
    return out, nil
}
```

- [ ] **Step 4: Run test — expect PASS on Linux, SKIP elsewhere**

```bash
go test -v -run TestExtractELFSections_Self ./pkg/scanner/binsections
```
Expected: PASS (on Linux) or SKIP (on macOS).

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/binsections/
git commit -m "feat(scanner): add ELF read-only section extractor"
```

---

### Task 6: Mach-O section walker

**Files:**
- Create: `pkg/scanner/binsections/macho.go`
- Create: `pkg/scanner/binsections/macho_test.go`

- [ ] **Step 1: Write failing test**

```go
package binsections

import (
    "os"
    "runtime"
    "testing"
)

func TestExtractMachOSections_Self(t *testing.T) {
    if runtime.GOOS != "darwin" {
        t.Skip("Mach-O test requires darwin host")
    }
    exe, err := os.Executable()
    if err != nil {
        t.Fatal(err)
    }

    sections, err := ExtractMachOSections(exe)
    if err != nil {
        t.Fatalf("ExtractMachOSections(%s): %v", exe, err)
    }

    // Mach-O Go binaries have __rodata in __DATA_CONST or __DATA segments.
    foundConst := false
    for _, s := range sections {
        if s.Name == "__rodata" || s.Name == "__const" {
            foundConst = true
            break
        }
    }
    if !foundConst {
        t.Errorf("expected __rodata or __const section, got %d sections", len(sections))
        for _, s := range sections {
            t.Logf("  section: %s (%d bytes)", s.Name, len(s.Data))
        }
    }
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
go test -v -run TestExtractMachOSections_Self ./pkg/scanner/binsections
```
Expected: FAIL — undefined.

- [ ] **Step 3: Implement `pkg/scanner/binsections/macho.go`**

```go
package binsections

import (
    "debug/macho"
    "fmt"
)

// machoReadOnlySections names Mach-O read-only section names we scan.
// The section Name (not SegmentName) matters — `__rodata` and `__const`
// are the typical locations for embedded constant data.
var machoReadOnlySections = map[string]bool{
    "__rodata":          true,
    "__const":           true,
    "__cstring":         true,
    "__gopclntab":       false, // large Go table, mostly code offsets — skip
    "__objc_const":      true,
    "__objc_classname":  true,
}

// ExtractMachOSections opens path as Mach-O and returns read-only sections.
// Handles both single-arch and universal binaries (for universal, only the
// first arch is returned — caller handles multi-arch upstream if needed).
func ExtractMachOSections(path string) ([]Section, error) {
    f, err := macho.Open(path)
    if err != nil {
        // Try as FAT/universal
        fat, ferr := macho.OpenFat(path)
        if ferr != nil {
            return nil, fmt.Errorf("macho.Open %s: %w", path, err)
        }
        defer fat.Close()
        if len(fat.Arches) == 0 {
            return nil, fmt.Errorf("macho fat %s: no arches", path)
        }
        return extractMachOFile(fat.Arches[0].File), nil
    }
    defer f.Close()
    return extractMachOFile(f), nil
}

func extractMachOFile(f *macho.File) []Section {
    out := make([]Section, 0, 4)
    for _, s := range f.Sections {
        if !machoReadOnlySections[s.Name] {
            continue
        }
        data, err := s.Data()
        if err != nil {
            continue
        }
        out = append(out, Section{Name: s.Name, Data: data})
    }
    return out
}
```

- [ ] **Step 4: Run — expect PASS on darwin, SKIP on Linux**

```bash
go test -v -run TestExtractMachOSections_Self ./pkg/scanner/binsections
```
Expected: PASS on macOS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/binsections/macho.go pkg/scanner/binsections/macho_test.go
git commit -m "feat(scanner): add Mach-O read-only section extractor"
```

---

### Task 7: PE section walker

**Files:**
- Create: `pkg/scanner/binsections/pe.go`
- Create: `pkg/scanner/binsections/pe_test.go`
- Create: `pkg/scanner/binsections/testdata/README.md`

- [ ] **Step 1: Write failing test using a small PE fixture**

We can't use `os.Executable()` on non-Windows hosts (it'd be ELF or Mach-O). Use a small embedded PE binary for testing. The simplest path: commit a tiny pre-built PE stub as testdata.

Create `pkg/scanner/binsections/testdata/README.md`:
```
Generate hello.exe for tests:

  GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o hello.exe hello.go

Where hello.go is:

  package main
  func main() { println("hello") }

The 2-3MB PE binary is checked in to keep tests hermetic.
```

Then create `pkg/scanner/binsections/pe_test.go`:
```go
package binsections

import "testing"

func TestExtractPESections_Fixture(t *testing.T) {
    sections, err := ExtractPESections("testdata/hello.exe")
    if err != nil {
        t.Fatalf("ExtractPESections: %v", err)
    }
    // PE binaries split read-only data into .rdata typically.
    names := map[string]bool{}
    for _, s := range sections {
        names[s.Name] = true
    }
    if !names[".rdata"] {
        t.Errorf("expected .rdata, got sections: %+v", names)
    }
}
```

Generate + commit the fixture:
```bash
cd /tmp && cat > hello.go <<'EOF'
package main
func main() { println("hello") }
EOF
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o hello.exe hello.go
cp hello.exe /Users/amirrudinyahaya/Workspace/triton/pkg/scanner/binsections/testdata/
```

- [ ] **Step 2: Run — expect FAIL**

```bash
go test -v -run TestExtractPESections_Fixture ./pkg/scanner/binsections
```
Expected: FAIL — undefined.

- [ ] **Step 3: Implement `pkg/scanner/binsections/pe.go`**

```go
package binsections

import (
    "debug/pe"
    "fmt"
)

// peReadOnlySections lists PE section names typically holding constant data.
// `.rdata` is the primary location; some compilers also use `.rodata`.
var peReadOnlySections = map[string]bool{
    ".rdata":  true,
    ".rodata": true,
    ".data":   false, // mutable globals, skip
}

// ExtractPESections opens path as PE/COFF and returns read-only sections.
func ExtractPESections(path string) ([]Section, error) {
    f, err := pe.Open(path)
    if err != nil {
        return nil, fmt.Errorf("pe.Open %s: %w", path, err)
    }
    defer f.Close()

    out := make([]Section, 0, 4)
    for _, s := range f.Sections {
        if !peReadOnlySections[s.Name] {
            continue
        }
        data, err := s.Data()
        if err != nil {
            continue
        }
        out = append(out, Section{Name: s.Name, Data: data})
    }
    return out, nil
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
go test -v -run TestExtractPESections_Fixture ./pkg/scanner/binsections
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/binsections/pe.go pkg/scanner/binsections/pe_test.go pkg/scanner/binsections/testdata/
git commit -m "feat(scanner): add PE read-only section extractor"
```

---

### Task 8: Unified dispatch — `ExtractSections(path)`

**Files:**
- Modify: `pkg/scanner/binsections/binsections.go`
- Create: `pkg/scanner/binsections/dispatch_test.go`

- [ ] **Step 1: Write failing test**

```go
package binsections

import (
    "os"
    "testing"
)

func TestExtractSections_AutoDetect(t *testing.T) {
    exe, err := os.Executable()
    if err != nil {
        t.Fatal(err)
    }
    sections, err := ExtractSections(exe)
    if err != nil {
        t.Fatalf("ExtractSections(%s): %v", exe, err)
    }
    if len(sections) == 0 {
        t.Error("expected at least one section from self-executable")
    }
}

func TestExtractSections_NonBinary(t *testing.T) {
    // Plain text file — should fail cleanly, not panic.
    path := "testdata/README.md"
    _, err := ExtractSections(path)
    if err == nil {
        t.Error("expected error from non-binary file")
    }
}
```

- [ ] **Step 2: Run — expect FAIL**

```bash
go test -v -run TestExtractSections ./pkg/scanner/binsections
```
Expected: FAIL.

- [ ] **Step 3: Implement dispatch by magic bytes**

Append to `pkg/scanner/binsections/binsections.go`:
```go
import (
    "bytes"
    "errors"
    "os"
)

var (
    elfMagic   = []byte{0x7f, 'E', 'L', 'F'}
    machoMagic = [][]byte{
        {0xCF, 0xFA, 0xED, 0xFE}, // 64-bit
        {0xFE, 0xED, 0xFA, 0xCF}, // 64-bit swap
        {0xCE, 0xFA, 0xED, 0xFE}, // 32-bit
        {0xCA, 0xFE, 0xBA, 0xBE}, // universal/fat
    }
    peMagic = []byte{'M', 'Z'}
)

// ErrUnsupportedFormat is returned for files that aren't ELF/Mach-O/PE.
var ErrUnsupportedFormat = errors.New("binsections: unsupported binary format")

// ExtractSections inspects the first 4 bytes of path, dispatches to the
// correct format-specific extractor, and returns the read-only sections.
func ExtractSections(path string) ([]Section, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    var header [4]byte
    n, _ := f.Read(header[:])
    f.Close()
    if n < 2 {
        return nil, ErrUnsupportedFormat
    }

    switch {
    case n >= 4 && bytes.Equal(header[:4], elfMagic):
        return ExtractELFSections(path)
    case n >= 4 && isMachOMagic(header[:4]):
        return ExtractMachOSections(path)
    case bytes.Equal(header[:2], peMagic):
        return ExtractPESections(path)
    }
    return nil, ErrUnsupportedFormat
}

func isMachOMagic(h []byte) bool {
    for _, m := range machoMagic {
        if bytes.Equal(h, m) {
            return true
        }
    }
    return false
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
go test -v ./pkg/scanner/binsections
```
Expected: all pass (PASS on current OS, SKIP on others).

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/binsections/binsections.go pkg/scanner/binsections/dispatch_test.go
git commit -m "feat(scanner): add unified ExtractSections dispatch by magic bytes"
```

---

## Phase 4 — Scanner Module

Wire the primitives together into a `Module` implementation that the engine can register.

### Task 9: Scaffold `ASN1OIDModule` with unit test

**Files:**
- Create: `pkg/scanner/asn1_oid.go`
- Create: `pkg/scanner/asn1_oid_test.go`

- [ ] **Step 1: Write failing unit test**

```go
package scanner

import (
    "context"
    "os"
    "runtime"
    "testing"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
)

func TestASN1OIDModule_BasicInterface(t *testing.T) {
    cfg := &scannerconfig.Config{}
    m := NewASN1OIDModule(cfg)

    if m.Name() != "asn1_oid" {
        t.Errorf("Name: got %q, want asn1_oid", m.Name())
    }
    if m.Category() != model.ModuleCategoryLibrary {
        t.Errorf("Category: got %v, want Library", m.Category())
    }
}

func TestASN1OIDModule_ScansSelfExecutable(t *testing.T) {
    if runtime.GOOS == "windows" {
        t.Skip("self-exec scan requires POSIX")
    }
    exe, err := os.Executable()
    if err != nil {
        t.Fatal(err)
    }

    cfg := &scannerconfig.Config{}
    m := NewASN1OIDModule(cfg)

    target := model.ScanTarget{
        Type: model.ScanTargetTypeFilesystem,
        Path: exe,
    }
    findings := make(chan *model.Finding, 100)
    done := make(chan struct{})
    var collected []*model.Finding
    go func() {
        for f := range findings {
            collected = append(collected, f)
        }
        close(done)
    }()

    err = m.Scan(context.Background(), target, findings)
    close(findings)
    <-done

    if err != nil {
        t.Fatalf("Scan: %v", err)
    }
    // The Go toolchain embeds Ed25519 and TLS-related OIDs in the binary.
    // We don't assert specific findings (brittle) — just that the scan
    // completes and may or may not produce findings without panicking.
    t.Logf("self-scan produced %d findings", len(collected))
}
```

- [ ] **Step 2: Run — expect FAIL (undefined)**

```bash
go test -v -run TestASN1OIDModule ./pkg/scanner
```
Expected: FAIL.

- [ ] **Step 3: Implement `pkg/scanner/asn1_oid.go`**

```go
package scanner

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "time"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/crypto"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner/binsections"
)

// ASN1OIDModule walks executable binaries, extracts read-only data sections,
// scans them for DER-encoded OIDs, and emits findings keyed to the crypto
// registry. This catches algorithms embedded in stripped binaries where
// symbol-based and string-based scanners miss them.
//
// Detection method: "asn1-oid". Runs only in the comprehensive profile
// because section extraction on large binaries is IO + CPU heavy (~50-200ms
// per binary). Not suited for quick/standard profiles.
type ASN1OIDModule struct {
    cfg *scannerconfig.Config
}

func NewASN1OIDModule(cfg *scannerconfig.Config) *ASN1OIDModule {
    return &ASN1OIDModule{cfg: cfg}
}

func (m *ASN1OIDModule) Name() string                         { return "asn1_oid" }
func (m *ASN1OIDModule) Category() model.ModuleCategory       { return model.ModuleCategoryLibrary }
func (m *ASN1OIDModule) ScanTargetType() model.ScanTargetType { return model.ScanTargetTypeFilesystem }

// Scan walks target.Path (expected to be a filesystem root), finds executable
// binaries, extracts their read-only sections, and emits a Finding for each
// classified OID.
func (m *ASN1OIDModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
    root := target.Path
    if root == "" {
        return nil
    }

    return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
        if err != nil {
            return nil // skip unreadable
        }
        if ctx.Err() != nil {
            return ctx.Err()
        }
        if d.IsDir() {
            return nil
        }
        info, err := d.Info()
        if err != nil || !info.Mode().IsRegular() {
            return nil
        }
        // Fast-reject non-binaries by magic. ExtractSections does this too,
        // but doing it here avoids allocating the full file descriptor path.
        if !looksLikeBinary(path) {
            return nil
        }
        m.scanBinary(ctx, path, findings)
        return nil
    })
}

func (m *ASN1OIDModule) scanBinary(ctx context.Context, path string, findings chan<- *model.Finding) {
    sections, err := binsections.ExtractSections(path)
    if err != nil {
        return // not a supported binary, or unreadable
    }
    seen := make(map[string]bool) // dedupe by OID within a single binary
    for _, s := range sections {
        hits := crypto.FindOIDsInBuffer(s.Data)
        classified := crypto.ClassifyFoundOIDs(hits)
        for _, c := range classified {
            if seen[c.OID] {
                continue
            }
            seen[c.OID] = true
            select {
            case <-ctx.Done():
                return
            case findings <- buildFinding(path, s.Name, c):
            }
        }
    }
}

func buildFinding(path, sectionName string, c crypto.ClassifiedOID) *model.Finding {
    asset := &model.CryptoAsset{
        ID:        uuid.New().String(),
        Algorithm: c.Entry.Algorithm,
        KeySize:   c.Entry.KeySize,
        Library:   filepath.Base(path),
        Function:  fmt.Sprintf("OID %s in %s", c.OID, sectionName),
        PQCStatus: c.Entry.Status.String(),
    }
    return &model.Finding{
        ID:       uuid.New().String(),
        Category: int(model.ModuleCategoryLibrary),
        Source: model.FindingSource{
            Type:            "file",
            Path:            path,
            DetectionMethod: "asn1-oid",
        },
        CryptoAsset: asset,
        Confidence:  0.95, // OID match is high-confidence by construction
        Module:      "asn1_oid",
        Timestamp:   time.Now().UTC(),
    }
}

// looksLikeBinary performs a 4-byte magic check to quickly reject
// non-binaries during the filesystem walk.
func looksLikeBinary(path string) bool {
    f, err := os.Open(path)
    if err != nil {
        return false
    }
    defer f.Close()
    var head [4]byte
    n, _ := f.Read(head[:])
    if n < 2 {
        return false
    }
    // ELF
    if n >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F' {
        return true
    }
    // Mach-O (single arch, 64 or 32 bit, either endian, or fat)
    if n >= 4 {
        m := [4]byte{head[0], head[1], head[2], head[3]}
        for _, magic := range [][4]byte{
            {0xCF, 0xFA, 0xED, 0xFE},
            {0xFE, 0xED, 0xFA, 0xCF},
            {0xCE, 0xFA, 0xED, 0xFE},
            {0xCA, 0xFE, 0xBA, 0xBE},
        } {
            if m == magic {
                return true
            }
        }
    }
    // PE (MZ header)
    if head[0] == 'M' && head[1] == 'Z' {
        return true
    }
    return false
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
go test -v -run TestASN1OIDModule ./pkg/scanner
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/asn1_oid.go pkg/scanner/asn1_oid_test.go
git commit -m "feat(scanner): add ASN1OIDModule for binary OID discovery"
```

---

### Task 10: Register module in engine under comprehensive profile only

**Files:**
- Modify: `pkg/scanner/engine.go`

- [ ] **Step 1: Write failing test asserting registration behavior**

Create `pkg/scanner/asn1_oid_engine_test.go`:
```go
package scanner

import (
    "testing"

    "github.com/amiryahaya/triton/internal/scannerconfig"
)

func TestASN1OIDModule_RegisteredInComprehensive(t *testing.T) {
    cfg := &scannerconfig.Config{Profile: "comprehensive"}
    e := New(cfg)
    e.RegisterDefaultModules()

    found := false
    for _, m := range e.modules {
        if m.Name() == "asn1_oid" {
            found = true
            break
        }
    }
    if !found {
        t.Error("asn1_oid module not registered under comprehensive profile")
    }
}

func TestASN1OIDModule_NotRegisteredInQuick(t *testing.T) {
    cfg := &scannerconfig.Config{Profile: "quick"}
    e := New(cfg)
    e.RegisterDefaultModules()

    for _, m := range e.modules {
        if m.Name() == "asn1_oid" {
            t.Error("asn1_oid module should NOT be registered under quick profile")
        }
    }
}
```

- [ ] **Step 2: Run — expect FAIL for the comprehensive test**

```bash
go test -v -run TestASN1OIDModule_Registered ./pkg/scanner
```
Expected: the "RegisteredInComprehensive" test FAILS.

- [ ] **Step 3: Register in `engine.go`'s `RegisterDefaultModules()`**

Find the end of `RegisterDefaultModules()` in `pkg/scanner/engine.go` and append (within the function body, before the closing brace):

```go
// Comprehensive-only: ASN.1 OID byte scanner (heavy)
if e.config != nil && e.config.Profile == "comprehensive" {
    e.RegisterModule(NewASN1OIDModule(e.config))
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
go test -v -run TestASN1OIDModule_Registered ./pkg/scanner
```
Expected: both PASS.

- [ ] **Step 5: Run the full scanner test suite to check for regressions**

```bash
go test ./pkg/scanner/...
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/engine.go pkg/scanner/asn1_oid_engine_test.go
git commit -m "feat(scanner): register asn1_oid module under comprehensive profile"
```

---

### Task 11: License gating — Pro+ tier only

**Files:**
- Modify: `internal/license/guard.go`

- [ ] **Step 1: Read current module gating logic**

```bash
grep -n "asn1\|deps\|library" /Users/amirrudinyahaya/Workspace/triton/internal/license/guard.go | head -20
```

Locate where `FilterConfig` restricts module lists by tier. The pattern for Pro/Enterprise-only modules is established — follow it.

- [ ] **Step 2: Write failing test in `internal/license/guard_test.go`** (add to existing file)

```go
func TestFilterConfig_ASN1OIDModule_FreeStripped(t *testing.T) {
    g := NewGuardForTest(TierFree)
    cfg := &scannerconfig.Config{
        Profile: "comprehensive",
        Modules: []string{"certificate", "asn1_oid", "binary"},
    }
    g.FilterConfig(cfg)

    for _, m := range cfg.Modules {
        if m == "asn1_oid" {
            t.Error("asn1_oid should be stripped from free-tier config")
        }
    }
}

func TestFilterConfig_ASN1OIDModule_ProKept(t *testing.T) {
    g := NewGuardForTest(TierPro)
    cfg := &scannerconfig.Config{
        Profile: "comprehensive",
        Modules: []string{"certificate", "asn1_oid", "binary"},
    }
    g.FilterConfig(cfg)

    found := false
    for _, m := range cfg.Modules {
        if m == "asn1_oid" {
            found = true
        }
    }
    if !found {
        t.Error("asn1_oid should be retained for Pro tier")
    }
}
```

Note: use the existing test helpers in `guard_test.go` — if `NewGuardForTest` isn't the exact name, match the file's established pattern.

- [ ] **Step 3: Run — expect FAIL for free-tier stripping**

```bash
go test -v -run 'TestFilterConfig_ASN1' ./internal/license
```
Expected: FAIL.

- [ ] **Step 4: Add `asn1_oid` to the Pro+ module allowlist in `guard.go`**

Locate the module allowlist for free tier (the 3-module allowlist mentioned in CLAUDE.md as "quick+json+3 modules"). Ensure `asn1_oid` is NOT in the free list but IS in the Pro list. If gating is inverted (denylists), add to the free denylist.

If the existing code uses a pattern like `proOnlyModules`, append `"asn1_oid"`. If it uses `freeTierModules`, ensure `"asn1_oid"` is not in it.

- [ ] **Step 5: Run — expect PASS**

```bash
go test -v -run 'TestFilterConfig_ASN1' ./internal/license
```
Expected: PASS.

- [ ] **Step 6: Full license-package test run**

```bash
go test ./internal/license/...
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/license/guard.go internal/license/guard_test.go
git commit -m "feat(license): gate asn1_oid module to Pro+ tier"
```

---

## Phase 5 — Integration & Real-Binary Validation

### Task 12: Integration test scanning a real OpenSSL binary

**Files:**
- Create: `test/integration/asn1_oid_test.go`

- [ ] **Step 1: Write failing integration test (build-tagged)**

```go
//go:build integration

package integration

import (
    "context"
    "os/exec"
    "runtime"
    "testing"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner"
)

func TestASN1OID_ScansSystemOpenSSL(t *testing.T) {
    // Locate the OpenSSL binary — skip if not present.
    opensslPath, err := exec.LookPath("openssl")
    if err != nil {
        t.Skip("openssl not installed on test host")
    }

    m := scanner.NewASN1OIDModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 1000)
    done := make(chan struct{})
    var collected []*model.Finding
    go func() {
        for f := range findings {
            collected = append(collected, f)
        }
        close(done)
    }()

    target := model.ScanTarget{
        Type: model.ScanTargetTypeFilesystem,
        Path: opensslPath, // single binary, not a directory — module handles this
    }
    if err := m.Scan(context.Background(), target, findings); err != nil {
        t.Fatalf("Scan: %v", err)
    }
    close(findings)
    <-done

    t.Logf("OpenSSL scan produced %d findings", len(collected))

    // OpenSSL, regardless of version, should embed these OIDs:
    expectAlgorithms := []string{"RSA", "SHA-256", "AES-256-GCM"}
    got := map[string]bool{}
    for _, f := range collected {
        if f.CryptoAsset != nil {
            got[f.CryptoAsset.Algorithm] = true
        }
    }
    for _, want := range expectAlgorithms {
        if !got[want] {
            t.Errorf("expected %q in OpenSSL findings, missing (platform=%s)", want, runtime.GOOS)
        }
    }
}
```

Note: `scanner.NewASN1OIDModule.Scan` above calls `filepath.WalkDir(root, ...)` — for a single file `root`, `WalkDir` still visits that one entry. Confirm this behavior or adjust the test to pass a parent directory.

- [ ] **Step 2: Run — expect FAIL if OpenSSL OIDs missing**

```bash
go test -v -tags integration -run TestASN1OID_ScansSystemOpenSSL ./test/integration/...
```
Expected: PASS if module works; SKIP if no OpenSSL; FAIL if registry gaps prevent RSA/SHA-256/AES-GCM classification.

- [ ] **Step 3: If the test fails, the likely fix is ensuring Task 2's registry expansion included every expected OID.** Audit the failure output, add missing OIDs, re-run.

- [ ] **Step 4: Commit**

```bash
git add test/integration/asn1_oid_test.go
git commit -m "test(integration): validate asn1_oid against real OpenSSL binary"
```

---

### Task 13: False-positive benchmark scanning a known non-crypto binary

**Files:**
- Create: `test/integration/asn1_oid_fp_test.go`

- [ ] **Step 1: Write the benchmark test**

```go
//go:build integration

package integration

import (
    "context"
    "os/exec"
    "testing"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner"
)

// TestASN1OID_FalsePositiveBaseline scans /bin/echo (a minimal binary that
// should NOT have significant crypto OID embeddings). Acceptable noise
// threshold: <5 findings. If this starts failing after a registry expansion,
// the FP filters in asn1.go need tightening.
func TestASN1OID_FalsePositiveBaseline(t *testing.T) {
    echoPath, err := exec.LookPath("echo")
    if err != nil {
        t.Skip("echo not found")
    }

    m := scanner.NewASN1OIDModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 100)
    done := make(chan struct{})
    var count int
    go func() {
        for range findings {
            count++
        }
        close(done)
    }()

    target := model.ScanTarget{Type: model.ScanTargetTypeFilesystem, Path: echoPath}
    if err := m.Scan(context.Background(), target, findings); err != nil {
        t.Fatalf("Scan: %v", err)
    }
    close(findings)
    <-done

    t.Logf("/bin/echo produced %d asn1_oid findings", count)
    if count > 5 {
        t.Errorf("false positive baseline breached: %d findings (threshold 5)", count)
    }
}
```

- [ ] **Step 2: Run — expect PASS**

```bash
go test -v -tags integration -run TestASN1OID_FalsePositiveBaseline ./test/integration/...
```
Expected: PASS with <5 findings. If it fails, tighten `tryDecodeOIDAt` validity rules (e.g., lower `maxOIDContentLen`).

- [ ] **Step 3: Commit**

```bash
git add test/integration/asn1_oid_fp_test.go
git commit -m "test(integration): add FP baseline for asn1_oid on non-crypto binary"
```

---

## Phase 6 — Documentation & Polish

### Task 14: Update CLAUDE.md scanner inventory + add module docs

**Files:**
- Modify: `CLAUDE.md`
- Create: `docs/scanners/asn1_oid.md`

- [ ] **Step 1: Update module count and description in `CLAUDE.md`**

Find the section "### Key packages" → "**`pkg/scanner/`**" and bump the scanner count from 28 to 29, add one line:

```
  - `asn1_oid.go` — ASN.1 OID byte scanner: walks ELF/Mach-O/PE read-only sections for DER-encoded OIDs, classifies via `pkg/crypto/oid.go` registry (comprehensive profile + Pro+ tier only)
```

Under "Scan profiles", update the comprehensive bullet to mention the new module.

- [ ] **Step 2: Write `docs/scanners/asn1_oid.md`**

```markdown
# ASN.1 OID Byte Scanner

## What it does

Walks executable binaries (ELF, Mach-O, PE), extracts read-only data sections,
and scans them byte-by-byte for DER-encoded OBJECT IDENTIFIERs (tag `0x06`).
Every valid OID discovered is cross-referenced against the curated registry in
`pkg/crypto/oid.go` (~200 entries) and emitted as a Finding with
`DetectionMethod: "asn1-oid"`.

## Why it complements existing scanners

`binary.go` (regex-based) and `library.go` (symbol-based) both rely on
human-readable names. Stripped, obfuscated, or custom-built binaries often
lose these names but *cannot* strip OIDs — OIDs are embedded as DER byte
sequences at runtime to construct protocol messages. Harvesting them directly
catches crypto that string-based scanners miss.

## Profile + license tier

- **Profile:** comprehensive only (not standard or quick)
- **License:** Pro+ (free tier stripped)
- **Cost:** ~50-200 ms per binary on a 2025-era laptop

## False-positive strategy

`FindOIDsInBuffer` applies five rejection rules to random byte sequences that
coincidentally start with `0x06`:

1. Content length must be 3-30 bytes
2. Length byte must use short form (high bit clear)
3. Final content byte's continuation bit must be clear (arc terminator)
4. First arc must be 0, 1, or 2 (X.690 §8.19.4)
5. Decoded arc count must be 3-20

Surviving candidates are looked up in the registry. Unknown OIDs are
discarded — an OID that isn't in the registry can't be classified, so
emitting it would create an unactionable finding.

## Limitations

- Does not detect OIDs passed dynamically (runtime-assembled from pieces)
- Only scans read-only data sections; OIDs in `.text` (inlined constants) are missed
- PE long-form length encoding rejected (<0.1% of real crypto OIDs use it)
- Universal Mach-O (fat) binaries: only the first architecture slice is scanned
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/scanners/asn1_oid.md
git commit -m "docs: document asn1_oid scanner module"
```

---

### Task 15: Run full test suite + lint

**Files:** none modified.

- [ ] **Step 1: Full build + unit tests**

```bash
make build && make test
```
Expected: PASS.

- [ ] **Step 2: Lint**

```bash
make lint
```
Expected: no new warnings. Fix any that surface.

- [ ] **Step 3: Integration tests (requires PostgreSQL)**

```bash
TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" make test-integration
```
Expected: PASS. (Note the port 5435 override per MEMORY.md — "Dev DB Port Drift" entry.)

- [ ] **Step 4: If any step fails, fix and re-run that step before proceeding.**

- [ ] **Step 5: Push the branch**

```bash
git push origin feat/asn1-oid-scanner
```

- [ ] **Step 6: Open a PR using the `ship` workflow if standard practice, else manually.**

---

## Self-Review Checklist

Before handing off, the plan author verified:

- **Spec coverage:** Every architectural decision from the design discussion maps to a task. Registry expansion → Tasks 1-2. DER scanner primitive → Tasks 3-4. Binary section walkers → Tasks 5-8. Module → Task 9. Engine/license wiring → Tasks 10-11. Real-binary + FP validation → Tasks 12-13. Docs → Task 14.
- **Placeholder scan:** No "TBD", "implement later", or "handle appropriately" phrases. All code blocks contain complete code. The only deferred item is `NewGuardForTest` in Task 11 which depends on existing test-helper conventions in `guard_test.go`.
- **Type consistency:** `FoundOID`, `ClassifiedOID`, `OIDEntry`, `Section`, `ASN1OIDModule` used identically across all referencing tasks. `FindOIDsInBuffer`, `ClassifyFoundOIDs`, `ExtractSections`, `ExtractELFSections`, `ExtractMachOSections`, `ExtractPESections` names stable.

## Known open questions

- **Windows PE fixture provenance:** Task 7 commits a pre-built `hello.exe`. If repo policy bans binary checkins, switch to a table-driven test that hand-crafts a minimal PE header in-memory. Raise with reviewer.
- **License gating function name:** Task 11 assumes `FilterConfig` + a `NewGuardForTest` or equivalent test helper. Verify exact symbol names in `internal/license/guard_test.go` before Step 2; adjust test accordingly.
- **Comprehensive profile detection:** Task 10 assumes `e.config.Profile == "comprehensive"` works. If profile is an enum elsewhere, use the canonical constant.

These are the only spots where plan execution should pause to read the current code before committing.
