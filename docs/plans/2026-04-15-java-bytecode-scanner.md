# Java Bytecode Crypto Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Add a scanner module that walks `.class`/`.jar`/`.war`/`.ear` files, parses the Java class file constant pool, extracts algorithm literals (e.g., `"AES/GCM/NoPadding"`, `"SHA256withRSA"`, `"ML-KEM-768"`), and classifies them — catching crypto embedded in compiled Java bytecode that source-code scanners (`webapp.go`) miss after ProGuard / R8 / compilation strip source comments and file paths.

**Architecture:**
1. `pkg/scanner/internal/javaclass/` — new package. Pure-Go class file parser using stdlib only. Parses the JVM spec §4.4 constant pool; extracts UTF-8 + String entries. No dependencies.
2. `pkg/scanner/internal/javaclass/` extends with `ScanJAR(path)` that walks ZIP entries matching `*.class` via `archive/zip`, also reads `META-INF/MANIFEST.MF` for provider hints (BouncyCastle version, FIPS flag).
3. New `pkg/crypto/java_algorithms.go` — curated algorithm-string registry covering JCA standard names, BouncyCastle aliases, and PQC provider names. Keyed by literal string, returns `OIDEntry`-equivalent metadata.
4. `pkg/scanner/java_bytecode.go` — new scanner `Module`. Walks filesystem, matches by extension + ZIP/class magic, dispatches to the javaclass package. Emits `CryptoAsset` findings with `DetectionMethod: "java-bytecode"`.
5. Registered in comprehensive profile only; Pro+ license tier only.

**Tech Stack:** Go 1.25 stdlib `archive/zip`, `encoding/binary`, `bytes`. No new dependencies. Existing `Module` interface + `walkTarget` walker + `OIDEntry`/`PQCStatus` types.

---

## Pre-flight

- [ ] **Step 0: Confirm baseline compiles and tests pass.**

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/java-bytecode
make build && make test
```

---

## Phase 1 — Java class file parser

### Task 1: Parse class file constant pool, extract UTF-8 + String entries

**Files:**
- Create: `pkg/scanner/internal/javaclass/javaclass.go`
- Create: `pkg/scanner/internal/javaclass/javaclass_test.go`
- Create: `pkg/scanner/internal/javaclass/testdata/` (hand-built class file fixtures)

Reference: JVM spec §4.4 Constant Pool. Key tag values:
- Tag 1 (CONSTANT_Utf8): `u2 length; u1 bytes[length]`
- Tag 7 (CONSTANT_Class): `u2 name_index` → points to Utf8
- Tag 8 (CONSTANT_String): `u2 string_index` → points to Utf8
- Tag 5 (CONSTANT_Long) / Tag 6 (CONSTANT_Double): **each consume TWO constant-pool slots** (historical JVM wart; miss this and indices shift)
- Other tags (3 Integer, 4 Float, 9/10/11 Fieldref/Methodref/InterfaceMethodref, 12 NameAndType, 15 MethodHandle, 16 MethodType, 18 InvokeDynamic, 19 Module, 20 Package) have fixed sizes and no embedded variable data beyond the spec sizes — skip them by byte count.

- [ ] **Step 1: Write failing test with a hand-built class file byte buffer.**

Create `pkg/scanner/internal/javaclass/javaclass_test.go`:

```go
package javaclass

import (
    "bytes"
    "encoding/binary"
    "testing"
)

// buildMinimalClassFile assembles a valid class file header + constant pool
// with one Utf8 entry "AES/GCM/NoPadding" and one String entry pointing to it.
// Used so tests don't need external javac.
func buildMinimalClassFile(t *testing.T, utf8Values []string) []byte {
    t.Helper()
    var buf bytes.Buffer
    // Magic
    buf.Write([]byte{0xCA, 0xFE, 0xBA, 0xBE})
    // Minor + major version (Java 11 = 55)
    binary.Write(&buf, binary.BigEndian, uint16(0)) // minor
    binary.Write(&buf, binary.BigEndian, uint16(55)) // major
    // constant_pool_count = utf8Values count + 1 (entries are 1-indexed, count = N+1)
    binary.Write(&buf, binary.BigEndian, uint16(len(utf8Values)+1))
    for _, s := range utf8Values {
        buf.WriteByte(1) // tag Utf8
        binary.Write(&buf, binary.BigEndian, uint16(len(s)))
        buf.WriteString(s)
    }
    // Remaining header fields — zeroed, enough for the parser to stop cleanly.
    // access_flags, this_class, super_class, interfaces_count, fields_count, methods_count, attributes_count
    for i := 0; i < 7; i++ {
        binary.Write(&buf, binary.BigEndian, uint16(0))
    }
    return buf.Bytes()
}

func TestParseClass_ExtractsUtf8Strings(t *testing.T) {
    data := buildMinimalClassFile(t, []string{"AES/GCM/NoPadding", "SHA-256", "RSA"})
    strs, err := ParseClass(data)
    if err != nil {
        t.Fatalf("ParseClass: %v", err)
    }
    want := map[string]bool{"AES/GCM/NoPadding": false, "SHA-256": false, "RSA": false}
    for _, s := range strs {
        if _, ok := want[s]; ok {
            want[s] = true
        }
    }
    for s, seen := range want {
        if !seen {
            t.Errorf("missing expected string: %q", s)
        }
    }
}

func TestParseClass_RejectsBadMagic(t *testing.T) {
    _, err := ParseClass([]byte{0x00, 0x00, 0x00, 0x00})
    if err == nil {
        t.Error("expected error on non-class magic")
    }
}

func TestParseClass_HandlesEmpty(t *testing.T) {
    _, err := ParseClass([]byte{})
    if err == nil {
        t.Error("expected error on empty input")
    }
}

func TestParseClass_RejectsTruncated(t *testing.T) {
    // Valid magic, claims 10 constant-pool entries but truncates after the header
    data := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 55, 0, 10}
    _, err := ParseClass(data)
    if err == nil {
        t.Error("expected error on truncated constant pool")
    }
}
```

- [ ] **Step 2: Run — expect FAIL (undefined)**

```bash
go test -v ./pkg/scanner/internal/javaclass
```

- [ ] **Step 3: Implement `javaclass.go`**

```go
// Package javaclass parses Java class files (JVM spec §4.4) and extracts
// UTF-8 + String constant-pool entries. Used by the java_bytecode scanner
// to find algorithm literals embedded in compiled Java code, where source
// scanners can't reach after obfuscation or strip of debug info.
//
// This parser is deliberately minimal: it walks the header + constant
// pool only and stops. We don't decode method bytecode, attributes, or
// fields — the constant pool already contains every string literal a
// crypto API call can pass to JCA.
package javaclass

import (
    "encoding/binary"
    "errors"
    "fmt"
)

// classMagic is the big-endian 4-byte header every JVM class file starts with.
var classMagic = []byte{0xCA, 0xFE, 0xBA, 0xBE}

// Constant pool tag values from JVM spec §4.4-A.
const (
    tagUtf8               = 1
    tagInteger            = 3
    tagFloat              = 4
    tagLong               = 5
    tagDouble             = 6
    tagClass              = 7
    tagString             = 8
    tagFieldref           = 9
    tagMethodref          = 10
    tagInterfaceMethodref = 11
    tagNameAndType        = 12
    tagMethodHandle       = 15
    tagMethodType         = 16
    tagDynamic            = 17
    tagInvokeDynamic      = 18
    tagModule             = 19
    tagPackage            = 20
)

// ErrNotClassFile is returned when the 4-byte header doesn't match.
var ErrNotClassFile = errors.New("javaclass: not a JVM class file (magic mismatch)")

// ParseClass reads a class file byte slice and returns every UTF-8 constant-pool
// string. Returns ErrNotClassFile if the magic is wrong, or a descriptive
// error if the constant pool is truncated.
//
// Strings are returned in the order they appear in the constant pool; duplicates
// are preserved so callers can dedupe as needed (the scanner dedupes at the
// finding level anyway).
func ParseClass(data []byte) ([]string, error) {
    if len(data) < 10 {
        return nil, fmt.Errorf("javaclass: file too short (%d bytes)", len(data))
    }
    if !equalMagic(data[:4]) {
        return nil, ErrNotClassFile
    }

    // Skip minor + major version (4 bytes). Then read constant_pool_count (u2).
    // Per spec, cpCount is one greater than the actual number of entries.
    off := 8
    cpCount := int(binary.BigEndian.Uint16(data[off : off+2]))
    off += 2
    if cpCount == 0 {
        return nil, fmt.Errorf("javaclass: constant_pool_count = 0 (invalid)")
    }

    // Entries are 1-indexed. cpCount-1 actual entries.
    out := make([]string, 0, cpCount/2)
    i := 1
    for i < cpCount {
        if off >= len(data) {
            return nil, fmt.Errorf("javaclass: truncated at cp entry %d/%d", i, cpCount-1)
        }
        tag := data[off]
        off++
        size, consumesTwoSlots, err := cpEntrySize(tag, data, off)
        if err != nil {
            return nil, fmt.Errorf("javaclass: cp entry %d: %w", i, err)
        }
        if tag == tagUtf8 {
            if off+2 > len(data) {
                return nil, fmt.Errorf("javaclass: utf8 length at entry %d truncated", i)
            }
            strLen := int(binary.BigEndian.Uint16(data[off : off+2]))
            start := off + 2
            end := start + strLen
            if end > len(data) {
                return nil, fmt.Errorf("javaclass: utf8 entry %d claims %d bytes, only %d remain", i, strLen, len(data)-start)
            }
            out = append(out, string(data[start:end]))
        }
        off += size
        i++
        if consumesTwoSlots {
            i++ // Long/Double consume two slots per §4.4.5.
        }
    }

    return out, nil
}

func equalMagic(b []byte) bool {
    if len(b) != 4 {
        return false
    }
    for i := range classMagic {
        if b[i] != classMagic[i] {
            return false
        }
    }
    return true
}

// cpEntrySize returns the size in bytes of a constant-pool entry body (excluding
// the tag byte, which has already been consumed). consumesTwoSlots is true for
// Long/Double which advance the pool index by 2 instead of 1.
func cpEntrySize(tag byte, data []byte, off int) (size int, consumesTwoSlots bool, err error) {
    switch tag {
    case tagUtf8:
        if off+2 > len(data) {
            return 0, false, fmt.Errorf("utf8 length header truncated")
        }
        strLen := int(binary.BigEndian.Uint16(data[off : off+2]))
        return 2 + strLen, false, nil
    case tagInteger, tagFloat:
        return 4, false, nil
    case tagLong, tagDouble:
        return 8, true, nil
    case tagClass, tagString, tagMethodType, tagModule, tagPackage:
        return 2, false, nil
    case tagFieldref, tagMethodref, tagInterfaceMethodref,
        tagNameAndType, tagDynamic, tagInvokeDynamic:
        return 4, false, nil
    case tagMethodHandle:
        return 3, false, nil
    default:
        return 0, false, fmt.Errorf("unknown constant-pool tag %d", tag)
    }
}
```

- [ ] **Step 4: Run — expect PASS**

```bash
go test -v ./pkg/scanner/internal/javaclass
```

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/javaclass/
git commit -m "feat(javaclass): parse Java class file constant pool for string literals"
```

---

### Task 2: Add JAR/WAR/EAR walker that dispatches per `.class` entry

**Files:**
- Modify: `pkg/scanner/internal/javaclass/javaclass.go` (add `ScanJAR` + `JARHit` type)
- Modify: `pkg/scanner/internal/javaclass/javaclass_test.go`
- Create: `pkg/scanner/internal/javaclass/testdata/crypto.jar` (small fixture)

- [ ] **Step 1: Write failing test that scans a tiny JAR fixture**

First, build the fixture. Create `/tmp/MakeFixture.java` and compile + JAR it:

```java
// /tmp/MakeFixture.java — minimal class using JCA with string literals
// so the constant pool contains recognizable algorithm names
public class MakeFixture {
    public static void main(String[] args) throws Exception {
        javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        java.security.MessageDigest.getInstance("SHA-256");
        java.security.KeyPairGenerator.getInstance("RSA");
    }
}
```

Build + JAR (requires local JDK):
```bash
cd /tmp && javac MakeFixture.java && jar cf crypto.jar MakeFixture.class
cp crypto.jar /Users/amirrudinyahaya/Workspace/triton/.worktrees/java-bytecode/pkg/scanner/internal/javaclass/testdata/
```

If the host doesn't have a JDK (macOS without it by default), install via `brew install openjdk` first. If that's also unavailable, the test should skip gracefully — build the fixture into the test using hand-crafted ZIP bytes.

Append test:
```go
func TestScanJAR_ExtractsClassStrings(t *testing.T) {
    hits, err := ScanJAR("testdata/crypto.jar")
    if err != nil {
        t.Skipf("testdata/crypto.jar missing — run 'make javaclass-fixtures' to build: %v", err)
    }
    // Every string from every class in the JAR is returned with its class path.
    want := map[string]bool{"AES/GCM/NoPadding": false, "SHA-256": false, "RSA": false}
    for _, h := range hits {
        if _, ok := want[h.Value]; ok {
            want[h.Value] = true
        }
    }
    for s, seen := range want {
        if !seen {
            t.Errorf("missing %q from crypto.jar scan", s)
        }
    }
}

func TestScanJAR_RejectsNonZIP(t *testing.T) {
    _, err := ScanJAR("javaclass.go") // source file, not a JAR
    if err == nil {
        t.Error("expected error scanning non-ZIP file")
    }
}
```

- [ ] **Step 2: Run — expect FAIL or SKIP**

- [ ] **Step 3: Implement `ScanJAR` + `JARHit`**

Append to `javaclass.go`:
```go
import "archive/zip"
import "io"

// JARHit pairs a UTF-8 constant-pool string with the class path inside the
// JAR that produced it. Used by the scanner to attribute findings precisely.
type JARHit struct {
    ClassPath string // e.g. "com/example/Foo.class"
    Value     string
}

// ScanJAR walks a JAR/WAR/EAR (ZIP archive) and returns every UTF-8
// constant-pool string from every .class entry it contains. Non-class
// entries are ignored. Manifest parsing is a separate function.
//
// Large JARs are processed lazily — entries are read one at a time, so
// memory stays bounded to the largest individual .class file.
func ScanJAR(path string) ([]JARHit, error) {
    r, err := zip.OpenReader(path)
    if err != nil {
        return nil, fmt.Errorf("javaclass: open %s: %w", path, err)
    }
    defer r.Close()

    var hits []JARHit
    for _, f := range r.File {
        if !isClassEntry(f.Name) {
            continue
        }
        strs, err := readClassFromZip(f)
        if err != nil {
            // Don't abort the whole JAR on one bad class — skip and continue.
            continue
        }
        for _, s := range strs {
            hits = append(hits, JARHit{ClassPath: f.Name, Value: s})
        }
    }
    return hits, nil
}

func isClassEntry(name string) bool {
    n := len(name)
    return n > 6 && name[n-6:] == ".class"
}

func readClassFromZip(f *zip.File) ([]string, error) {
    rc, err := f.Open()
    if err != nil {
        return nil, err
    }
    defer rc.Close()
    data, err := io.ReadAll(rc)
    if err != nil {
        return nil, err
    }
    return ParseClass(data)
}
```

- [ ] **Step 4: Run — expect PASS (or SKIP if no fixture)**

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/javaclass/
git commit -m "feat(javaclass): add JAR walker + testdata fixture"
```

---

## Phase 2 — Java Algorithm Registry

### Task 3: Build Java crypto string → algorithm registry

**Files:**
- Create: `pkg/crypto/java_algorithms.go`
- Create: `pkg/crypto/java_algorithms_test.go`

- [ ] **Step 1: Write failing test**

```go
package crypto

import "testing"

func TestLookupJavaAlgorithm_JCAStandardNames(t *testing.T) {
    cases := []struct {
        literal string
        wantAlg string
        wantStatus PQCStatus
    }{
        {"AES/GCM/NoPadding", "AES", SAFE},
        {"AES/CBC/PKCS5Padding", "AES", TRANSITIONAL},
        {"DES/ECB/NoPadding", "DES", UNSAFE},
        {"DESede/CBC/PKCS5Padding", "3DES", DEPRECATED},
        {"RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA", TRANSITIONAL},
        {"SHA-256", "SHA-256", TRANSITIONAL},
        {"SHA-1", "SHA-1", DEPRECATED},
        {"MD5", "MD5", UNSAFE},
        {"SHA256withRSA", "SHA256withRSA", TRANSITIONAL},
        {"SHA1withDSA", "SHA1withDSA", DEPRECATED},
        {"Ed25519", "Ed25519", TRANSITIONAL},
        {"ML-DSA-65", "ML-DSA-65", SAFE},
        {"ML-KEM-768", "ML-KEM-768", SAFE},
    }
    for _, c := range cases {
        entry, ok := LookupJavaAlgorithm(c.literal)
        if !ok {
            t.Errorf("literal %q: not found in registry", c.literal)
            continue
        }
        if entry.Algorithm != c.wantAlg {
            t.Errorf("literal %q: got algorithm %q, want %q", c.literal, entry.Algorithm, c.wantAlg)
        }
        if entry.Status != c.wantStatus {
            t.Errorf("literal %q: got status %s, want %s", c.literal, entry.Status, c.wantStatus)
        }
    }
}

func TestLookupJavaAlgorithm_Unknown(t *testing.T) {
    if _, ok := LookupJavaAlgorithm("not-a-real-alg"); ok {
        t.Error("expected lookup miss on gibberish")
    }
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `java_algorithms.go`**

```go
package crypto

import "strings"

// JavaAlgEntry is a classified Java crypto API literal.
type JavaAlgEntry struct {
    Literal   string // Original string as it appears in the constant pool
    Algorithm string // Canonical algorithm name (matches crypto registry conventions)
    Family    string
    Status    PQCStatus
}

// javaAlgorithmRegistry maps literal strings found in Java constant pools
// (JCA standard names + common BouncyCastle / PQC provider names) to
// classified metadata. The key is lowercased + whitespace-trimmed for
// case-insensitive match semantics.
//
// Reference: Oracle JCA Standard Algorithm Names
// (https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html)
// and BouncyCastle / BC-FIPS / BC-PQC provider documentation.
var javaAlgorithmRegistry = buildJavaAlgRegistry()

// LookupJavaAlgorithm does a case-insensitive lookup of a Java crypto
// literal. Returns the classified entry + ok=true when the literal is
// recognized. Literals that start with "AES/", "RSA/", etc. are matched
// against their prefix to capture cipher-transformation strings.
func LookupJavaAlgorithm(literal string) (JavaAlgEntry, bool) {
    key := strings.ToLower(strings.TrimSpace(literal))
    if e, ok := javaAlgorithmRegistry[key]; ok {
        return e, true
    }
    // Prefix match for cipher transformations: "AES/GCM/NoPadding" etc.
    if slash := strings.Index(key, "/"); slash > 0 {
        prefix := key[:slash]
        if e, ok := javaAlgorithmRegistry[prefix]; ok {
            // Preserve original literal in the returned entry for attribution.
            e.Literal = literal
            // Promote mode/padding hint to Status refinement where appropriate.
            if strings.Contains(key, "/gcm/") || strings.Contains(key, "/ccm/") {
                if e.Status == TRANSITIONAL {
                    e.Status = SAFE
                }
            }
            if strings.Contains(key, "/ecb/") {
                // ECB is a red flag regardless of cipher; downgrade.
                if e.Status == TRANSITIONAL {
                    e.Status = DEPRECATED
                }
            }
            return e, true
        }
    }
    return JavaAlgEntry{}, false
}

func buildJavaAlgRegistry() map[string]JavaAlgEntry {
    m := map[string]JavaAlgEntry{}
    add := func(literals []string, algo, family string, status PQCStatus) {
        for _, l := range literals {
            key := strings.ToLower(l)
            m[key] = JavaAlgEntry{
                Literal: l, Algorithm: algo, Family: family, Status: status,
            }
        }
    }

    // --- Symmetric ciphers (Cipher.getInstance keys) ---
    add([]string{"AES", "AES_128", "AES_192", "AES_256"}, "AES", "AES", TRANSITIONAL)
    add([]string{"DES"}, "DES", "DES", UNSAFE)
    add([]string{"DESede", "TripleDES"}, "3DES", "3DES", DEPRECATED)
    add([]string{"Blowfish"}, "Blowfish", "Blowfish", DEPRECATED)
    add([]string{"ChaCha20", "ChaCha20-Poly1305"}, "ChaCha20", "ChaCha", SAFE)
    add([]string{"RC2"}, "RC2", "RC2", UNSAFE)
    add([]string{"RC4", "ARCFOUR"}, "RC4", "RC4", UNSAFE)
    add([]string{"IDEA"}, "IDEA", "IDEA", DEPRECATED)

    // --- Asymmetric ---
    add([]string{"RSA"}, "RSA", "RSA", TRANSITIONAL)
    add([]string{"DSA"}, "DSA", "DSA", DEPRECATED)
    add([]string{"EC", "ECDSA", "ECDH"}, "ECDSA", "ECDSA", TRANSITIONAL)
    add([]string{"Ed25519", "EdDSA"}, "Ed25519", "EdDSA", TRANSITIONAL)
    add([]string{"Ed448"}, "Ed448", "EdDSA", SAFE)
    add([]string{"DH", "DiffieHellman"}, "DH", "DH", TRANSITIONAL)
    add([]string{"X25519"}, "X25519", "ECDH", TRANSITIONAL)
    add([]string{"X448"}, "X448", "ECDH", SAFE)

    // --- Hash functions ---
    add([]string{"MD2"}, "MD2", "MD2", UNSAFE)
    add([]string{"MD4"}, "MD4", "MD4", UNSAFE)
    add([]string{"MD5"}, "MD5", "MD5", UNSAFE)
    add([]string{"SHA", "SHA-1", "SHA1"}, "SHA-1", "SHA", DEPRECATED)
    add([]string{"SHA-224", "SHA224"}, "SHA-224", "SHA", TRANSITIONAL)
    add([]string{"SHA-256", "SHA256"}, "SHA-256", "SHA", TRANSITIONAL)
    add([]string{"SHA-384", "SHA384"}, "SHA-384", "SHA", SAFE)
    add([]string{"SHA-512", "SHA512"}, "SHA-512", "SHA", SAFE)
    add([]string{"SHA3-224"}, "SHA3-224", "SHA3", SAFE)
    add([]string{"SHA3-256"}, "SHA3-256", "SHA3", SAFE)
    add([]string{"SHA3-384"}, "SHA3-384", "SHA3", SAFE)
    add([]string{"SHA3-512"}, "SHA3-512", "SHA3", SAFE)

    // --- Signature algorithms (JCA naming: <digest>with<key>) ---
    add([]string{"MD5withRSA"}, "MD5withRSA", "RSA", UNSAFE)
    add([]string{"SHA1withRSA"}, "SHA1withRSA", "RSA", DEPRECATED)
    add([]string{"SHA224withRSA"}, "SHA224withRSA", "RSA", TRANSITIONAL)
    add([]string{"SHA256withRSA"}, "SHA256withRSA", "RSA", TRANSITIONAL)
    add([]string{"SHA384withRSA"}, "SHA384withRSA", "RSA", SAFE)
    add([]string{"SHA512withRSA"}, "SHA512withRSA", "RSA", SAFE)
    add([]string{"SHA256withRSAandMGF1"}, "SHA256withRSA-PSS", "RSA", TRANSITIONAL)
    add([]string{"SHA1withDSA"}, "SHA1withDSA", "DSA", DEPRECATED)
    add([]string{"SHA256withDSA"}, "SHA256withDSA", "DSA", DEPRECATED)
    add([]string{"SHA1withECDSA"}, "SHA1withECDSA", "ECDSA", DEPRECATED)
    add([]string{"SHA256withECDSA"}, "SHA256withECDSA", "ECDSA", TRANSITIONAL)
    add([]string{"SHA384withECDSA"}, "SHA384withECDSA", "ECDSA", SAFE)
    add([]string{"SHA512withECDSA"}, "SHA512withECDSA", "ECDSA", SAFE)

    // --- MAC / KDF ---
    add([]string{"HmacMD5"}, "HMAC-MD5", "HMAC", UNSAFE)
    add([]string{"HmacSHA1"}, "HMAC-SHA1", "HMAC", DEPRECATED)
    add([]string{"HmacSHA256"}, "HMAC-SHA256", "HMAC", TRANSITIONAL)
    add([]string{"HmacSHA384"}, "HMAC-SHA384", "HMAC", SAFE)
    add([]string{"HmacSHA512"}, "HMAC-SHA512", "HMAC", SAFE)
    add([]string{"PBKDF2WithHmacSHA1"}, "PBKDF2-SHA1", "KDF", DEPRECATED)
    add([]string{"PBKDF2WithHmacSHA256"}, "PBKDF2-SHA256", "KDF", TRANSITIONAL)
    add([]string{"PBKDF2WithHmacSHA512"}, "PBKDF2-SHA512", "KDF", SAFE)

    // --- NIST PQC (BouncyCastle BCPQC provider names) ---
    add([]string{"ML-KEM-512", "MLKEM512", "KYBER512"}, "ML-KEM-512", "Lattice", SAFE)
    add([]string{"ML-KEM-768", "MLKEM768", "KYBER768"}, "ML-KEM-768", "Lattice", SAFE)
    add([]string{"ML-KEM-1024", "MLKEM1024", "KYBER1024"}, "ML-KEM-1024", "Lattice", SAFE)
    add([]string{"ML-DSA-44", "MLDSA44", "DILITHIUM2"}, "ML-DSA-44", "Lattice", SAFE)
    add([]string{"ML-DSA-65", "MLDSA65", "DILITHIUM3"}, "ML-DSA-65", "Lattice", SAFE)
    add([]string{"ML-DSA-87", "MLDSA87", "DILITHIUM5"}, "ML-DSA-87", "Lattice", SAFE)
    add([]string{"SLH-DSA-SHA2-128S", "SPHINCS+-SHA2-128S"}, "SLH-DSA-SHA2-128s", "Hash-Based", SAFE)
    add([]string{"SLH-DSA-SHA2-192S"}, "SLH-DSA-SHA2-192s", "Hash-Based", SAFE)
    add([]string{"SLH-DSA-SHA2-256S"}, "SLH-DSA-SHA2-256s", "Hash-Based", SAFE)
    add([]string{"FN-DSA-512", "FALCON-512"}, "FN-DSA-512", "Lattice", SAFE)
    add([]string{"FN-DSA-1024", "FALCON-1024"}, "FN-DSA-1024", "Lattice", SAFE)

    // --- BouncyCastle provider identification ---
    add([]string{"BC", "BouncyCastleProvider"}, "BouncyCastle", "Provider", TRANSITIONAL)
    add([]string{"BCFIPS", "BouncyCastleFipsProvider"}, "BouncyCastle-FIPS", "Provider", SAFE)
    add([]string{"BCPQC", "BouncyCastlePQCProvider"}, "BouncyCastle-PQC", "Provider", SAFE)

    return m
}
```

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add pkg/crypto/java_algorithms.go pkg/crypto/java_algorithms_test.go
git commit -m "feat(crypto): add Java algorithm literal registry (JCA + BouncyCastle + PQC)"
```

---

## Phase 3 — Scanner Module

### Task 4: `java_bytecode.go` scanner module

**Files:**
- Create: `pkg/scanner/java_bytecode.go`
- Create: `pkg/scanner/java_bytecode_test.go`

- [ ] **Step 1: Write failing test**

```go
package scanner

import (
    "context"
    "testing"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
)

func TestJavaBytecodeModule_BasicInterface(t *testing.T) {
    m := NewJavaBytecodeModule(&scannerconfig.Config{})
    if m.Name() != "java_bytecode" {
        t.Errorf("Name: got %q, want java_bytecode", m.Name())
    }
    if m.Category() != model.CategoryPassiveFile {
        t.Errorf("Category: got %v, want CategoryPassiveFile", m.Category())
    }
}

func TestJavaBytecodeModule_ScansJAR(t *testing.T) {
    // Requires the crypto.jar fixture built in Phase 1 Task 2
    m := NewJavaBytecodeModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 32)
    done := make(chan struct{})
    var collected []*model.Finding
    go func() {
        for f := range findings {
            collected = append(collected, f)
        }
        close(done)
    }()

    target := model.ScanTarget{
        Type:  model.TargetFilesystem,
        Value: "internal/javaclass/testdata/crypto.jar",
    }
    if err := m.Scan(context.Background(), target, findings); err != nil {
        t.Skipf("jar fixture unavailable: %v", err)
    }
    close(findings)
    <-done

    // At minimum AES, SHA-256, RSA should classify.
    want := map[string]bool{"AES": false, "SHA-256": false, "RSA": false}
    for _, f := range collected {
        if f.CryptoAsset == nil {
            continue
        }
        if _, ok := want[f.CryptoAsset.Algorithm]; ok {
            want[f.CryptoAsset.Algorithm] = true
        }
    }
    for algo, seen := range want {
        if !seen {
            t.Errorf("missing %q in JAR findings", algo)
        }
    }
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement the module**

```go
package scanner

import (
    "context"
    "path/filepath"
    "strings"
    "time"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/crypto"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner/fsadapter"
    "github.com/amiryahaya/triton/pkg/scanner/internal/javaclass"
    "github.com/amiryahaya/triton/pkg/store"
)

// JavaBytecodeModule scans compiled Java artifacts (.class, .jar, .war, .ear)
// for crypto-API string literals embedded in the constant pool. Complements
// the source-code scanner (webapp.go) by reaching into artifacts where
// source was stripped, obfuscated, or never shipped.
type JavaBytecodeModule struct {
    cfg    *scannerconfig.Config
    store  store.Store
    reader fsadapter.FileReader
}

// NewJavaBytecodeModule constructs the module.
func NewJavaBytecodeModule(cfg *scannerconfig.Config) *JavaBytecodeModule {
    return &JavaBytecodeModule{cfg: cfg}
}

func (m *JavaBytecodeModule) Name() string                         { return "java_bytecode" }
func (m *JavaBytecodeModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *JavaBytecodeModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *JavaBytecodeModule) SetStore(s store.Store)               { m.store = s }
func (m *JavaBytecodeModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

// Scan walks target.Value, matching .class/.jar/.war/.ear files and extracting
// classified crypto literals from each.
func (m *JavaBytecodeModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
    if target.Value == "" {
        return nil
    }
    return walkTarget(walkerConfig{
        ctx:       ctx,
        target:    target,
        config:    m.cfg,
        matchFile: looksLikeJavaArtifact,
        store:     m.store,
        reader:    m.reader,
        processFile: func(_ context.Context, _ fsadapter.FileReader, path string) error {
            m.scanArtifact(ctx, path, findings)
            return nil
        },
    })
}

func (m *JavaBytecodeModule) scanArtifact(ctx context.Context, path string, findings chan<- *model.Finding) {
    lower := strings.ToLower(path)
    switch {
    case strings.HasSuffix(lower, ".class"):
        data, err := readAll(path)
        if err != nil {
            return
        }
        strs, err := javaclass.ParseClass(data)
        if err != nil {
            return
        }
        m.classifyAndEmit(ctx, path, "", strs, findings)

    case strings.HasSuffix(lower, ".jar"),
        strings.HasSuffix(lower, ".war"),
        strings.HasSuffix(lower, ".ear"):
        hits, err := javaclass.ScanJAR(path)
        if err != nil {
            return
        }
        // Group by class path for cleaner evidence trail.
        byClass := map[string][]string{}
        for _, h := range hits {
            byClass[h.ClassPath] = append(byClass[h.ClassPath], h.Value)
        }
        for classPath, values := range byClass {
            m.classifyAndEmit(ctx, path, classPath, values, findings)
        }
    }
}

// classifyAndEmit classifies each string literal; unclassified strings are
// silently dropped. De-duplicates by (path, classPath, algorithm) — each
// unique crypto surface produces at most one finding per source.
func (m *JavaBytecodeModule) classifyAndEmit(
    ctx context.Context,
    path, classPath string,
    strs []string,
    findings chan<- *model.Finding,
) {
    seen := map[string]bool{}
    for _, s := range strs {
        entry, ok := crypto.LookupJavaAlgorithm(s)
        if !ok {
            continue
        }
        if seen[entry.Algorithm] {
            continue
        }
        seen[entry.Algorithm] = true
        select {
        case <-ctx.Done():
            return
        case findings <- buildJavaFinding(path, classPath, s, entry):
        }
    }
}

func buildJavaFinding(path, classPath, literal string, e crypto.JavaAlgEntry) *model.Finding {
    evidence := literal
    if classPath != "" {
        evidence = classPath + ": " + literal
    }
    asset := &model.CryptoAsset{
        ID:        uuid.New().String(),
        Algorithm: e.Algorithm,
        Library:   filepath.Base(path),
        Language:  "Java",
        Function:  functionForFamily(e.Family),
        PQCStatus: string(e.Status),
    }
    return &model.Finding{
        ID:       uuid.New().String(),
        Category: int(model.CategoryPassiveFile),
        Source: model.FindingSource{
            Type:            "file",
            Path:            path,
            DetectionMethod: "java-bytecode",
            Evidence:        evidence,
        },
        CryptoAsset: asset,
        Confidence:  0.90, // literal match is high-confidence; not as strict as OID
        Module:      "java_bytecode",
        Timestamp:   time.Now().UTC(),
    }
}

// looksLikeJavaArtifact matches extension-based pre-filtering for the walker.
// The walker calls this cheaply on every file; actual format validation
// happens in scanArtifact (zip.OpenReader / ParseClass do the real checks).
func looksLikeJavaArtifact(path string) bool {
    lower := strings.ToLower(path)
    return strings.HasSuffix(lower, ".class") ||
        strings.HasSuffix(lower, ".jar") ||
        strings.HasSuffix(lower, ".war") ||
        strings.HasSuffix(lower, ".ear")
}

// readAll reads the entire file for .class parsing. Walker already enforces
// MaxFileSize so runaway reads are bounded.
func readAll(path string) ([]byte, error) {
    f, err := osOpen(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()
    return ioReadAll(f)
}
```

Note: `osOpen` / `ioReadAll` — use `os.Open` and `io.ReadAll` directly, no wrapper needed. Plan-block aliases dropped in implementation.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/java_bytecode.go pkg/scanner/java_bytecode_test.go
git commit -m "feat(scanner): add Java bytecode crypto scanner module"
```

---

### Task 5: Register module in comprehensive profile + Pro+ license gate

**Files:**
- Modify: `pkg/scanner/engine.go`
- Modify: `internal/scannerconfig/` (wherever profile module lists live — same place asn1_oid was added)
- Modify: `internal/license/tier.go`

- [ ] **Step 1: Write failing test**

```go
// pkg/scanner/java_bytecode_engine_test.go
package scanner

import (
    "testing"

    "github.com/amiryahaya/triton/internal/scannerconfig"
)

func TestJavaBytecodeModule_RegisteredInComprehensive(t *testing.T) {
    cfg := &scannerconfig.Config{Profile: "comprehensive"}
    e := New(cfg)
    e.RegisterDefaultModules()
    found := false
    for _, m := range e.modules {
        if m.Name() == "java_bytecode" {
            found = true
            break
        }
    }
    if !found {
        t.Error("java_bytecode not registered under comprehensive profile")
    }
}
```

Also update the config-profile test to assert `"java_bytecode"` is in comprehensive's module list and NOT in quick/standard.

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Wire everything**

In `pkg/scanner/engine.go::RegisterDefaultModules()`, append:
```go
e.RegisterModule(NewJavaBytecodeModule(e.config))
```
(Unconditional — same pattern we landed for `asn1_oid` in PR #44.)

In `internal/scannerconfig/` profile defaults: add `"java_bytecode"` to the comprehensive module list.

In `internal/license/tier.go::proModules()`: add `"java_bytecode"` to the Pro+ allowlist.

- [ ] **Step 4: Run — expect PASS**

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/engine.go internal/scannerconfig/ internal/license/tier.go pkg/scanner/java_bytecode_engine_test.go
git commit -m "feat(scanner): register java_bytecode in comprehensive profile, Pro+ tier"
```

---

## Phase 4 — Integration & Polish

### Task 6: Integration test against a real JAR in the Go build env

**Files:**
- Create: `test/integration/java_bytecode_test.go`

- [ ] **Step 1: Write the test**

```go
//go:build integration

package integration_test

import (
    "context"
    "os/exec"
    "testing"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner"
)

// TestJavaBytecode_ScansTestdataJAR runs the module against the checked-in
// crypto.jar fixture (built in Phase 1 Task 2). SKIPs if the fixture is
// missing. Validates end-to-end module behavior including profile defaults.
func TestJavaBytecode_ScansTestdataJAR(t *testing.T) {
    fixture := "../../pkg/scanner/internal/javaclass/testdata/crypto.jar"
    if _, err := exec.LookPath("java"); err == nil {
        t.Logf("java present on PATH — fixture is authoritative")
    }
    m := scanner.NewJavaBytecodeModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 64)
    done := make(chan struct{})
    var collected []*model.Finding
    go func() {
        for f := range findings {
            collected = append(collected, f)
        }
        close(done)
    }()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: fixture}
    if err := m.Scan(context.Background(), target, findings); err != nil {
        t.Skipf("scan failed: %v", err)
    }
    close(findings)
    <-done

    if len(collected) == 0 {
        t.Skipf("no findings — is %s present?", fixture)
    }
    t.Logf("%s produced %d findings", fixture, len(collected))
}
```

- [ ] **Step 2: Commit**

```bash
git add test/integration/java_bytecode_test.go
git commit -m "test(integration): java_bytecode against checked-in crypto.jar fixture"
```

---

### Task 7: Docs + final CI

**Files:**
- Modify: `CLAUDE.md` (scanner count 29 → 30, add module line)
- Create: `docs/scanners/java_bytecode.md`

- [ ] **Step 1: Update CLAUDE.md**

In "Key packages" → `pkg/scanner/` section, add:
```
  - `java_bytecode.go` — Java class/JAR/WAR/EAR scanner: parses constant pool for crypto literals (JCA standard names, BouncyCastle, PQC), classifies via `pkg/crypto/java_algorithms.go` (comprehensive profile + Pro+ tier only)
```
Bump module count 29 → 30.

Under `pkg/crypto/`, add:
```
  - `java_algorithms.go` — Java crypto literal registry (~80 entries)
```

Under "Scan profiles" → comprehensive: add `java_bytecode`.

- [ ] **Step 2: Create `docs/scanners/java_bytecode.md`**

```markdown
# Java Bytecode Crypto Scanner

Parses compiled Java artifacts and extracts crypto algorithm literals from
the class-file constant pool.

## Scope

- `.class` — single class file; reads `CONSTANT_Utf8` entries (JVM §4.4)
- `.jar`, `.war`, `.ear` — ZIP archives; iterates `*.class` entries

## What's detected

Literals passed to JCA APIs remain in the constant pool even after
`javac` compilation and most obfuscators (ProGuard, R8) preserve them
because reflection-based crypto calls (`Cipher.getInstance("AES/GCM/NoPadding")`)
need the literal at runtime.

Registry covers ~80 entries: JCA standard names, BouncyCastle aliases,
NIST PQC (ML-KEM, ML-DSA, SLH-DSA, FN-DSA), and provider-identification
strings (BC, BCFIPS, BCPQC).

## Profile + tier

- Comprehensive profile only (heavy — parses every class)
- Pro+ license tier only

## What's NOT detected

- Keys dynamically constructed from `String.concat` / `StringBuilder`
- Algorithm names loaded from runtime config files (those are caught by `config.go`)
- Provider-internal APIs that bypass the JCA layer
- Classes inside encrypted/signed JARs where the attacker stripped the pool

## Limitations

- Only literal strings are matched. `getInstance(myAlgoVar)` is opaque to
  this scanner and caught (if at all) by source scanning.
- ProGuard's `-repackage` does not affect constant pool literals, so the
  scanner still works on obfuscated JARs.
```

- [ ] **Step 3: Final CI**

```bash
make build && make test && make lint
go test -tags integration -run 'TestJavaBytecode' ./test/integration/...
```
All green.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md docs/scanners/java_bytecode.md
git commit -m "docs: document Java bytecode scanner"
```

---

## Self-Review

**Spec coverage:** parser → JAR walker → registry → scanner module → engine registration → license gate → integration → docs. Every component in the architecture diagram has a task.

**Placeholder scan:** No TBDs. `osOpen`/`ioReadAll` called out as plan-block aliases for `os.Open`/`io.ReadAll`.

**Type consistency:** `ParseClass`, `ScanJAR`, `JARHit`, `LookupJavaAlgorithm`, `JavaAlgEntry`, `JavaBytecodeModule` used identically across all referencing tasks.

## Known open questions

- **Fixture generation requires JDK.** Host must have `javac` + `jar` on PATH, or Homebrew `openjdk`. If CI runner lacks JDK, integration test SKIPs; unit tests work with hand-built byte buffers so unit coverage is unaffected.
- **Confidence value 0.90 vs 0.95.** OID byte scanner uses 0.95 (DER structure is unambiguous). Java literals are slightly weaker — a string matching "RSA" could legitimately be non-crypto context. 0.90 reflects this.
- **Internal package path.** Put under `pkg/scanner/internal/javaclass/` matching `binsections` pattern. Not `pkg/javaclass/` since nothing outside the scanner package should import it.
