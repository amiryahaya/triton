# PCert Parity Sprint — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close 8 cryptographic asset discovery gaps between Triton and PCert 4.5.5 so Triton produces equivalent or greater finding counts on the same target.

**Architecture:** Enhance 4 existing scanner modules (`certificate.go`, `key.go`, `certstore.go`, `engine.go`) and add 1 new module (`archive.go`). Add 1 CLI flag (`--keystore-passwords`) and 1 new Go dependency (`go.mozilla.org/pkcs7`). All changes follow existing patterns: `walkTarget`, `cmdRunnerLimited`, `FileReaderAware`, fail-open with classification `Unknown`.

**Tech Stack:** Go 1.25, `archive/zip`, `archive/tar`, `compress/gzip`, `compress/bzip2`, `go.mozilla.org/pkcs7`, `software.sslmate.com/src/go-pkcs12`, `encoding/pem`, `encoding/asn1`.

**Spec:** `docs/superpowers/specs/2026-04-16-pcert-parity-design.md`

---

### Task 1: Add `KeystorePasswords` to Config + CLI Flag

**Files:**
- Modify: `internal/scannerconfig/config.go:11-40`
- Modify: `cmd/root.go:149-189`

- [ ] **Step 1: Add `KeystorePasswords` field to Config**

In `internal/scannerconfig/config.go`, add the field to the `Config` struct:

```go
// In the Config struct, after DNSSECZones:
KeystorePasswords []string // user-supplied passwords for PKCS#12/JKS/JCEKS containers
```

- [ ] **Step 2: Add CLI flag and env var wiring in `cmd/root.go`**

In `cmd/root.go`, add a new var and flag. After the existing `dnssecZones` var declaration, add:

```go
var keystorePasswords []string
```

In `init()`, after the `--dnssec-zone` flag (line ~178), add:

```go
rootCmd.PersistentFlags().StringSliceVar(&keystorePasswords, "keystore-passwords", nil,
    "Passwords to try on PKCS#12/JKS/JCEKS keystores (comma-separated, env: TRITON_KEYSTORE_PASSWORDS)")
```

In `buildScanConfig()` (the function that builds the `scannerconfig.Config` from flags), wire the passwords into the config. Find where eBPF flags are applied (around line 354) and add before the return:

```go
// Keystore passwords: CLI flag → env var → empty (built-in defaults only).
if len(keystorePasswords) > 0 {
    cfg.KeystorePasswords = keystorePasswords
} else if envPW := os.Getenv("TRITON_KEYSTORE_PASSWORDS"); envPW != "" {
    cfg.KeystorePasswords = strings.Split(envPW, ",")
}
```

- [ ] **Step 3: Run existing tests to verify no breakage**

Run: `go test -v ./internal/scannerconfig/... ./cmd/...`
Expected: All existing tests PASS — field addition is backward-compatible.

- [ ] **Step 4: Commit**

```bash
git add internal/scannerconfig/config.go cmd/root.go
git commit -m "feat(config): add --keystore-passwords flag for PKCS#12/JKS/JCEKS password list"
```

---

### Task 2: Expanded PKCS#12 Password Support + Fail-Open (Section 5)

**Files:**
- Modify: `pkg/scanner/certificate.go:155-171`
- Test: `pkg/scanner/certificate_test.go`

- [ ] **Step 1: Write failing test for expanded passwords**

Add to `pkg/scanner/certificate_test.go`:

```go
func TestParsePKCS12_ExpandedPasswords(t *testing.T) {
    t.Parallel()

    // Generate a PKCS#12 with password "password" (not in old 3-password list)
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    require.NoError(t, err)

    template := &x509.Certificate{
        SerialNumber: big.NewInt(42),
        Subject:      pkix.Name{CommonName: "pkcs12-expanded-test"},
        NotBefore:    time.Now().Add(-time.Hour),
        NotAfter:     time.Now().Add(24 * time.Hour),
    }
    certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    require.NoError(t, err)

    cert, err := x509.ParseCertificate(certDER)
    require.NoError(t, err)

    p12Data, err := pkcs12.Encode(rand.Reader, key, cert, nil, "password")
    require.NoError(t, err)

    tmpDir := t.TempDir()
    p12File := filepath.Join(tmpDir, "test.p12")
    require.NoError(t, os.WriteFile(p12File, p12Data, 0o600))

    m := NewCertificateModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 10)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err = m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    require.Len(t, found, 1, "should find the cert inside password-protected PKCS#12")
    assert.Equal(t, "ECDSA-P256", found[0].CryptoAsset.Algorithm)
}

func TestParsePKCS12_UserConfiguredPassword(t *testing.T) {
    t.Parallel()

    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    require.NoError(t, err)

    template := &x509.Certificate{
        SerialNumber: big.NewInt(43),
        Subject:      pkix.Name{CommonName: "pkcs12-userpw-test"},
        NotBefore:    time.Now().Add(-time.Hour),
        NotAfter:     time.Now().Add(24 * time.Hour),
    }
    certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    require.NoError(t, err)

    cert, err := x509.ParseCertificate(certDER)
    require.NoError(t, err)

    p12Data, err := pkcs12.Encode(rand.Reader, key, cert, nil, "mySecretP@ss")
    require.NoError(t, err)

    tmpDir := t.TempDir()
    p12File := filepath.Join(tmpDir, "custom.p12")
    require.NoError(t, os.WriteFile(p12File, p12Data, 0o600))

    m := NewCertificateModule(&scannerconfig.Config{
        KeystorePasswords: []string{"mySecretP@ss"},
    })
    findings := make(chan *model.Finding, 10)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err = m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    require.Len(t, found, 1, "should decrypt with user-configured password")
    assert.Contains(t, found[0].CryptoAsset.Subject, "pkcs12-userpw-test")
}

func TestParsePKCS12_FailOpen(t *testing.T) {
    t.Parallel()

    // Generate a PKCS#12 with unknown password
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    require.NoError(t, err)

    template := &x509.Certificate{
        SerialNumber: big.NewInt(44),
        Subject:      pkix.Name{CommonName: "pkcs12-failopen-test"},
        NotBefore:    time.Now().Add(-time.Hour),
        NotAfter:     time.Now().Add(24 * time.Hour),
    }
    certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    require.NoError(t, err)

    cert, err := x509.ParseCertificate(certDER)
    require.NoError(t, err)

    p12Data, err := pkcs12.Encode(rand.Reader, key, cert, nil, "unknowablePassword!$#")
    require.NoError(t, err)

    tmpDir := t.TempDir()
    p12File := filepath.Join(tmpDir, "locked.p12")
    require.NoError(t, os.WriteFile(p12File, p12Data, 0o600))

    m := NewCertificateModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 10)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err = m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    require.Len(t, found, 1, "should emit fail-open finding for locked PKCS#12")
    assert.Equal(t, "Unknown", found[0].CryptoAsset.Algorithm)
    assert.Contains(t, found[0].CryptoAsset.Purpose, "password-protected")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestParsePKCS12_(ExpandedPasswords|UserConfiguredPassword|FailOpen)" ./pkg/scanner/`
Expected: First two FAIL (password "password" not tried), third FAIL (no fail-open finding emitted).

- [ ] **Step 3: Implement `keystorePasswords()` helper and update `parsePKCS12`**

In `pkg/scanner/certificate.go`, add a helper and rewrite `parsePKCS12`:

```go
// keystorePasswords returns the merged password list: user-configured first,
// then built-in defaults. Short-circuit on first match is the caller's job.
func (m *CertificateModule) keystorePasswords() []string {
    builtins := []string{"", "changeit", "changeme", "password", "secret", "triton", "server", "client", "keystore"}
    if m.config == nil || len(m.config.KeystorePasswords) == 0 {
        return builtins
    }
    // User passwords first (tried before builtins), dedup later entries.
    seen := make(map[string]struct{}, len(m.config.KeystorePasswords)+len(builtins))
    var merged []string
    for _, pw := range append(m.config.KeystorePasswords, builtins...) {
        if _, ok := seen[pw]; !ok {
            seen[pw] = struct{}{}
            merged = append(merged, pw)
        }
    }
    return merged
}

// parsePKCS12 attempts to decode a PKCS#12/PFX container.
// Tries user-configured passwords first, then built-in defaults.
// Returns (nil, errPKCS12Locked) if no password works — caller
// can emit a fail-open finding.
func (m *CertificateModule) parsePKCS12(data []byte) ([]*x509.Certificate, error) {
    for _, pw := range m.keystorePasswords() {
        _, cert, caCerts, err := pkcs12.DecodeChain(data, pw)
        if err == nil {
            var certs []*x509.Certificate
            if cert != nil {
                certs = append(certs, cert)
            }
            certs = append(certs, caCerts...)
            return certs, nil
        }
    }
    return nil, errPKCS12Locked
}

var errPKCS12Locked = fmt.Errorf("could not decode PKCS#12 with known passwords")
```

Then update the `Scan` method's `processFile` closure to handle `errPKCS12Locked` for `.p12`/`.pfx`:

```go
// In the processFile closure, replace the existing cert parse + JKS block:
certs, err := m.parseCertificateFile(ctx, reader, path)

// Fail-open for locked PKCS#12/PFX containers
if err == errPKCS12Locked {
    finding := m.createLockedContainerFinding(path, "PKCS#12")
    select {
    case findings <- finding:
    case <-ctx.Done():
        return ctx.Err()
    }
    return nil
}

// JKS files can't be fully parsed but should produce a finding
if (ext == ".jks") && err == nil && len(certs) == 0 {
    // ... existing JKS container finding code ...
}
```

Add the `createLockedContainerFinding` helper:

```go
// createLockedContainerFinding emits a finding for a password-protected
// container that could not be decrypted. Fail-open: the container is
// visible even if we can't read its contents.
func (m *CertificateModule) createLockedContainerFinding(path, containerType string) *model.Finding {
    asset := &model.CryptoAsset{
        ID:        uuid.Must(uuid.NewV7()).String(),
        Function:  containerType + " container",
        Algorithm: "Unknown",
        Purpose:   "password-protected container (could not decrypt)",
    }
    crypto.ClassifyCryptoAsset(asset)

    return &model.Finding{
        ID:       uuid.Must(uuid.NewV7()).String(),
        Category: 5,
        Source: model.FindingSource{
            Type: "file",
            Path: path,
        },
        CryptoAsset: asset,
        Confidence:  0.50,
        Module:      "certificates",
        Timestamp:   time.Now(),
    }
}
```

Update `parseCertificateFile` to propagate `errPKCS12Locked`:

```go
func (m *CertificateModule) parseCertificateFile(ctx context.Context, reader fsadapter.FileReader, path string) ([]*x509.Certificate, error) {
    data, err := reader.ReadFile(ctx, path)
    if err != nil {
        return nil, err
    }

    ext := strings.ToLower(filepath.Ext(path))

    // PKCS#12 / PFX containers
    if ext == ".p12" || ext == ".pfx" {
        return m.parsePKCS12(data)  // returns errPKCS12Locked if all passwords fail
    }

    // ... rest unchanged
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run "TestParsePKCS12_(ExpandedPasswords|UserConfiguredPassword|FailOpen)" ./pkg/scanner/`
Expected: All 3 PASS.

- [ ] **Step 5: Run full certificate test suite**

Run: `go test -v ./pkg/scanner/ -run TestCertificate -count=1`
Expected: All existing tests still PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/certificate.go pkg/scanner/certificate_test.go
git commit -m "feat(scanner): expanded PKCS#12 password support + fail-open for locked containers"
```

---

### Task 3: PKCS#7 Proper Parsing (Section 3)

**Files:**
- Modify: `go.mod`, `go.sum`
- Modify: `pkg/scanner/certificate.go:110-153`
- Test: `pkg/scanner/certificate_test.go`

- [ ] **Step 1: Add `go.mozilla.org/pkcs7` dependency**

Run: `go get go.mozilla.org/pkcs7`

- [ ] **Step 2: Write failing test for PKCS#7 multi-cert bundle**

Add to `pkg/scanner/certificate_test.go`:

```go
func TestParsePKCS7_MultiCertChain(t *testing.T) {
    t.Parallel()

    // Generate a CA + leaf certificate chain
    caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    require.NoError(t, err)

    caTemplate := &x509.Certificate{
        SerialNumber: big.NewInt(100),
        Subject:      pkix.Name{CommonName: "p7b-test-ca"},
        NotBefore:    time.Now().Add(-time.Hour),
        NotAfter:     time.Now().Add(24 * time.Hour),
        IsCA:         true,
        KeyUsage:     x509.KeyUsageCertSign,
        BasicConstraintsValid: true,
    }
    caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
    require.NoError(t, err)
    caCert, err := x509.ParseCertificate(caDER)
    require.NoError(t, err)

    leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    require.NoError(t, err)
    leafTemplate := &x509.Certificate{
        SerialNumber: big.NewInt(101),
        Subject:      pkix.Name{CommonName: "p7b-test-leaf"},
        NotBefore:    time.Now().Add(-time.Hour),
        NotAfter:     time.Now().Add(24 * time.Hour),
    }
    leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
    require.NoError(t, err)

    // Build a PKCS#7 SignedData with both certs (no signer — certs-only bundle)
    p7Bundle, err := buildCertsOnlyPKCS7(caDER, leafDER)
    require.NoError(t, err)

    tmpDir := t.TempDir()
    p7bFile := filepath.Join(tmpDir, "chain.p7b")
    require.NoError(t, os.WriteFile(p7bFile, p7Bundle, 0o644))

    m := NewCertificateModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 10)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err = m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    assert.Len(t, found, 2, "should find both CA and leaf cert from .p7b bundle")
}

// buildCertsOnlyPKCS7 creates a minimal DER-encoded PKCS#7 SignedData
// containing only certificates (no signers). This is the standard .p7b format.
func buildCertsOnlyPKCS7(certs ...[]byte) ([]byte, error) {
    cb := pkcs7.NewBuilder(nil, nil, nil)
    for _, c := range certs {
        cert, err := x509.ParseCertificate(c)
        if err != nil {
            return nil, err
        }
        cb.AddCertificate(cert)
    }
    return cb.Finish()
}
```

Note: The `buildCertsOnlyPKCS7` helper above uses `go.mozilla.org/pkcs7`'s builder API. If the library doesn't expose a builder, construct the DER manually using `encoding/asn1`. The test helper becomes:

```go
import (
    "encoding/asn1"
    gopkcs7 "go.mozilla.org/pkcs7"
)

// buildCertsOnlyPKCS7 creates a degenerate PKCS#7 SignedData (no signers, certs only).
func buildCertsOnlyPKCS7(certsDER ...[]byte) ([]byte, error) {
    // OID for signedData: 1.2.840.113549.1.7.2
    oidSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
    oidData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}

    var rawCerts []asn1.RawValue
    for _, der := range certsDER {
        rawCerts = append(rawCerts, asn1.RawValue{FullBytes: der})
    }

    type signedData struct {
        Version          int
        DigestAlgorithms asn1.RawValue `asn1:"set"`
        ContentInfo      struct {
            ContentType asn1.ObjectIdentifier
        }
        Certificates asn1.RawValue `asn1:"optional,tag:0"`
    }

    certsBytes, err := asn1.Marshal(rawCerts)
    if err != nil {
        return nil, err
    }

    sd := signedData{
        Version:          1,
        DigestAlgorithms: asn1.RawValue{Tag: 17, Class: asn1.ClassUniversal, IsCompound: true, Bytes: []byte{}},
        ContentInfo: struct {
            ContentType asn1.ObjectIdentifier
        }{ContentType: oidData},
        Certificates: asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, IsCompound: true, Bytes: certsBytes},
    }

    sdBytes, err := asn1.Marshal(sd)
    if err != nil {
        return nil, err
    }

    type contentInfo struct {
        ContentType asn1.ObjectIdentifier
        Content     asn1.RawValue `asn1:"explicit,tag:0"`
    }

    ci := contentInfo{
        ContentType: oidSignedData,
        Content:     asn1.RawValue{FullBytes: sdBytes},
    }
    return asn1.Marshal(ci)
}
```

Adjust the test helper based on what the `go.mozilla.org/pkcs7` library actually exposes — the goal is a DER PKCS#7 with 2 certs.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test -v -run "TestParsePKCS7" ./pkg/scanner/`
Expected: FAIL — current code doesn't parse PKCS#7 properly.

- [ ] **Step 4: Implement PKCS#7 parsing in `parseCertificateFile`**

In `pkg/scanner/certificate.go`, add the import and update `parseCertificateFile`:

```go
import (
    gopkcs7 "go.mozilla.org/pkcs7"
)
```

In `parseCertificateFile`, add a PKCS#7 branch after the JKS check and before the PEM fallback:

```go
// PKCS#7 / CMS (.p7b, .p7c) — may contain certificate chains
if ext == ".p7b" || ext == ".p7c" {
    return m.parsePKCS7(data)
}
```

Add the parser method:

```go
// parsePKCS7 extracts certificates from a PKCS#7/CMS SignedData structure.
// Handles both raw DER and PEM-wrapped PKCS#7. Returns all embedded certs.
func (m *CertificateModule) parsePKCS7(data []byte) ([]*x509.Certificate, error) {
    // Try PEM unwrap first
    if block, _ := pem.Decode(data); block != nil {
        data = block.Bytes
    }

    p7, err := gopkcs7.Parse(data)
    if err != nil {
        return nil, err
    }

    if len(p7.Certificates) == 0 {
        return nil, fmt.Errorf("PKCS#7 contains no certificates")
    }

    return p7.Certificates, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test -v -run "TestParsePKCS7" ./pkg/scanner/`
Expected: PASS.

- [ ] **Step 6: Run full test suite**

Run: `go test -v ./pkg/scanner/ -run TestCertificate -count=1`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum pkg/scanner/certificate.go pkg/scanner/certificate_test.go
git commit -m "feat(scanner): PKCS#7 proper parsing — extract all certs from .p7b/.p7c bundles"
```

---

### Task 4: JCEKS/BKS Format Detection + JKS Full Parsing via keytool (Sections 1 & 7)

**Files:**
- Modify: `pkg/scanner/certificate.go`
- Test: `pkg/scanner/certificate_test.go`

- [ ] **Step 1: Write failing test for JCEKS magic byte detection**

Add to `pkg/scanner/certificate_test.go`:

```go
func TestCertificateModule_JCEKSDetection(t *testing.T) {
    t.Parallel()

    tmpDir := t.TempDir()
    // JCEKS magic bytes: 0xCECECECE followed by junk
    jceksData := []byte{0xCE, 0xCE, 0xCE, 0xCE, 0x00, 0x00, 0x00, 0x02}
    jceksFile := filepath.Join(tmpDir, "creds.jceks")
    require.NoError(t, os.WriteFile(jceksFile, jceksData, 0o644))

    m := NewCertificateModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 10)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err := m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    require.Len(t, found, 1, "should detect JCEKS keystore")
    assert.Contains(t, found[0].CryptoAsset.Function, "JCEKS")
}

func TestCertificateModule_NewExtensions(t *testing.T) {
    t.Parallel()

    m := NewCertificateModule(&scannerconfig.Config{})
    // New extensions should be matched
    assert.True(t, m.isCertificateFile("/path/to/creds.jceks"))
    assert.True(t, m.isCertificateFile("/path/to/store.bks"))
    assert.True(t, m.isCertificateFile("/path/to/app.keystore"))
    assert.True(t, m.isCertificateFile("/path/to/ca.truststore"))
    assert.True(t, m.isCertificateFile("/path/to/uber.uber"))
    // Existing extensions still work
    assert.True(t, m.isCertificateFile("/path/to/cert.pem"))
    assert.True(t, m.isCertificateFile("/path/to/key.jks"))
    // Non-cert files still rejected
    assert.False(t, m.isCertificateFile("/path/to/readme.txt"))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestCertificateModule_(JCEKSDetection|NewExtensions)" ./pkg/scanner/`
Expected: Both FAIL.

- [ ] **Step 3: Implement new extensions and magic byte detection**

Update `isCertificateFile` in `certificate.go`:

```go
func (m *CertificateModule) isCertificateFile(path string) bool {
    ext := strings.ToLower(filepath.Ext(path))
    return ext == ".pem" || ext == ".crt" || ext == ".cer" ||
        ext == ".der" || ext == ".p7b" || ext == ".p7c" ||
        ext == ".p12" || ext == ".pfx" || ext == ".jks" ||
        ext == ".jceks" || ext == ".bks" || ext == ".uber" ||
        ext == ".keystore" || ext == ".truststore"
}
```

Add magic byte constants and detection:

```go
// isJCEKSMagic detects JCEKS keystore format (magic: 0xCECECECE).
func isJCEKSMagic(b []byte) bool {
    return len(b) >= 4 && binary.BigEndian.Uint32(b) == 0xCECECECE
}
```

Update `parseCertificateFile` to handle new extensions. After the JKS branch, add:

```go
// JCEKS keystores
if ext == ".jceks" {
    if len(data) >= 4 && isJCEKSMagic(data[:4]) {
        return m.parseKeystoreViaKeytool(ctx, path, "JCEKS")
    }
    return nil, fmt.Errorf("not a valid JCEKS file")
}

// BKS / UBER keystores
if ext == ".bks" || ext == ".uber" {
    return m.parseKeystoreViaKeytool(ctx, path, "BKS")
}

// Generic .keystore / .truststore — try keytool with auto-detect
if ext == ".keystore" || ext == ".truststore" {
    return m.parseKeystoreViaKeytool(ctx, path, "")
}
```

Also update the JKS branch to use keytool instead of just reporting opaque:

```go
// JKS (Java KeyStore) — try keytool first, fall back to opaque container
if ext == ".jks" {
    if len(data) >= 4 && isJKSMagic(data[:4]) {
        return m.parseKeystoreViaKeytool(ctx, path, "JKS")
    }
    return nil, fmt.Errorf("not a valid JKS file")
}
```

- [ ] **Step 4: Implement `parseKeystoreViaKeytool`**

Add to `certificate.go`:

```go
// parseKeystoreViaKeytool shells out to keytool to extract certs from a
// keystore. storeType is "JKS", "JCEKS", "BKS", or "" (auto-detect).
// Returns the extracted certs. If keytool is unavailable or all passwords
// fail, returns (nil, nil) — the caller creates a container/locked finding.
func (m *CertificateModule) parseKeystoreViaKeytool(ctx context.Context, path, storeType string) ([]*x509.Certificate, error) {
    keytoolBin := discoverKeytool()
    if keytoolBin == "" {
        return nil, nil // keytool not found — caller emits container finding
    }

    for _, pw := range m.keystorePasswords() {
        args := []string{"-list", "-rfc", "-keystore", path, "-storepass", pw}
        if storeType != "" {
            args = append(args, "-storetype", storeType)
        }

        subCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
        out, err := m.runKeytool(subCtx, keytoolBin, args...)
        cancel()

        if err != nil {
            continue // wrong password or keytool error — try next
        }

        certs := parsePEMCertsFromBytes(out)
        if len(certs) > 0 {
            return certs, nil
        }
    }

    return nil, nil // all passwords failed — caller emits locked finding
}

// discoverKeytool finds the keytool binary. Checks JAVA_HOME/bin first,
// then falls back to PATH lookup.
func discoverKeytool() string {
    for _, env := range []string{"JAVA_HOME", "JDK_HOME"} {
        if home := os.Getenv(env); home != "" {
            candidate := filepath.Join(home, "bin", "keytool")
            if _, err := os.Stat(candidate); err == nil {
                return candidate
            }
        }
    }
    if path, err := exec.LookPath("keytool"); err == nil {
        return path
    }
    return ""
}

// runKeytool executes keytool with a stdout cap for safety.
func (m *CertificateModule) runKeytool(ctx context.Context, keytoolBin string, args ...string) ([]byte, error) {
    cmd := exec.CommandContext(ctx, keytoolBin, args...)
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return nil, err
    }
    if err := cmd.Start(); err != nil {
        return nil, err
    }
    const maxKeytoolStdout = 32 * 1024 * 1024 // 32MB
    out, readErr := io.ReadAll(io.LimitReader(stdout, maxKeytoolStdout))
    _, _ = io.Copy(io.Discard, stdout) // drain excess
    waitErr := cmd.Wait()
    if readErr != nil {
        return out, readErr
    }
    return out, waitErr
}

// parsePEMCertsFromBytes extracts X.509 certs from PEM data (ignoring non-CERTIFICATE blocks).
func parsePEMCertsFromBytes(pemData []byte) []*x509.Certificate {
    var certs []*x509.Certificate
    rest := pemData
    for len(rest) > 0 {
        var block *pem.Block
        block, rest = pem.Decode(rest)
        if block == nil {
            break
        }
        if block.Type != "CERTIFICATE" {
            continue
        }
        cert, err := x509.ParseCertificate(block.Bytes)
        if err == nil {
            certs = append(certs, cert)
        }
    }
    return certs
}
```

Add `"io"` and `"os/exec"` to the import block.

- [ ] **Step 5: Update Scan method to handle keytool results**

Update the `processFile` closure in `Scan()` to handle the new keystore types. Replace the existing JKS-only block with a generic keystore handler:

```go
processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
    ext := strings.ToLower(filepath.Ext(path))

    certs, err := m.parseCertificateFile(ctx, reader, path)

    // Fail-open for locked PKCS#12/PFX containers
    if err == errPKCS12Locked {
        finding := m.createLockedContainerFinding(path, "PKCS#12")
        select {
        case findings <- finding:
        case <-ctx.Done():
            return ctx.Err()
        }
        return nil
    }

    // Keystore types: if keytool returned 0 certs, emit container finding
    isKeystore := ext == ".jks" || ext == ".jceks" || ext == ".bks" ||
        ext == ".uber" || ext == ".keystore" || ext == ".truststore"
    if isKeystore && err == nil && len(certs) == 0 {
        containerType := strings.ToUpper(strings.TrimPrefix(ext, "."))
        if ext == ".keystore" || ext == ".truststore" {
            containerType = "Java"
        }
        finding := m.createLockedContainerFinding(path, containerType)
        select {
        case findings <- finding:
        case <-ctx.Done():
            return ctx.Err()
        }
        return nil
    }

    if err != nil {
        return nil // Skip other parse errors
    }

    for _, cert := range certs {
        finding := m.createFinding(path, cert)
        select {
        case findings <- finding:
        case <-ctx.Done():
            return ctx.Err()
        }
    }
    return nil
},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test -v -run "TestCertificateModule_(JCEKSDetection|NewExtensions)" ./pkg/scanner/`
Expected: Both PASS.

- [ ] **Step 7: Run full test suite**

Run: `go test -v ./pkg/scanner/ -run TestCertificate -count=1 && go test -v ./pkg/scanner/ -run TestParsePKCS -count=1`
Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add pkg/scanner/certificate.go pkg/scanner/certificate_test.go
git commit -m "feat(scanner): JKS/JCEKS/BKS full keystore parsing via keytool + new extension detection"
```

---

### Task 5: Encrypted Private Key Detection (Section 6)

**Files:**
- Modify: `pkg/scanner/key.go`
- Test: `pkg/scanner/key_test.go`

- [ ] **Step 1: Write failing tests for encrypted key detection**

Add to `pkg/scanner/key_test.go`:

```go
func TestKeyModule_EncryptedRFC1423(t *testing.T) {
    t.Parallel()

    // RFC 1423 encrypted RSA private key (DEK-Info header)
    encryptedPEM := `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,AABBCCDD00112233AABBCCDD00112233

SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBmYWtlIGVuY3J5cHRlZCBrZXkgYm9keQ==
-----END RSA PRIVATE KEY-----`

    tmpDir := t.TempDir()
    keyFile := filepath.Join(tmpDir, "encrypted.key")
    require.NoError(t, os.WriteFile(keyFile, []byte(encryptedPEM), 0o600))

    m := NewKeyModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 10)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err := m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    require.Len(t, found, 1, "should detect encrypted RSA private key")
    assert.Equal(t, "RSA", found[0].CryptoAsset.Algorithm)
    assert.Contains(t, found[0].CryptoAsset.Purpose, "encrypted")
    assert.Contains(t, found[0].CryptoAsset.Purpose, "AES-256-CBC")
    assert.Equal(t, 0, found[0].CryptoAsset.KeySize)
}

func TestKeyModule_EncryptedPKCS8(t *testing.T) {
    t.Parallel()

    encryptedPEM := `-----BEGIN ENCRYPTED PRIVATE KEY-----
SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBmYWtlIGVuY3J5cHRlZCBQS0NTIzgg
a2V5IGJvZHkgdGhhdCB3b250IHBhcnNl
-----END ENCRYPTED PRIVATE KEY-----`

    tmpDir := t.TempDir()
    keyFile := filepath.Join(tmpDir, "pkcs8-encrypted.key")
    require.NoError(t, os.WriteFile(keyFile, []byte(encryptedPEM), 0o600))

    m := NewKeyModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 10)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err := m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    require.Len(t, found, 1, "should detect encrypted PKCS#8 private key")
    assert.Contains(t, found[0].CryptoAsset.Function, "encrypted")
}

func TestKeyModule_EncryptedOpenSSH(t *testing.T) {
    t.Parallel()

    // OpenSSH encrypted key — header says "openssh-key-v1" followed by
    // cipher name. We use a minimal fake that has the right structure.
    encryptedPEM := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB
-----END OPENSSH PRIVATE KEY-----`

    tmpDir := t.TempDir()
    keyFile := filepath.Join(tmpDir, "id_ed25519_enc")
    require.NoError(t, os.WriteFile(keyFile, []byte(encryptedPEM), 0o600))

    m := NewKeyModule(&scannerconfig.Config{})
    findings := make(chan *model.Finding, 10)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err := m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    require.Len(t, found, 1, "should detect encrypted OpenSSH key")
    assert.Contains(t, found[0].CryptoAsset.Purpose, "encrypted")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestKeyModule_Encrypted" ./pkg/scanner/`
Expected: FAIL — encrypted keys currently return nil finding.

- [ ] **Step 3: Implement encrypted key detection in `detectPEMKey`**

In `pkg/scanner/key.go`, update `detectPEMKey` to handle encrypted keys. Add a new check before the existing `detectKeyTypeAndAlgorithm` call:

```go
func (m *KeyModule) detectPEMKey(data []byte, content string) (keyType, algorithm string, keySize int, pub stdcrypto.PublicKey) {
    // Check for encrypted keys first — these can't be parsed but should be reported.
    if ekType, ekAlgo, ekPurpose := m.detectEncryptedKey(data, content); ekType != "" {
        return ekType, ekAlgo, 0, nil // keySize=0, no public key extractable
    }

    // ... rest of existing detectPEMKey unchanged ...
    keyType, algorithm = m.detectKeyTypeAndAlgorithm(content)
    // ...
}
```

Wait — this won't work because `detectPEMKey` only returns 4 values and we need to pass the `Purpose` string. Instead, modify `parseKeyFile` to check for encrypted keys separately:

```go
func (m *KeyModule) parseKeyFile(ctx context.Context, reader fsadapter.FileReader, path string) (*model.Finding, error) {
    data, err := reader.ReadFile(ctx, path)
    if err != nil {
        return nil, err
    }

    content := string(data)

    // Check for encrypted keys first — report them even though we can't parse contents.
    if finding := m.detectEncryptedKeyFinding(data, content, path); finding != nil {
        return finding, nil
    }

    // Try PEM-based key detection first
    keyType, algorithm, keySize, pubKey := m.detectPEMKey(data, content)

    // ... rest unchanged ...
}
```

Add the encrypted key detection method:

```go
// detectEncryptedKeyFinding checks if the data contains an encrypted private
// key (RFC 1423, PKCS#8 encrypted, or OpenSSH encrypted). Returns a finding
// with Purpose describing the encryption, or nil if not encrypted.
func (m *KeyModule) detectEncryptedKeyFinding(data []byte, content, path string) *model.Finding {
    block, _ := pem.Decode(data)
    if block == nil {
        return nil
    }

    var keyType, algorithm, purpose string

    switch {
    case block.Type == "ENCRYPTED PRIVATE KEY":
        // PKCS#8 encrypted
        keyType = "pkcs8-encrypted-private"
        algorithm = "Unknown"
        purpose = "encrypted private key (PKCS#8)"

    case block.Headers["Proc-Type"] == "4,ENCRYPTED":
        // RFC 1423 encrypted — DEK-Info tells us the cipher and outer key type
        dekInfo := block.Headers["DEK-Info"]
        cipher := "unknown"
        if parts := strings.SplitN(dekInfo, ",", 2); len(parts) > 0 && parts[0] != "" {
            cipher = parts[0]
        }
        // Derive key type from PEM block type
        switch {
        case strings.Contains(block.Type, "RSA"):
            algorithm = "RSA"
        case strings.Contains(block.Type, "EC"):
            algorithm = "ECDSA"
        case strings.Contains(block.Type, "DSA"):
            algorithm = "DSA"
        default:
            algorithm = "Unknown"
        }
        keyType = "encrypted-private"
        purpose = fmt.Sprintf("encrypted private key (%s, cipher: %s)", algorithm, cipher)

    case block.Type == "OPENSSH PRIVATE KEY":
        // OpenSSH format — check if cipher is "none" (unencrypted) or something else.
        // The binary format after base64 decode starts with "openssh-key-v1\0"
        // followed by: ciphername (string), kdfname (string), ...
        cipherName := extractOpenSSHCipher(block.Bytes)
        if cipherName == "" || cipherName == "none" {
            return nil // not encrypted — let normal parser handle it
        }
        keyType = "openssh-encrypted-private"
        algorithm = "Unknown"
        purpose = fmt.Sprintf("encrypted private key (OpenSSH, cipher: %s)", cipherName)

    default:
        return nil
    }

    asset := &model.CryptoAsset{
        ID:        uuid.Must(uuid.NewV7()).String(),
        Function:  keyType,
        Algorithm: algorithm,
        KeySize:   0, // unknown without decryption
        Purpose:   purpose,
    }
    crypto.ClassifyCryptoAsset(asset)

    return &model.Finding{
        ID:       uuid.Must(uuid.NewV7()).String(),
        Category: 5,
        Source: model.FindingSource{
            Type: "file",
            Path: path,
        },
        CryptoAsset: asset,
        Confidence:  0.85,
        Module:      "keys",
        Timestamp:   time.Now(),
    }
}

// extractOpenSSHCipher parses the cipher name from OpenSSH private key binary format.
// Format: "openssh-key-v1\0" magic, then ciphername as SSH string (uint32 len + bytes).
func extractOpenSSHCipher(data []byte) string {
    magic := "openssh-key-v1\x00"
    if len(data) < len(magic)+4 {
        return ""
    }
    if string(data[:len(magic)]) != magic {
        return ""
    }
    rest := data[len(magic):]
    if len(rest) < 4 {
        return ""
    }
    nameLen := int(binary.BigEndian.Uint32(rest[:4]))
    rest = rest[4:]
    if len(rest) < nameLen || nameLen > 64 {
        return ""
    }
    return string(rest[:nameLen])
}
```

Add `"encoding/binary"` to the import block if not already present.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run "TestKeyModule_Encrypted" ./pkg/scanner/`
Expected: All 3 PASS.

- [ ] **Step 5: Run full key test suite**

Run: `go test -v ./pkg/scanner/ -run TestKey -count=1`
Expected: All tests PASS (no regression).

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/key.go pkg/scanner/key_test.go
git commit -m "feat(scanner): detect encrypted private keys (RFC 1423, PKCS#8, OpenSSH) instead of silently skipping"
```

---

### Task 6: Windows Intermediate/Personal Certificate Stores (Section 4)

**Files:**
- Modify: `pkg/scanner/certstore.go:178-199`
- Test: `pkg/scanner/certstore_test.go`

- [ ] **Step 1: Write failing test for additional Windows stores**

Add to `pkg/scanner/certstore_test.go`:

```go
func TestWindowsCertStore_AdditionalStores(t *testing.T) {
    t.Parallel()

    // Generate a test cert to use in mock output
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    require.NoError(t, err)

    template := &x509.Certificate{
        SerialNumber: big.NewInt(200),
        Subject:      pkix.Name{CommonName: "win-intermediate-ca"},
        NotBefore:    time.Now().Add(-time.Hour),
        NotAfter:     time.Now().Add(24 * time.Hour),
        IsCA:         true,
    }
    certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    require.NoError(t, err)
    b64DER := base64.StdEncoding.EncodeToString(certDER)

    // Track which PowerShell scripts were called
    var calledStores []string
    var mu sync.Mutex

    m := &CertStoreModule{
        config: &scannerconfig.Config{},
        cmdRunner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
            return nil, fmt.Errorf("not used")
        },
        cmdRunnerLimited: func(ctx context.Context, limit int64, name string, args ...string) ([]byte, error) {
            // Extract the store path from the PowerShell command
            for _, arg := range args {
                if strings.Contains(arg, "Cert:\\") {
                    mu.Lock()
                    calledStores = append(calledStores, arg)
                    mu.Unlock()
                }
            }
            return []byte(b64DER + "\n"), nil
        },
    }

    findings := make(chan *model.Finding, 50)
    ctx := context.Background()

    // Only test the Windows path — mock always returns certs
    err = m.scanWindowsCertStores(ctx, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }

    // Should have findings from 5 stores (1 cert each from our mock)
    assert.GreaterOrEqual(t, len(found), 5, "should scan 5 Windows certificate stores")

    // Verify different source paths
    paths := make(map[string]bool)
    for _, f := range found {
        paths[f.Source.Path] = true
    }
    assert.True(t, paths["os:certstore:windows:LocalMachine\\Root"], "should scan LocalMachine\\Root")
    assert.True(t, paths["os:certstore:windows:LocalMachine\\CA"], "should scan LocalMachine\\CA")
    assert.True(t, paths["os:certstore:windows:LocalMachine\\My"], "should scan LocalMachine\\My")
    assert.True(t, paths["os:certstore:windows:CurrentUser\\Root"], "should scan CurrentUser\\Root")
    assert.True(t, paths["os:certstore:windows:CurrentUser\\My"], "should scan CurrentUser\\My")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run "TestWindowsCertStore_AdditionalStores" ./pkg/scanner/`
Expected: FAIL — `scanWindowsCertStores` doesn't exist yet.

- [ ] **Step 3: Implement additional Windows stores**

In `pkg/scanner/certstore.go`, replace `scanWindowsCertStore` with a multi-store version:

```go
// windowsCertStore describes a Windows certificate store to enumerate.
type windowsCertStore struct {
    path       string // e.g., "LocalMachine\\Root"
    sourcePath string // e.g., "os:certstore:windows:LocalMachine\\Root"
    purpose    string // e.g., "System trust anchor (Windows Root store)"
}

var windowsCertStores = []windowsCertStore{
    {`Cert:\LocalMachine\Root`, `os:certstore:windows:LocalMachine\Root`, "System trust anchor (Windows Root store)"},
    {`Cert:\LocalMachine\CA`, `os:certstore:windows:LocalMachine\CA`, "Intermediate CA (Windows)"},
    {`Cert:\LocalMachine\My`, `os:certstore:windows:LocalMachine\My`, "Machine certificate (Windows)"},
    {`Cert:\CurrentUser\Root`, `os:certstore:windows:CurrentUser\Root`, "User trust anchor (Windows)"},
    {`Cert:\CurrentUser\My`, `os:certstore:windows:CurrentUser\My`, "User certificate (Windows)"},
}

// scanWindowsCertStores enumerates all configured Windows certificate stores.
func (m *CertStoreModule) scanWindowsCertStores(ctx context.Context, findings chan<- *model.Finding) error {
    for _, store := range windowsCertStores {
        if err := ctx.Err(); err != nil {
            return err
        }
        _ = m.scanOneWindowsStore(ctx, store, findings)
    }
    return nil
}

// scanOneWindowsStore enumerates a single Windows certificate store via PowerShell.
func (m *CertStoreModule) scanOneWindowsStore(ctx context.Context, store windowsCertStore, findings chan<- *model.Finding) error {
    subCtx, cancel := context.WithTimeout(ctx, certstoreSubprocessTimeout)
    defer cancel()

    script := fmt.Sprintf(`Get-ChildItem %s | ForEach-Object { [Convert]::ToBase64String($_.RawData) }`, store.path)
    out, err := m.cmdRunnerLimited(subCtx, windowsRootStoreStdoutCap,
        "powershell", "-NoProfile", "-Command", script)
    if err != nil {
        return nil // Store inaccessible — skip
    }
    return m.parseBase64DERList(ctx, out, store.sourcePath, store.purpose, findings)
}
```

Update the `Scan` method's Windows branch to call `scanWindowsCertStores`:

```go
case "windows":
    _ = m.scanWindowsCertStores(ctx, findings)
```

Remove the old `scanWindowsCertStore` (singular) method.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run "TestWindowsCertStore_AdditionalStores" ./pkg/scanner/`
Expected: PASS.

- [ ] **Step 5: Run full certstore test suite**

Run: `go test -v ./pkg/scanner/ -run TestCertStore -count=1`
Expected: All existing tests PASS (update any that reference the old `scanWindowsCertStore` method).

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/certstore.go pkg/scanner/certstore_test.go
git commit -m "feat(scanner): enumerate all Windows certificate stores (Root, CA, My for LocalMachine + CurrentUser)"
```

---

### Task 7: Archive Extraction Module (Section 2)

**Files:**
- Create: `pkg/scanner/archive.go`
- Create: `pkg/scanner/archive_test.go`
- Modify: `pkg/scanner/engine.go:120-170`
- Modify: `internal/scannerconfig/config.go:63-106`

- [ ] **Step 1: Write failing test for ZIP archive with embedded cert**

Create `pkg/scanner/archive_test.go`:

```go
package scanner

import (
    "archive/zip"
    "bytes"
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
)

var _ Module = (*ArchiveModule)(nil)

func TestArchiveModule_Interface(t *testing.T) {
    t.Parallel()
    m := NewArchiveModule(&scannerconfig.Config{})
    assert.Equal(t, "archive", m.Name())
    assert.Equal(t, model.CategoryPassiveFile, m.Category())
    assert.Equal(t, model.TargetFilesystem, m.ScanTargetType())
}

func TestArchiveModule_ZipWithCert(t *testing.T) {
    t.Parallel()

    // Generate a PEM cert
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    require.NoError(t, err)
    template := &x509.Certificate{
        SerialNumber: big.NewInt(300),
        Subject:      pkix.Name{CommonName: "archive-test-cert"},
        NotBefore:    time.Now().Add(-time.Hour),
        NotAfter:     time.Now().Add(24 * time.Hour),
    }
    certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    require.NoError(t, err)

    var certPEM bytes.Buffer
    require.NoError(t, pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

    // Create a ZIP containing the cert
    var zipBuf bytes.Buffer
    zw := zip.NewWriter(&zipBuf)
    fw, err := zw.Create("META-INF/server.crt")
    require.NoError(t, err)
    _, err = fw.Write(certPEM.Bytes())
    require.NoError(t, err)
    require.NoError(t, zw.Close())

    tmpDir := t.TempDir()
    zipFile := filepath.Join(tmpDir, "app.jar")
    require.NoError(t, os.WriteFile(zipFile, zipBuf.Bytes(), 0o644))

    m := NewArchiveModule(&scannerconfig.Config{MaxFileSize: 100 * 1024 * 1024})
    findings := make(chan *model.Finding, 10)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err = m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    require.Len(t, found, 1, "should find cert inside JAR")
    assert.Contains(t, found[0].Source.Path, "app.jar!")
    assert.Contains(t, found[0].Source.Path, "server.crt")
    assert.Equal(t, "ECDSA-P256", found[0].CryptoAsset.Algorithm)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run "TestArchiveModule" ./pkg/scanner/`
Expected: FAIL — `ArchiveModule` doesn't exist yet.

- [ ] **Step 3: Implement `ArchiveModule` core**

Create `pkg/scanner/archive.go`:

```go
package scanner

import (
    "archive/tar"
    "archive/zip"
    "bytes"
    "compress/bzip2"
    "compress/gzip"
    "context"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io"
    "path/filepath"
    "strings"
    "sync/atomic"
    "time"

    "github.com/google/uuid"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/crypto"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner/fsadapter"
    "github.com/amiryahaya/triton/pkg/store"
)

// Archive safety limits.
const (
    archiveMaxEntrySize    = 50 * 1024 * 1024  // 50MB per entry
    archiveMaxTotalExtract = 256 * 1024 * 1024  // 256MB total per archive
    archiveMaxEntries      = 10_000             // zip bomb protection
    archiveMaxNestDepth    = 2                  // WAR→JAR→cert (2 levels)
)

type ArchiveModule struct {
    config      *scannerconfig.Config
    lastScanned int64
    lastMatched int64
    store       store.Store
    reader      fsadapter.FileReader
}

func NewArchiveModule(cfg *scannerconfig.Config) *ArchiveModule {
    return &ArchiveModule{config: cfg}
}

func (m *ArchiveModule) Name() string                         { return "archive" }
func (m *ArchiveModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *ArchiveModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *ArchiveModule) SetStore(s store.Store)               { m.store = s }
func (m *ArchiveModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }
func (m *ArchiveModule) FileStats() (scanned, matched int64) {
    return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *ArchiveModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
    atomic.StoreInt64(&m.lastScanned, 0)
    atomic.StoreInt64(&m.lastMatched, 0)
    return walkTarget(walkerConfig{
        ctx:          ctx,
        target:       target,
        config:       m.config,
        matchFile:    isArchiveFile,
        filesScanned: &m.lastScanned,
        filesMatched: &m.lastMatched,
        store:        m.store,
        reader:       m.reader,
        processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
            data, err := reader.ReadFile(ctx, path)
            if err != nil {
                return nil
            }
            return m.scanArchive(ctx, data, path, 1, findings)
        },
    })
}

func isArchiveFile(path string) bool {
    lower := strings.ToLower(path)
    ext := strings.ToLower(filepath.Ext(path))
    return ext == ".jar" || ext == ".war" || ext == ".ear" ||
        ext == ".zip" || ext == ".tar" ||
        strings.HasSuffix(lower, ".tar.gz") || ext == ".tgz" ||
        strings.HasSuffix(lower, ".tar.bz2")
}

// scanArchive dispatches to the right extractor based on content/extension.
func (m *ArchiveModule) scanArchive(ctx context.Context, data []byte, archivePath string, depth int, findings chan<- *model.Finding) error {
    lower := strings.ToLower(archivePath)
    ext := strings.ToLower(filepath.Ext(archivePath))

    // ZIP-based formats (JAR/WAR/EAR/ZIP)
    if ext == ".jar" || ext == ".war" || ext == ".ear" || ext == ".zip" {
        return m.scanZip(ctx, data, archivePath, depth, findings)
    }

    // TAR-based formats
    if strings.HasSuffix(lower, ".tar.gz") || ext == ".tgz" {
        gr, err := gzip.NewReader(bytes.NewReader(data))
        if err != nil {
            return nil
        }
        defer gr.Close()
        tarData, err := io.ReadAll(io.LimitReader(gr, archiveMaxTotalExtract))
        if err != nil {
            return nil
        }
        return m.scanTar(ctx, tarData, archivePath, depth, findings)
    }

    if strings.HasSuffix(lower, ".tar.bz2") {
        br := bzip2.NewReader(bytes.NewReader(data))
        tarData, err := io.ReadAll(io.LimitReader(br, archiveMaxTotalExtract))
        if err != nil {
            return nil
        }
        return m.scanTar(ctx, tarData, archivePath, depth, findings)
    }

    if ext == ".tar" {
        return m.scanTar(ctx, data, archivePath, depth, findings)
    }

    return nil
}

// scanZip extracts cert/key files from a ZIP archive.
func (m *ArchiveModule) scanZip(ctx context.Context, data []byte, archivePath string, depth int, findings chan<- *model.Finding) error {
    zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
    if err != nil {
        return nil
    }

    var totalExtracted int64
    for i, f := range zr.File {
        if err := ctx.Err(); err != nil {
            return err
        }
        if i >= archiveMaxEntries {
            break
        }
        if f.FileInfo().IsDir() {
            continue
        }
        if int64(f.UncompressedSize64) > archiveMaxEntrySize {
            continue
        }
        if totalExtracted+int64(f.UncompressedSize64) > archiveMaxTotalExtract {
            break
        }

        entryPath := archivePath + "!/" + f.Name

        // Nested archive — recurse if depth allows
        if depth < archiveMaxNestDepth && isArchiveFile(f.Name) {
            entryData, err := readZipEntry(f, archiveMaxEntrySize)
            if err != nil {
                continue
            }
            totalExtracted += int64(len(entryData))
            _ = m.scanArchive(ctx, entryData, entryPath, depth+1, findings)
            continue
        }

        // Check if entry is a cert/key file
        if !isCryptoFile(f.Name) {
            continue
        }

        entryData, err := readZipEntry(f, archiveMaxEntrySize)
        if err != nil {
            continue
        }
        totalExtracted += int64(len(entryData))

        m.processExtractedFile(ctx, entryData, entryPath, findings)
    }
    return nil
}

// scanTar extracts cert/key files from a TAR archive.
func (m *ArchiveModule) scanTar(ctx context.Context, data []byte, archivePath string, depth int, findings chan<- *model.Finding) error {
    tr := tar.NewReader(bytes.NewReader(data))
    var totalExtracted int64
    var entryCount int

    for {
        if err := ctx.Err(); err != nil {
            return err
        }
        hdr, err := tr.Next()
        if err == io.EOF {
            break
        }
        if err != nil {
            break
        }
        entryCount++
        if entryCount > archiveMaxEntries {
            break
        }
        if hdr.Typeflag != tar.TypeReg {
            continue
        }
        if hdr.Size > archiveMaxEntrySize {
            continue
        }
        if totalExtracted+hdr.Size > archiveMaxTotalExtract {
            break
        }

        entryPath := archivePath + "!/" + hdr.Name

        entryData, err := io.ReadAll(io.LimitReader(tr, archiveMaxEntrySize))
        if err != nil {
            continue
        }
        totalExtracted += int64(len(entryData))

        // Nested archive
        if depth < archiveMaxNestDepth && isArchiveFile(hdr.Name) {
            _ = m.scanArchive(ctx, entryData, entryPath, depth+1, findings)
            continue
        }

        if !isCryptoFile(hdr.Name) {
            continue
        }

        m.processExtractedFile(ctx, entryData, entryPath, findings)
    }
    return nil
}

// isCryptoFile returns true if the file could contain certs, keys, or keystores.
func isCryptoFile(path string) bool {
    ext := strings.ToLower(filepath.Ext(path))
    switch ext {
    case ".pem", ".crt", ".cer", ".der", ".p7b", ".p7c",
        ".p12", ".pfx", ".jks", ".jceks", ".bks", ".uber",
        ".keystore", ".truststore",
        ".key", ".priv", ".pub":
        return true
    }
    return false
}

// processExtractedFile parses an extracted file for certs/keys and emits findings.
func (m *ArchiveModule) processExtractedFile(ctx context.Context, data []byte, entryPath string, findings chan<- *model.Finding) {
    // Try certificate parsing
    certs := m.parseCertsFromBytes(data)
    for _, cert := range certs {
        finding := m.createCertFinding(entryPath, cert)
        select {
        case findings <- finding:
        case <-ctx.Done():
            return
        }
    }

    // Try key parsing (only if no certs found — avoid double-reporting .pem files)
    if len(certs) == 0 {
        if finding := m.parseKeyFromBytes(data, entryPath); finding != nil {
            select {
            case findings <- finding:
            case <-ctx.Done():
                return
            }
        }
    }
}

// parseCertsFromBytes extracts X.509 certificates from raw bytes (PEM or DER).
func (m *ArchiveModule) parseCertsFromBytes(data []byte) []*x509.Certificate {
    var certs []*x509.Certificate

    // Try PEM
    if bytes.Contains(data, []byte("BEGIN CERTIFICATE")) {
        rest := data
        for len(rest) > 0 {
            block, r := pem.Decode(rest)
            rest = r
            if block == nil {
                break
            }
            if block.Type == "CERTIFICATE" {
                cert, err := x509.ParseCertificate(block.Bytes)
                if err == nil {
                    certs = append(certs, cert)
                }
            }
        }
    }

    // Try DER if no PEM certs found
    if len(certs) == 0 {
        cert, err := x509.ParseCertificate(data)
        if err == nil {
            certs = append(certs, cert)
        }
    }

    return certs
}

// parseKeyFromBytes detects a key from raw bytes. Returns nil if no key found.
func (m *ArchiveModule) parseKeyFromBytes(data []byte, path string) *model.Finding {
    content := string(data)
    for _, h := range keyPEMHeaders {
        if strings.Contains(content, h.header) {
            asset := &model.CryptoAsset{
                ID:        uuid.Must(uuid.NewV7()).String(),
                Function:  h.keyType,
                Algorithm: h.algorithm,
            }
            crypto.ClassifyCryptoAsset(asset)
            return &model.Finding{
                ID:       uuid.Must(uuid.NewV7()).String(),
                Category: 5,
                Source:   model.FindingSource{Type: "file", Path: path},
                CryptoAsset: asset,
                Confidence:  0.85,
                Module:      "archive",
                Timestamp:   time.Now(),
            }
        }
    }
    return nil
}

// createCertFinding creates a finding from a cert found inside an archive.
func (m *ArchiveModule) createCertFinding(path string, cert *x509.Certificate) *model.Finding {
    algoName, keySize := certPublicKeyInfo(cert)
    notBefore := cert.NotBefore
    notAfter := cert.NotAfter

    asset := &model.CryptoAsset{
        ID:           uuid.Must(uuid.NewV7()).String(),
        Function:     "Certificate authentication",
        Algorithm:    algoName,
        KeySize:      keySize,
        Subject:      cert.Subject.String(),
        Issuer:       cert.Issuer.String(),
        SerialNumber: cert.SerialNumber.String(),
        NotBefore:    &notBefore,
        NotAfter:     &notAfter,
        IsCA:         cert.IsCA,
    }
    crypto.ClassifyCryptoAsset(asset)

    return &model.Finding{
        ID:       uuid.Must(uuid.NewV7()).String(),
        Category: 5,
        Source:   model.FindingSource{Type: "file", Path: path},
        CryptoAsset: asset,
        Confidence:  0.90,
        Module:      "archive",
        Timestamp:   time.Now(),
    }
}

// readZipEntry reads a zip file entry with a size cap.
func readZipEntry(f *zip.File, maxSize int64) ([]byte, error) {
    rc, err := f.Open()
    if err != nil {
        return nil, err
    }
    defer rc.Close()
    return io.ReadAll(io.LimitReader(rc, maxSize))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run "TestArchiveModule" ./pkg/scanner/`
Expected: All PASS.

- [ ] **Step 5: Write test for two-level nesting (WAR→JAR→cert)**

Add to `pkg/scanner/archive_test.go`:

```go
func TestArchiveModule_TwoLevelNesting(t *testing.T) {
    t.Parallel()

    // Generate a cert
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    require.NoError(t, err)
    template := &x509.Certificate{
        SerialNumber: big.NewInt(301),
        Subject:      pkix.Name{CommonName: "nested-cert"},
        NotBefore:    time.Now().Add(-time.Hour),
        NotAfter:     time.Now().Add(24 * time.Hour),
    }
    certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    require.NoError(t, err)
    var certPEM bytes.Buffer
    require.NoError(t, pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

    // Create inner JAR with cert
    var innerJar bytes.Buffer
    innerZW := zip.NewWriter(&innerJar)
    fw, err := innerZW.Create("META-INF/inner.crt")
    require.NoError(t, err)
    _, err = fw.Write(certPEM.Bytes())
    require.NoError(t, err)
    require.NoError(t, innerZW.Close())

    // Create outer WAR containing the inner JAR
    var outerWar bytes.Buffer
    outerZW := zip.NewWriter(&outerWar)
    fw, err = outerZW.Create("WEB-INF/lib/inner.jar")
    require.NoError(t, err)
    _, err = fw.Write(innerJar.Bytes())
    require.NoError(t, err)
    require.NoError(t, outerZW.Close())

    tmpDir := t.TempDir()
    warFile := filepath.Join(tmpDir, "app.war")
    require.NoError(t, os.WriteFile(warFile, outerWar.Bytes(), 0o644))

    m := NewArchiveModule(&scannerconfig.Config{MaxFileSize: 100 * 1024 * 1024})
    findings := make(chan *model.Finding, 10)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err = m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    require.Len(t, found, 1, "should find cert at depth 2 (WAR→JAR→cert)")
    assert.Contains(t, found[0].Source.Path, "app.war!/")
    assert.Contains(t, found[0].Source.Path, "inner.jar!/")
    assert.Contains(t, found[0].Source.Path, "inner.crt")
}

func TestArchiveModule_ZipBombProtection(t *testing.T) {
    t.Parallel()

    // Create a ZIP with more than archiveMaxEntries entries
    var zipBuf bytes.Buffer
    zw := zip.NewWriter(&zipBuf)
    for i := 0; i < 100; i++ {
        fw, err := zw.Create(fmt.Sprintf("file%d.crt", i))
        require.NoError(t, err)
        _, _ = fw.Write([]byte("not a real cert"))
    }
    require.NoError(t, zw.Close())

    tmpDir := t.TempDir()
    zipFile := filepath.Join(tmpDir, "many.zip")
    require.NoError(t, os.WriteFile(zipFile, zipBuf.Bytes(), 0o644))

    m := NewArchiveModule(&scannerconfig.Config{MaxFileSize: 100 * 1024 * 1024})
    findings := make(chan *model.Finding, 200)
    ctx := context.Background()
    target := model.ScanTarget{Type: model.TargetFilesystem, Value: tmpDir, Depth: 3}

    err := m.Scan(ctx, target, findings)
    require.NoError(t, err)
    close(findings)

    // Should complete without hanging — the protection prevents runaway extraction.
    // No real certs in the zip, so 0 findings expected.
    var found []*model.Finding
    for f := range findings {
        found = append(found, f)
    }
    assert.Empty(t, found)
}
```

- [ ] **Step 6: Run all archive tests**

Run: `go test -v -run "TestArchiveModule" ./pkg/scanner/`
Expected: All PASS.

- [ ] **Step 7: Register archive module in engine + profile**

In `pkg/scanner/engine.go`, add to `defaultModuleFactories` (after the `NewTPMModule` line):

```go
func(c *scannerconfig.Config) Module { return NewArchiveModule(c) },
```

In `internal/scannerconfig/config.go`, add `"archive"` to the `standard` and `comprehensive` module lists:

In the `standard` profile Modules slice, add `"archive"` at the end.
In the `comprehensive` profile Modules slice, add `"archive"` at the end.

- [ ] **Step 8: Run full test suite**

Run: `go test -v ./pkg/scanner/ -count=1`
Expected: All tests PASS.

- [ ] **Step 9: Commit**

```bash
git add pkg/scanner/archive.go pkg/scanner/archive_test.go pkg/scanner/engine.go internal/scannerconfig/config.go
git commit -m "feat(scanner): archive extraction module — scan certs/keys inside JAR/ZIP/TAR with 2-level nesting"
```

---

### Task 8: Integration Tests

**Files:**
- Create: `test/integration/pcert_parity_test.go`

- [ ] **Step 1: Write integration test covering multiple gaps**

Create `test/integration/pcert_parity_test.go`:

```go
//go:build integration

package integration

import (
    "archive/zip"
    "bytes"
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "software.sslmate.com/src/go-pkcs12"

    "github.com/amiryahaya/triton/internal/scannerconfig"
    "github.com/amiryahaya/triton/pkg/model"
    "github.com/amiryahaya/triton/pkg/scanner"
)

func TestPCertParity_FullScan(t *testing.T) {
    cfg := scannerconfig.Load("standard")
    cfg.Modules = []string{"certificates", "keys", "archive"}
    cfg.MaxDepth = 5

    tmpDir := t.TempDir()
    cfg.ScanTargets = []model.ScanTarget{
        {Type: model.TargetFilesystem, Value: tmpDir, Depth: 5},
    }

    // --- Seed test fixtures ---

    // 1. Plain PEM cert
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    require.NoError(t, err)
    template := &x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject:      pkix.Name{CommonName: "parity-pem"},
        NotBefore:    time.Now().Add(-time.Hour),
        NotAfter:     time.Now().Add(24 * time.Hour),
    }
    certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
    require.NoError(t, err)
    var certPEM bytes.Buffer
    require.NoError(t, pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
    require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "server.crt"), certPEM.Bytes(), 0o644))

    // 2. PKCS#12 with expanded password "password"
    cert, err := x509.ParseCertificate(certDER)
    require.NoError(t, err)
    p12Data, err := pkcs12.Encode(rand.Reader, key, cert, nil, "password")
    require.NoError(t, err)
    require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "expanded.p12"), p12Data, 0o644))

    // 3. Locked PKCS#12 (unknown password)
    lockedP12, err := pkcs12.Encode(rand.Reader, key, cert, nil, "impossiblePW!@#$")
    require.NoError(t, err)
    require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "locked.pfx"), lockedP12, 0o644))

    // 4. Encrypted private key (RFC 1423)
    encKeyPEM := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,AABB\n\nZmFrZWRhdGE=\n-----END RSA PRIVATE KEY-----\n"
    require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "encrypted.key"), []byte(encKeyPEM), 0o600))

    // 5. JAR with embedded cert
    var jarBuf bytes.Buffer
    zw := zip.NewWriter(&jarBuf)
    fw, err := zw.Create("META-INF/cert.pem")
    require.NoError(t, err)
    _, err = fw.Write(certPEM.Bytes())
    require.NoError(t, err)
    require.NoError(t, zw.Close())
    require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "lib.jar"), jarBuf.Bytes(), 0o644))

    // --- Run scan ---
    engine := scanner.New(cfg)
    engine.RegisterDefaultModules()

    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    result, err := engine.Run(ctx, nil)
    require.NoError(t, err)

    // --- Assert findings ---
    var (
        pemCert     int
        expandedP12 int
        lockedPFX   int
        encryptedKey int
        archiveCert int
    )

    for _, f := range result.Findings {
        switch {
        case f.Source.Path == filepath.Join(tmpDir, "server.crt"):
            pemCert++
        case f.Source.Path == filepath.Join(tmpDir, "expanded.p12"):
            expandedP12++
        case f.Source.Path == filepath.Join(tmpDir, "locked.pfx"):
            lockedPFX++
        case f.Source.Path == filepath.Join(tmpDir, "encrypted.key"):
            encryptedKey++
        case filepath.Base(f.Source.Path) == "lib.jar" || // archive parent
            (len(f.Source.Path) > 0 && bytes.Contains([]byte(f.Source.Path), []byte("lib.jar!/"))):
            archiveCert++
        }
    }

    assert.Equal(t, 1, pemCert, "should find plain PEM cert")
    assert.Equal(t, 1, expandedP12, "should decrypt PKCS#12 with expanded password list")
    assert.Equal(t, 1, lockedPFX, "should emit fail-open finding for locked PFX")
    assert.Equal(t, 1, encryptedKey, "should detect encrypted private key")
    assert.Equal(t, 1, archiveCert, "should find cert inside JAR archive")
}
```

- [ ] **Step 2: Run integration test**

Run: `go test -v -tags integration -run TestPCertParity ./test/integration/`
Expected: PASS — all 5 fixture types produce findings.

- [ ] **Step 3: Commit**

```bash
git add test/integration/pcert_parity_test.go
git commit -m "test(integration): PCert parity end-to-end test — PKCS#12 passwords, encrypted keys, archive extraction"
```

---

### Task 9: Update CLAUDE.md + Memory

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md scanner module count and archive module docs**

In `CLAUDE.md`, update the scanner module count from 30 to 31 (or current count). Add `archive.go` to the key packages list under `pkg/scanner/`:

```
  - `archive.go` — Archive extraction scanner: JAR/WAR/EAR/ZIP/TAR with 2-level nesting, zip bomb protection; delegates cert/key parsing to existing modules
```

Add `"archive"` to the standard and comprehensive profile descriptions.

Update the scan profiles section to note that archive is in standard + comprehensive.

- [ ] **Step 2: Update the `--keystore-passwords` flag in Build & Development Commands**

No new make targets needed — existing `make test` and `make test-integration` cover the new code.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for PCert parity sprint (archive module, keystore passwords, encrypted key detection)"
```

---

## Execution Order

Tasks can be partially parallelized:

```
Task 1 (config) ──→ Task 2 (PKCS#12 passwords) ──→ Task 4 (JKS/JCEKS/BKS via keytool)
                 ──→ Task 3 (PKCS#7)
                 ──→ Task 5 (encrypted keys)
                 ──→ Task 6 (Windows cert stores)
                 ──→ Task 7 (archive module)
                                                  ──→ Task 8 (integration tests)
                                                  ──→ Task 9 (docs)
```

- **Task 1** must go first (config field used by Tasks 2 and 4).
- **Tasks 2-7** can run in any order after Task 1, but Task 4 depends on Task 2's `keystorePasswords()` helper.
- **Task 8** runs after all feature tasks.
- **Task 9** runs last.
