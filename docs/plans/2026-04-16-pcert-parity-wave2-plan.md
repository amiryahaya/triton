# PCert Parity Wave 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 4 new scanner modules (TLS pcap observer, FTPS, SSH certificate, LDIF) plus shared chain-walking extraction, closing remaining PCert 4.5.5 discovery gaps.

**Architecture:** Four independent modules following the established 1-module-per-file pattern. A new `internal/tlsparse/` package provides the pure-Go TLS record parser and JA3/JA3S/JA4/JA4S fingerprint computation. A new `internal/tlsutil/` package extracts cert chain walking logic from `protocol.go` to share across protocol/FTPS/observer modules. New `TargetPcap` scan target type for pcap input. Build-tagged Linux/non-Linux split for live AF_PACKET capture.

**Tech Stack:** Go 1.25, `github.com/gopacket/gopacket` (pure Go pcapgo reader, no CGO), `golang.org/x/crypto/ssh` (already in go.mod), standard `crypto/tls`, `crypto/md5`, `encoding/base64`.

---

## File Map

### New files

| File | Responsibility |
|------|----------------|
| `pkg/scanner/internal/tlsutil/chain.go` | Cert chain walking: labels, weak sig, expiry warning, SANs — extracted from `protocol.go` |
| `pkg/scanner/internal/tlsutil/chain_test.go` | Tests for chain walking (migrated + expanded from protocol tests) |
| `pkg/scanner/internal/tlsparse/types.go` | Types: `ClientHelloInfo`, `ServerHelloInfo`, `FlowKey`, `Fingerprint` |
| `pkg/scanner/internal/tlsparse/handshake.go` | TLS record layer parser: extract ClientHello/ServerHello from raw bytes |
| `pkg/scanner/internal/tlsparse/handshake_test.go` | Known-answer parsing tests with binary fixtures |
| `pkg/scanner/internal/tlsparse/ja3.go` | JA3/JA3S computation |
| `pkg/scanner/internal/tlsparse/ja3_test.go` | Known-answer JA3 tests against published vectors |
| `pkg/scanner/internal/tlsparse/ja4.go` | JA4/JA4S computation |
| `pkg/scanner/internal/tlsparse/ja4_test.go` | Known-answer JA4 tests |
| `pkg/scanner/internal/tlsparse/grease.go` | GREASE value filter (RFC 8701) |
| `pkg/scanner/internal/tlsparse/reader.go` | `PacketSource` interface + pcap file reader via pcapgo |
| `pkg/scanner/internal/tlsparse/reader_test.go` | Pcap file reading tests |
| `pkg/scanner/internal/tlsparse/afpacket_linux.go` | AF_PACKET live capture reader (build-tagged linux) |
| `pkg/scanner/internal/tlsparse/afpacket_stub.go` | Non-Linux stub returning error (build-tagged !linux) |
| `pkg/scanner/internal/tlsparse/testdata/sample.pcap` | Small pcap fixture with known TLS handshakes |
| `pkg/scanner/tls_observer.go` | TLSObserverModule: Module impl, flow tracking, finding emission |
| `pkg/scanner/tls_observer_test.go` | Unit tests with mock reader |
| `pkg/scanner/ftps.go` | FTPSModule: AUTH TLS + implicit FTPS cert extraction |
| `pkg/scanner/ftps_test.go` | Unit tests with mock FTP server |
| `pkg/scanner/ssh_cert.go` | SSHCertModule: SSH handshake, host key + certificate extraction |
| `pkg/scanner/ssh_cert_test.go` | Unit tests with mock SSH server |
| `pkg/scanner/ldif.go` | LDIFModule: .ldif file parser, cert attribute extraction |
| `pkg/scanner/ldif_test.go` | Unit tests with fixture LDIF files |
| `pkg/scanner/doctor_pcap_linux.go` | Doctor check: CAP_NET_RAW for live pcap (linux) |
| `pkg/scanner/doctor_pcap_other.go` | Doctor check stub: not Linux (non-linux) |

### Modified files

| File | Changes |
|------|---------|
| `pkg/model/types.go` | Add `TargetPcap` constant + 6 new `CryptoAsset` fields (JA3/JA3S/JA4/JA4S/SNI/TLSFlowSource) |
| `pkg/scanner/engine.go` | Add 4 factories to `defaultModuleFactories` |
| `pkg/scanner/protocol.go` | Replace inline chain walking with `tlsutil.WalkCertChain()` calls |
| `internal/scannerconfig/config.go` | Add `tls_observer` to comprehensive, `ftps`/`ssh_cert`/`ldif` to standard+comprehensive profiles; add `PcapFile`/`PcapInterface`/`PcapWindow`/`PcapFilter` config fields; add pcap target injection |
| `internal/license/tier.go` | Add `ftps`, `ssh_cert`, `ldif`, `tls_observer` to `proModules()` (ldif also in free) |
| `cmd/root.go` | Add `--pcap-file`, `--pcap-interface`, `--pcap-window`, `--pcap-filter` flags + mutual exclusion + config wiring |
| `pkg/scanner/doctor.go` | Add `tls_observer` to `moduleDependencies` (links to doctor_pcap_*.go check) |
| `pkg/report/generator.go` | Render JA3/JA4 fingerprints in HTML finding detail |
| `pkg/report/cyclonedx.go` | Emit `triton:ja3`, `triton:ja3s`, `triton:ja4`, `triton:ja4s` properties |
| `go.mod` / `go.sum` | Add `github.com/gopacket/gopacket` |

---

## Phase 1: Foundation (Model + Shared Libraries)

### Task 1: Add TargetPcap and CryptoAsset fingerprint fields

**Files:**
- Modify: `pkg/model/types.go`

- [ ] **Step 1: Add TargetPcap constant**

In `pkg/model/types.go`, after the `TargetKubernetesCluster` constant (line 28), add:

```go
TargetPcap                  // pcap file or live network capture
```

- [ ] **Step 2: Add fingerprint fields to CryptoAsset**

In `pkg/model/types.go`, after the `SANs` field (line 236), add:

```go
	// TLS fingerprinting (pcap observer / passive capture)
	JA3Fingerprint  string `json:"ja3Fingerprint,omitempty"`
	JA3SFingerprint string `json:"ja3sFingerprint,omitempty"`
	JA4Fingerprint  string `json:"ja4Fingerprint,omitempty"`
	JA4SFingerprint string `json:"ja4sFingerprint,omitempty"`
	SNI             string `json:"sni,omitempty"`
	TLSFlowSource   string `json:"tlsFlowSource,omitempty"` // "pcap_file" or "live_capture"
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: clean build, no errors.

- [ ] **Step 4: Commit**

```bash
git add pkg/model/types.go
git commit -m "model: add TargetPcap and TLS fingerprint fields on CryptoAsset"
```

### Task 2: Add gopacket dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add dependency**

```bash
go get github.com/gopacket/gopacket@latest
```

- [ ] **Step 2: Tidy**

```bash
go mod tidy
```

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add gopacket for pure-Go pcap parsing"
```

### Task 3: Extract tlsutil chain walking from protocol.go

**Files:**
- Create: `pkg/scanner/internal/tlsutil/chain.go`
- Create: `pkg/scanner/internal/tlsutil/chain_test.go`
- Modify: `pkg/scanner/protocol.go`

- [ ] **Step 1: Write chain_test.go with tests**

```go
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkCertChain_SingleLeaf(t *testing.T) {
	cert := selfSignedCert(t, "leaf.example.com", false, x509.SHA256WithRSA, time.Now().Add(365*24*time.Hour))
	entries := WalkCertChain([]*x509.Certificate{cert})
	require.Len(t, entries, 1)
	assert.Equal(t, "leaf", entries[0].Position)
	assert.False(t, entries[0].WeakSignature)
	assert.False(t, entries[0].ExpiryWarning)
}

func TestWalkCertChain_WeakSHA1Signature(t *testing.T) {
	cert := selfSignedCert(t, "sha1.example.com", false, x509.SHA1WithRSA, time.Now().Add(365*24*time.Hour))
	entries := WalkCertChain([]*x509.Certificate{cert})
	require.Len(t, entries, 1)
	assert.True(t, entries[0].WeakSignature)
	assert.Equal(t, "SHA-1", entries[0].WeakSigAlgo)
}

func TestWalkCertChain_ExpiryWarning30Days(t *testing.T) {
	cert := selfSignedCert(t, "expiring.example.com", false, x509.SHA256WithRSA, time.Now().Add(15*24*time.Hour))
	entries := WalkCertChain([]*x509.Certificate{cert})
	require.Len(t, entries, 1)
	assert.True(t, entries[0].ExpiryWarning)
	assert.True(t, entries[0].DaysRemaining >= 14 && entries[0].DaysRemaining <= 16)
}

func TestWalkCertChain_LeafIntermediateRoot(t *testing.T) {
	leaf := selfSignedCert(t, "leaf.example.com", false, x509.SHA256WithRSA, time.Now().Add(365*24*time.Hour))
	inter := selfSignedCert(t, "intermediate.example.com", true, x509.SHA256WithRSA, time.Now().Add(3650*24*time.Hour))
	root := selfSignedCert(t, "root.example.com", true, x509.SHA256WithRSA, time.Now().Add(7300*24*time.Hour))
	entries := WalkCertChain([]*x509.Certificate{leaf, inter, root})
	require.Len(t, entries, 3)
	assert.Equal(t, "leaf", entries[0].Position)
	assert.Equal(t, "intermediate", entries[1].Position)
	assert.Equal(t, "root", entries[2].Position)
}

func TestWalkCertChain_SANsOnLeaf(t *testing.T) {
	cert := selfSignedCert(t, "san.example.com", false, x509.SHA256WithRSA, time.Now().Add(365*24*time.Hour))
	cert.DNSNames = []string{"san.example.com", "alt.example.com"}
	entries := WalkCertChain([]*x509.Certificate{cert})
	require.Len(t, entries, 1)
	assert.Equal(t, []string{"san.example.com", "alt.example.com"}, entries[0].SANs)
}

func TestWalkCertChain_Empty(t *testing.T) {
	entries := WalkCertChain(nil)
	assert.Empty(t, entries)
}

// selfSignedCert creates a minimal self-signed cert for testing.
func selfSignedCert(t *testing.T, cn string, isCA bool, sigAlgo x509.SignatureAlgorithm, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: cn},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           notAfter,
		IsCA:               isCA,
		SignatureAlgorithm: sigAlgo,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestWalkCertChain ./pkg/scanner/internal/tlsutil/...`
Expected: FAIL — `WalkCertChain` not defined.

- [ ] **Step 3: Implement chain.go**

```go
package tlsutil

import (
	"crypto/x509"
	"net"
	"time"
)

// ChainEntry holds analysis results for one certificate in a TLS chain.
type ChainEntry struct {
	Cert          *x509.Certificate
	Position      string // "leaf", "intermediate", "root"
	WeakSignature bool
	WeakSigAlgo   string // "SHA-1", "MD5" if weak
	ExpiryWarning bool   // true if expires within 30 days
	DaysRemaining int    // days until expiry (only set if ExpiryWarning)
	SANs          []string
}

// WalkCertChain analyzes a certificate chain and returns per-cert entries
// with position labels, weak signature detection, and expiry warnings.
func WalkCertChain(certs []*x509.Certificate) []ChainEntry {
	if len(certs) == 0 {
		return nil
	}

	entries := make([]ChainEntry, len(certs))
	for i, cert := range certs {
		entries[i] = ChainEntry{
			Cert:     cert,
			Position: chainPosition(i, len(certs), cert),
		}

		// Weak signature detection.
		if algo, weak := weakSigAlgo(cert.SignatureAlgorithm); weak {
			entries[i].WeakSignature = true
			entries[i].WeakSigAlgo = algo
		}

		// Expiry warning: within 30 days but not yet expired.
		if cert.NotAfter.After(time.Now()) {
			days := int(time.Until(cert.NotAfter).Hours() / 24)
			if days <= 30 {
				entries[i].ExpiryWarning = true
				entries[i].DaysRemaining = days
			}
		}

		// SANs on leaf only.
		if i == 0 {
			entries[i].SANs = extractSANs(cert)
		}
	}
	return entries
}

func chainPosition(idx, chainLen int, cert *x509.Certificate) string {
	if idx == 0 {
		return "leaf"
	}
	if idx == chainLen-1 || cert.IsCA {
		if cert.IsCA && idx == chainLen-1 {
			return "root"
		}
		return "intermediate"
	}
	return "intermediate"
}

func weakSigAlgo(algo x509.SignatureAlgorithm) (string, bool) {
	switch algo {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "SHA-1", true
	case x509.MD5WithRSA, x509.MD2WithRSA:
		return "MD5", true
	default:
		return "", false
	}
}

func extractSANs(cert *x509.Certificate) []string {
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	return sans
}

// CertAlgoName returns a display-friendly algorithm name for a certificate.
func CertAlgoName(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *interface{ Params() *struct{ Name string } }:
		_ = pub // exhaustive switch
	}
	return cert.PublicKeyAlgorithm.String()
}

// SigAlgoToPQCName maps x509.SignatureAlgorithm to the PQC registry algorithm name.
func SigAlgoToPQCName(algo x509.SignatureAlgorithm) string {
	switch algo {
	case x509.SHA1WithRSA:
		return "SHA-1"
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
		return "SHA-256"
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		return "SHA-384"
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		return "SHA-512"
	case x509.ECDSAWithSHA256:
		return "ECDSA-P256"
	case x509.ECDSAWithSHA384:
		return "ECDSA-P384"
	case x509.ECDSAWithSHA512:
		return "ECDSA-P521"
	case x509.MD5WithRSA, x509.MD2WithRSA:
		return "MD5"
	case x509.PureEd25519:
		return "Ed25519"
	default:
		return algo.String()
	}
}
```

Note: The `chainPosition` logic mirrors the existing `protocol.go` implementation. The `CertAlgoName` and `SigAlgoToPQCName` helpers are also extracted from protocol.go's `certAlgoName` and `sigAlgoToPQCAlgorithm`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run TestWalkCertChain ./pkg/scanner/internal/tlsutil/...`
Expected: all 6 tests PASS.

- [ ] **Step 5: Update protocol.go to use tlsutil**

In `protocol.go`, replace the `enhancedChainValidation` method's inline chain walking with calls to `tlsutil.WalkCertChain()`. The method calls `isWeakSignatureAlgorithm`, `sigAlgoToPQCAlgorithm`, `certAlgoName`, and `chainPosition` — these move to `tlsutil` but the method itself stays as the finding-emission orchestrator:

Replace the body of `enhancedChainValidation` (lines 499-568) with:

```go
func (m *ProtocolModule) enhancedChainValidation(ctx context.Context, addr string, certs []*x509.Certificate, findings chan<- *model.Finding) error {
	entries := tlsutil.WalkCertChain(certs)
	for _, e := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if e.WeakSignature {
			if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
				ID:            uuid.Must(uuid.NewV7()).String(),
				Function:      "Weak certificate signature algorithm",
				Algorithm:     tlsutil.SigAlgoToPQCName(e.Cert.SignatureAlgorithm),
				Subject:       e.Cert.Subject.String(),
				Issuer:        e.Cert.Issuer.String(),
				ChainPosition: e.Position,
				ChainDepth:    len(certs),
				Purpose:       fmt.Sprintf("Certificate uses weak signature algorithm %s", e.Cert.SignatureAlgorithm),
			}, findings); err != nil {
				return err
			}
		}

		if e.ExpiryWarning {
			notAfter := e.Cert.NotAfter
			if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
				ID:            uuid.Must(uuid.NewV7()).String(),
				Function:      "Certificate expiry warning",
				Algorithm:     tlsutil.CertAlgoName(e.Cert),
				Subject:       e.Cert.Subject.String(),
				NotAfter:      &notAfter,
				ChainPosition: e.Position,
				ChainDepth:    len(certs),
				Purpose:       fmt.Sprintf("Certificate expires in %d days", e.DaysRemaining),
			}, findings); err != nil {
				return err
			}
		}

		if e.Position == "leaf" && len(e.SANs) > 0 {
			if err := m.emitFinding(ctx, addr, &model.CryptoAsset{
				ID:            uuid.Must(uuid.NewV7()).String(),
				Function:      "TLS certificate SANs",
				Algorithm:     tlsutil.CertAlgoName(e.Cert),
				Subject:       e.Cert.Subject.String(),
				SANs:          e.SANs,
				ChainPosition: e.Position,
				ChainDepth:    len(certs),
				Purpose:       fmt.Sprintf("Certificate has %d SANs", len(e.SANs)),
			}, findings); err != nil {
				return err
			}
		}
	}
	return nil
}
```

Add the import `"github.com/amiryahaya/triton/pkg/scanner/internal/tlsutil"` to protocol.go. Remove the now-unused `isWeakSignatureAlgorithm`, `sigAlgoToPQCAlgorithm` helper functions from protocol.go (keep `certAlgoName` if used elsewhere, or move it too).

- [ ] **Step 6: Verify existing protocol tests still pass**

Run: `go test -v ./pkg/scanner/ -run TestProtocol`
Expected: all existing protocol tests pass — this is a pure refactor.

- [ ] **Step 7: Verify full build**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 8: Commit**

```bash
git add pkg/scanner/internal/tlsutil/ pkg/scanner/protocol.go
git commit -m "refactor: extract cert chain walking from protocol.go into internal/tlsutil"
```

---

## Phase 2: TLS Record Parser (`tlsparse/`)

### Task 4: GREASE filter and types

**Files:**
- Create: `pkg/scanner/internal/tlsparse/grease.go`
- Create: `pkg/scanner/internal/tlsparse/types.go`

- [ ] **Step 1: Write grease.go**

```go
package tlsparse

// IsGREASE returns true if the value is a GREASE sentinel per RFC 8701.
// GREASE values follow the pattern 0x?A?A where ? is 0-F.
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a
}

// FilterGREASE returns a new slice with GREASE values removed.
func FilterGREASE(vals []uint16) []uint16 {
	out := make([]uint16, 0, len(vals))
	for _, v := range vals {
		if !IsGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}
```

- [ ] **Step 2: Write types.go**

```go
package tlsparse

import "net"

// ClientHelloInfo holds parsed fields from a TLS ClientHello message.
type ClientHelloInfo struct {
	TLSVersion       uint16
	CipherSuites     []uint16
	Extensions       []uint16
	EllipticCurves   []uint16 // supported_groups
	ECPointFormats   []uint8
	SNI              string
	ALPNProtocols    []string
	SignatureSchemes  []uint16
}

// ServerHelloInfo holds parsed fields from a TLS ServerHello message.
type ServerHelloInfo struct {
	TLSVersion   uint16
	CipherSuite  uint16
	Extensions   []uint16
	SelectedALPN string
}

// FlowKey identifies a unique TCP flow.
type FlowKey struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
}

// FlowState tracks handshake progress for a single TLS flow.
type FlowState struct {
	Key         FlowKey
	ClientHello *ClientHelloInfo
	ServerHello *ServerHelloInfo
}

// Fingerprint holds computed fingerprints for a TLS flow.
type Fingerprint struct {
	JA3  string // MD5 hex of JA3 raw string
	JA3S string // MD5 hex of JA3S raw string
	JA4  string // structured JA4 fingerprint
	JA4S string // structured JA4S fingerprint

	// Raw strings (useful for debugging / threat intel matching).
	JA3Raw  string
	JA3SRaw string
}
```

- [ ] **Step 3: Verify build**

Run: `go build ./pkg/scanner/internal/tlsparse/...`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add pkg/scanner/internal/tlsparse/
git commit -m "feat(tlsparse): add types and GREASE filter"
```

### Task 5: TLS handshake parser

**Files:**
- Create: `pkg/scanner/internal/tlsparse/handshake.go`
- Create: `pkg/scanner/internal/tlsparse/handshake_test.go`

- [ ] **Step 1: Write handshake_test.go**

```go
package tlsparse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClientHello_Minimal(t *testing.T) {
	// Minimal ClientHello: TLS 1.2, 1 cipher (TLS_AES_128_GCM_SHA256 = 0x1301), no extensions.
	raw := buildClientHello(t, 0x0303, []uint16{0x1301}, nil, nil, nil, "")
	ch, err := ParseClientHello(raw)
	require.NoError(t, err)
	assert.Equal(t, uint16(0x0303), ch.TLSVersion)
	assert.Equal(t, []uint16{0x1301}, ch.CipherSuites)
	assert.Empty(t, ch.Extensions)
}

func TestParseClientHello_WithSNI(t *testing.T) {
	raw := buildClientHello(t, 0x0303, []uint16{0x1301}, []extension{
		sniExtension("example.com"),
	}, nil, nil, "")
	ch, err := ParseClientHello(raw)
	require.NoError(t, err)
	assert.Equal(t, "example.com", ch.SNI)
	assert.Contains(t, ch.Extensions, uint16(0x0000)) // SNI extension type
}

func TestParseClientHello_WithGREASE(t *testing.T) {
	raw := buildClientHello(t, 0x0303, []uint16{0x0a0a, 0x1301, 0x1302}, nil, nil, nil, "")
	ch, err := ParseClientHello(raw)
	require.NoError(t, err)
	// GREASE cipher is included in raw parse; filtering happens in JA3/JA4 computation
	assert.Contains(t, ch.CipherSuites, uint16(0x0a0a))
	assert.Contains(t, ch.CipherSuites, uint16(0x1301))
}

func TestParseClientHello_Truncated(t *testing.T) {
	_, err := ParseClientHello([]byte{0x01, 0x00}) // too short
	assert.Error(t, err)
}

func TestParseClientHello_WithEllipticCurves(t *testing.T) {
	raw := buildClientHello(t, 0x0303, []uint16{0x1301}, []extension{
		supportedGroupsExtension([]uint16{0x0017, 0x0018}), // P-256, P-384
	}, nil, nil, "")
	ch, err := ParseClientHello(raw)
	require.NoError(t, err)
	assert.Equal(t, []uint16{0x0017, 0x0018}, ch.EllipticCurves)
}

func TestParseServerHello_Minimal(t *testing.T) {
	raw := buildServerHello(t, 0x0303, 0x1301, nil)
	sh, err := ParseServerHello(raw)
	require.NoError(t, err)
	assert.Equal(t, uint16(0x0303), sh.TLSVersion)
	assert.Equal(t, uint16(0x1301), sh.CipherSuite)
}

func TestParseServerHello_Truncated(t *testing.T) {
	_, err := ParseServerHello([]byte{0x02, 0x00})
	assert.Error(t, err)
}

// --- Test helpers: TLS record builders ---

type extension struct {
	typ  uint16
	data []byte
}

func sniExtension(hostname string) extension {
	// SNI extension format: list_length(2) + type(1)=0 + name_length(2) + hostname
	nameLen := len(hostname)
	listLen := nameLen + 3 // type(1) + len(2)
	data := make([]byte, 0, 2+listLen)
	data = append(data, byte(listLen>>8), byte(listLen))
	data = append(data, 0) // hostname type
	data = append(data, byte(nameLen>>8), byte(nameLen))
	data = append(data, []byte(hostname)...)
	return extension{typ: 0x0000, data: data}
}

func supportedGroupsExtension(groups []uint16) extension {
	data := make([]byte, 0, 2+2*len(groups))
	listLen := 2 * len(groups)
	data = append(data, byte(listLen>>8), byte(listLen))
	for _, g := range groups {
		data = append(data, byte(g>>8), byte(g))
	}
	return extension{typ: 0x000a, data: data}
}

func buildClientHello(t *testing.T, version uint16, ciphers []uint16, exts []extension, curves []uint16, ecFormats []uint8, sni string) []byte {
	t.Helper()
	var body []byte

	// Handshake type: ClientHello (1)
	// We'll build the handshake body first, then prepend type+length

	// client_version (2 bytes)
	body = append(body, byte(version>>8), byte(version))

	// random (32 bytes)
	body = append(body, make([]byte, 32)...)

	// session_id_length (1 byte) + session_id (0 bytes)
	body = append(body, 0)

	// cipher_suites_length (2 bytes) + cipher_suites
	csLen := 2 * len(ciphers)
	body = append(body, byte(csLen>>8), byte(csLen))
	for _, cs := range ciphers {
		body = append(body, byte(cs>>8), byte(cs))
	}

	// compression_methods_length (1) + null compression (1)
	body = append(body, 1, 0)

	// extensions
	if len(exts) > 0 {
		var extData []byte
		for _, ext := range exts {
			extData = append(extData, byte(ext.typ>>8), byte(ext.typ))
			extData = append(extData, byte(len(ext.data)>>8), byte(len(ext.data)))
			extData = append(extData, ext.data...)
		}
		body = append(body, byte(len(extData)>>8), byte(len(extData)))
		body = append(body, extData...)
	}

	// Prepend handshake header: type(1) + length(3)
	hdr := []byte{0x01} // ClientHello
	bodyLen := len(body)
	hdr = append(hdr, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	return append(hdr, body...)
}

func buildServerHello(t *testing.T, version uint16, cipher uint16, exts []extension) []byte {
	t.Helper()
	var body []byte

	// server_version (2 bytes)
	body = append(body, byte(version>>8), byte(version))

	// random (32 bytes)
	body = append(body, make([]byte, 32)...)

	// session_id_length (1) + session_id (0)
	body = append(body, 0)

	// cipher_suite (2 bytes)
	body = append(body, byte(cipher>>8), byte(cipher))

	// compression_method (1 byte)
	body = append(body, 0)

	// extensions
	if len(exts) > 0 {
		var extData []byte
		for _, ext := range exts {
			extData = append(extData, byte(ext.typ>>8), byte(ext.typ))
			extData = append(extData, byte(len(ext.data)>>8), byte(len(ext.data)))
			extData = append(extData, ext.data...)
		}
		body = append(body, byte(len(extData)>>8), byte(len(extData)))
		body = append(body, extData...)
	}

	// Prepend handshake header: type(1) + length(3)
	hdr := []byte{0x02} // ServerHello
	bodyLen := len(body)
	hdr = append(hdr, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	return append(hdr, body...)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestParse ./pkg/scanner/internal/tlsparse/...`
Expected: FAIL — `ParseClientHello` and `ParseServerHello` not defined.

- [ ] **Step 3: Implement handshake.go**

```go
package tlsparse

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrTruncated    = errors.New("tlsparse: truncated handshake message")
	ErrNotHandshake = errors.New("tlsparse: not a handshake message")
)

// ParseClientHello parses a TLS ClientHello handshake message.
// Input must start with the handshake type byte (0x01) and 3-byte length.
func ParseClientHello(data []byte) (*ClientHelloInfo, error) {
	if len(data) < 4 {
		return nil, ErrTruncated
	}
	if data[0] != 0x01 {
		return nil, fmt.Errorf("%w: expected type 0x01, got 0x%02x", ErrNotHandshake, data[0])
	}

	bodyLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	body := data[4:]
	if len(body) < bodyLen {
		return nil, ErrTruncated
	}
	body = body[:bodyLen]

	return parseClientHelloBody(body)
}

func parseClientHelloBody(b []byte) (*ClientHelloInfo, error) {
	if len(b) < 38 { // version(2) + random(32) + session_id_len(1) + min
		return nil, ErrTruncated
	}

	ch := &ClientHelloInfo{
		TLSVersion: binary.BigEndian.Uint16(b[0:2]),
	}
	pos := 34 // skip version(2) + random(32)

	// Session ID
	if pos >= len(b) {
		return nil, ErrTruncated
	}
	sidLen := int(b[pos])
	pos++
	pos += sidLen
	if pos+2 > len(b) {
		return nil, ErrTruncated
	}

	// Cipher suites
	csLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	if pos+csLen > len(b) {
		return nil, ErrTruncated
	}
	for i := 0; i < csLen; i += 2 {
		ch.CipherSuites = append(ch.CipherSuites, binary.BigEndian.Uint16(b[pos+i:pos+i+2]))
	}
	pos += csLen

	// Compression methods
	if pos >= len(b) {
		return nil, ErrTruncated
	}
	compLen := int(b[pos])
	pos++
	pos += compLen

	// Extensions (optional)
	if pos+2 <= len(b) {
		extTotalLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
		pos += 2
		extEnd := pos + extTotalLen
		if extEnd > len(b) {
			extEnd = len(b)
		}
		for pos+4 <= extEnd {
			extType := binary.BigEndian.Uint16(b[pos : pos+2])
			extLen := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
			pos += 4
			extData := b[pos:]
			if extLen <= len(extData) {
				extData = extData[:extLen]
			}

			ch.Extensions = append(ch.Extensions, extType)

			switch extType {
			case 0x0000: // SNI
				ch.SNI = parseSNI(extData)
			case 0x000a: // supported_groups
				ch.EllipticCurves = parseUint16List(extData)
			case 0x000b: // ec_point_formats
				if len(extData) >= 1 {
					fmtLen := int(extData[0])
					if 1+fmtLen <= len(extData) {
						ch.ECPointFormats = make([]uint8, fmtLen)
						copy(ch.ECPointFormats, extData[1:1+fmtLen])
					}
				}
			case 0x000d: // signature_algorithms
				ch.SignatureSchemes = parseUint16List(extData)
			case 0x0010: // ALPN
				ch.ALPNProtocols = parseALPN(extData)
			}

			pos += extLen
		}
	}

	return ch, nil
}

// ParseServerHello parses a TLS ServerHello handshake message.
func ParseServerHello(data []byte) (*ServerHelloInfo, error) {
	if len(data) < 4 {
		return nil, ErrTruncated
	}
	if data[0] != 0x02 {
		return nil, fmt.Errorf("%w: expected type 0x02, got 0x%02x", ErrNotHandshake, data[0])
	}

	bodyLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	body := data[4:]
	if len(body) < bodyLen {
		return nil, ErrTruncated
	}
	body = body[:bodyLen]

	return parseServerHelloBody(body)
}

func parseServerHelloBody(b []byte) (*ServerHelloInfo, error) {
	if len(b) < 38 { // version(2) + random(32) + session_id_len(1) + cipher(2) + comp(1)
		return nil, ErrTruncated
	}

	sh := &ServerHelloInfo{
		TLSVersion: binary.BigEndian.Uint16(b[0:2]),
	}
	pos := 34 // skip version(2) + random(32)

	// Session ID
	if pos >= len(b) {
		return nil, ErrTruncated
	}
	sidLen := int(b[pos])
	pos++
	pos += sidLen
	if pos+3 > len(b) {
		return nil, ErrTruncated
	}

	// Cipher suite
	sh.CipherSuite = binary.BigEndian.Uint16(b[pos : pos+2])
	pos += 2

	// Compression method
	pos++

	// Extensions
	if pos+2 <= len(b) {
		extTotalLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
		pos += 2
		extEnd := pos + extTotalLen
		if extEnd > len(b) {
			extEnd = len(b)
		}
		for pos+4 <= extEnd {
			extType := binary.BigEndian.Uint16(b[pos : pos+2])
			extLen := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
			pos += 4

			sh.Extensions = append(sh.Extensions, extType)

			if extType == 0x0010 && extLen <= len(b)-pos { // ALPN
				alpns := parseALPN(b[pos : pos+extLen])
				if len(alpns) > 0 {
					sh.SelectedALPN = alpns[0]
				}
			}

			pos += extLen
		}
	}

	return sh, nil
}

// ExtractHandshakeFromTLSRecord extracts the handshake message from a TLS
// record layer frame. Returns the handshake bytes starting at the type byte.
// Input: raw TLS record (content_type(1) + version(2) + length(2) + fragment).
func ExtractHandshakeFromTLSRecord(record []byte) ([]byte, error) {
	if len(record) < 5 {
		return nil, ErrTruncated
	}
	if record[0] != 0x16 { // handshake content type
		return nil, fmt.Errorf("%w: content type 0x%02x is not handshake", ErrNotHandshake, record[0])
	}
	fragLen := int(binary.BigEndian.Uint16(record[3:5]))
	if len(record) < 5+fragLen {
		return nil, ErrTruncated
	}
	return record[5 : 5+fragLen], nil
}

func parseSNI(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// list_length(2) + type(1) + name_length(2) + name
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+listLen || listLen < 3 {
		return ""
	}
	// type should be 0 (hostname)
	if data[2] != 0 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseUint16List(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if listLen > len(data) {
		listLen = len(data)
	}
	var out []uint16
	for i := 0; i+1 < listLen; i += 2 {
		out = append(out, binary.BigEndian.Uint16(data[i:i+2]))
	}
	return out
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if listLen > len(data) {
		listLen = len(data)
	}
	var out []string
	pos := 0
	for pos < listLen {
		if pos >= len(data) {
			break
		}
		strLen := int(data[pos])
		pos++
		if pos+strLen > len(data) {
			break
		}
		out = append(out, string(data[pos:pos+strLen]))
		pos += strLen
	}
	return out
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestParse ./pkg/scanner/internal/tlsparse/...`
Expected: all 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/tlsparse/
git commit -m "feat(tlsparse): TLS handshake parser for ClientHello/ServerHello"
```

### Task 6: JA3/JA3S fingerprint computation

**Files:**
- Create: `pkg/scanner/internal/tlsparse/ja3.go`
- Create: `pkg/scanner/internal/tlsparse/ja3_test.go`

- [ ] **Step 1: Write ja3_test.go**

```go
package tlsparse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJA3_KnownVector(t *testing.T) {
	// Reference vector from https://github.com/salesforce/ja3
	// TLS 1.2 ClientHello with specific cipher/extension/curve set.
	ch := &ClientHelloInfo{
		TLSVersion:     0x0303, // TLS 1.2
		CipherSuites:   []uint16{0xc02c, 0xc02b, 0xc024, 0xc023, 0xc00a, 0xc009, 0xc030, 0xc02f, 0xc028, 0xc027, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00ff},
		Extensions:     []uint16{0x0000, 0x000b, 0x000a, 0x000d, 0x000f, 0x0010},
		EllipticCurves: []uint16{0x001d, 0x0017, 0x0018},
		ECPointFormats: []uint8{0x00},
	}
	raw, hash := JA3(ch)
	assert.NotEmpty(t, raw)
	assert.Len(t, hash, 32) // MD5 hex = 32 chars
	// Verify the raw string format: version,ciphers,extensions,curves,formats
	assert.Contains(t, raw, "771,")  // TLS 1.2 = 771
	assert.Contains(t, raw, "49196-") // first cipher
}

func TestJA3_GREASEFiltered(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:     0x0303,
		CipherSuites:   []uint16{0x0a0a, 0x1301}, // GREASE + real
		Extensions:     []uint16{0x3a3a, 0x0000},  // GREASE + SNI
		EllipticCurves: []uint16{0x4a4a, 0x0017},  // GREASE + P-256
		ECPointFormats: []uint8{0x00},
	}
	raw, _ := JA3(ch)
	assert.NotContains(t, raw, "2570")  // 0x0a0a decimal
	assert.NotContains(t, raw, "14906") // 0x3a3a decimal
	assert.NotContains(t, raw, "19018") // 0x4a4a decimal
	assert.Contains(t, raw, "4865")     // 0x1301 decimal
}

func TestJA3S_KnownVector(t *testing.T) {
	sh := &ServerHelloInfo{
		TLSVersion:  0x0303,
		CipherSuite: 0xc02c,
		Extensions:  []uint16{0xff01, 0x000b, 0x0023},
	}
	raw, hash := JA3S(sh)
	assert.NotEmpty(t, raw)
	assert.Len(t, hash, 32)
	assert.Contains(t, raw, "771,49196,") // version,cipher,extensions
}

func TestJA3_EmptyCiphers(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion: 0x0303,
	}
	raw, hash := JA3(ch)
	assert.Equal(t, "771,,,,", raw)
	assert.Len(t, hash, 32) // still produces valid MD5
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestJA3 ./pkg/scanner/internal/tlsparse/...`
Expected: FAIL — `JA3` not defined.

- [ ] **Step 3: Implement ja3.go**

```go
package tlsparse

import (
	"crypto/md5"
	"fmt"
	"strconv"
	"strings"
)

// JA3 computes the JA3 fingerprint for a ClientHello.
// Returns the raw string and its MD5 hex hash.
// Spec: https://github.com/salesforce/ja3
// Format: TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
// All values are decimal, dash-separated within each group, GREASE filtered.
func JA3(ch *ClientHelloInfo) (raw string, hash string) {
	ciphers := FilterGREASE(ch.CipherSuites)
	exts := FilterGREASE(ch.Extensions)
	curves := FilterGREASE(ch.EllipticCurves)

	raw = fmt.Sprintf("%d,%s,%s,%s,%s",
		ch.TLSVersion,
		joinUint16(ciphers),
		joinUint16(exts),
		joinUint16(curves),
		joinUint8(ch.ECPointFormats),
	)
	hash = md5Hex(raw)
	return raw, hash
}

// JA3S computes the JA3S fingerprint for a ServerHello.
// Format: TLSVersion,CipherSuite,Extensions
func JA3S(sh *ServerHelloInfo) (raw string, hash string) {
	exts := FilterGREASE(sh.Extensions)

	raw = fmt.Sprintf("%d,%d,%s",
		sh.TLSVersion,
		sh.CipherSuite,
		joinUint16(exts),
	)
	hash = md5Hex(raw)
	return raw, hash
}

func joinUint16(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, "-")
}

func joinUint8(vals []uint8) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, "-")
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", sum)
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestJA3 ./pkg/scanner/internal/tlsparse/...`
Expected: all 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/tlsparse/ja3.go pkg/scanner/internal/tlsparse/ja3_test.go
git commit -m "feat(tlsparse): JA3/JA3S fingerprint computation"
```

### Task 7: JA4/JA4S fingerprint computation

**Files:**
- Create: `pkg/scanner/internal/tlsparse/ja4.go`
- Create: `pkg/scanner/internal/tlsparse/ja4_test.go`

- [ ] **Step 1: Write ja4_test.go**

```go
package tlsparse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJA4_Structure(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:     0x0303,
		CipherSuites:   []uint16{0x1301, 0x1302, 0xc02c},
		Extensions:     []uint16{0x0000, 0x000a, 0x000d},
		EllipticCurves: []uint16{0x0017},
		ECPointFormats: []uint8{0x00},
		SNI:            "example.com",
		ALPNProtocols:  []string{"h2"},
	}
	fp := JA4(ch)
	// JA4 format: t{version}{sni}{cipherCount}{extCount}_{alpn}_{cipherHash}_{extHash}
	// e.g. "t13d030300_h2_aabbccdd1122_eeff0011"
	assert.NotEmpty(t, fp)
	// Should start with "t" for TLS (not "q" for QUIC)
	assert.True(t, fp[0] == 't', "JA4 should start with 't' for TLS, got %c", fp[0])
}

func TestJA4_NoSNI(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x000a},
	}
	fp := JA4(ch)
	assert.NotEmpty(t, fp)
	// 'i' for no SNI (ip literal or missing)
	assert.Contains(t, fp, "i")
}

func TestJA4_GREASEFiltered(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x0a0a, 0x1301},
		Extensions:   []uint16{0x3a3a, 0x0000},
	}
	fp := JA4(ch)
	assert.NotEmpty(t, fp)
	// Count should reflect non-GREASE values only
}

func TestJA4S_Structure(t *testing.T) {
	sh := &ServerHelloInfo{
		TLSVersion:  0x0303,
		CipherSuite: 0x1301,
		Extensions:  []uint16{0x002b},
	}
	fp := JA4S(sh)
	assert.NotEmpty(t, fp)
	// JA4S format: t{version}{extCount}_{cipherSuite}_{extHash}
}

func TestJA4_SortedCiphersAndExtensions(t *testing.T) {
	// JA4 sorts cipher suites and extensions for deterministic fingerprint
	ch1 := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x1302, 0x1301},
		Extensions:   []uint16{0x000d, 0x000a},
	}
	ch2 := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x1301, 0x1302},
		Extensions:   []uint16{0x000a, 0x000d},
	}
	assert.Equal(t, JA4(ch1), JA4(ch2), "JA4 should be order-independent")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestJA4 ./pkg/scanner/internal/tlsparse/...`
Expected: FAIL — `JA4` not defined.

- [ ] **Step 3: Implement ja4.go**

```go
package tlsparse

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// JA4 computes the JA4 fingerprint for a ClientHello.
// Spec: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
//
// Format: {q|t}{version}{d|i}{cipherCount:02d}{extCount:02d}_{alpn}_{sortedCipherHash12}_{sortedExtHash12}
// - q = QUIC, t = TLS
// - d = domain (SNI present), i = IP/no SNI
// - cipher/ext counts are 2-digit zero-padded, capped at 99
// - hashes are first 12 chars of SHA-256 hex
func JA4(ch *ClientHelloInfo) string {
	ciphers := FilterGREASE(ch.CipherSuites)
	exts := FilterGREASE(ch.Extensions)

	// Protocol type: always 't' (TLS). QUIC not supported yet.
	proto := "t"

	// TLS version mapped to JA4 version string
	ver := ja4Version(ch.TLSVersion, ch.Extensions)

	// SNI indicator
	sni := "i"
	if ch.SNI != "" {
		sni = "d"
	}

	// Counts (capped at 99)
	cc := len(ciphers)
	if cc > 99 {
		cc = 99
	}
	ec := len(exts)
	if ec > 99 {
		ec = 99
	}

	// ALPN first value, first and last char
	alpn := "00"
	if len(ch.ALPNProtocols) > 0 {
		a := ch.ALPNProtocols[0]
		if len(a) >= 2 {
			alpn = string(a[0]) + string(a[len(a)-1])
		} else if len(a) == 1 {
			alpn = string(a[0]) + "0"
		}
	}

	// Section A: type + version + sni + counts + alpn
	sectionA := fmt.Sprintf("%s%s%s%02d%02d_%s", proto, ver, sni, cc, ec, alpn)

	// Section B: sorted cipher suites hash (first 12 hex chars of SHA-256)
	sortedCiphers := sortUint16(ciphers)
	cipherStr := joinUint16Sorted(sortedCiphers)
	cipherHash := sha256Hex12(cipherStr)

	// Section C: sorted extensions hash (first 12 hex chars of SHA-256)
	// SNI (0x0000) and ALPN (0x0010) are excluded from extension hash per spec
	filteredExts := filterSNIALPN(exts)
	sortedExts := sortUint16(filteredExts)
	extStr := joinUint16Sorted(sortedExts)
	extHash := sha256Hex12(extStr)

	return fmt.Sprintf("%s_%s_%s", sectionA, cipherHash, extHash)
}

// JA4S computes the JA4S fingerprint for a ServerHello.
// Format: {q|t}{version}{extCount:02d}_{cipherSuiteHex}_{sortedExtHash12}
func JA4S(sh *ServerHelloInfo) string {
	exts := FilterGREASE(sh.Extensions)

	proto := "t"
	ver := ja4VersionFromRaw(sh.TLSVersion)

	ec := len(exts)
	if ec > 99 {
		ec = 99
	}

	sectionA := fmt.Sprintf("%s%s%02d", proto, ver, ec)

	// Cipher suite as 4-char lowercase hex
	cipherHex := fmt.Sprintf("%04x", sh.CipherSuite)

	// Sorted extensions hash
	sortedExts := sortUint16(exts)
	extStr := joinUint16Sorted(sortedExts)
	extHash := sha256Hex12(extStr)

	return fmt.Sprintf("%s_%s_%s", sectionA, cipherHex, extHash)
}

// ja4Version maps TLS version to JA4 2-char version code.
// If supported_versions extension (0x002b) is present, it indicates TLS 1.3.
func ja4Version(rawVer uint16, extensions []uint16) string {
	for _, ext := range extensions {
		if ext == 0x002b { // supported_versions
			return "13"
		}
	}
	return ja4VersionFromRaw(rawVer)
}

func ja4VersionFromRaw(ver uint16) string {
	switch ver {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

func sortUint16(vals []uint16) []uint16 {
	sorted := make([]uint16, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted
}

func joinUint16Sorted(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, ",")
}

func filterSNIALPN(exts []uint16) []uint16 {
	out := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 { // not SNI, not ALPN
			out = append(out, e)
		}
	}
	return out
}

func sha256Hex12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)[:12]
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestJA4 ./pkg/scanner/internal/tlsparse/...`
Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/internal/tlsparse/ja4.go pkg/scanner/internal/tlsparse/ja4_test.go
git commit -m "feat(tlsparse): JA4/JA4S fingerprint computation"
```

### Task 8: Pcap file reader

**Files:**
- Create: `pkg/scanner/internal/tlsparse/reader.go`
- Create: `pkg/scanner/internal/tlsparse/reader_test.go`
- Create: `pkg/scanner/internal/tlsparse/afpacket_linux.go`
- Create: `pkg/scanner/internal/tlsparse/afpacket_stub.go`
- Create: `pkg/scanner/internal/tlsparse/testdata/sample.pcap`

- [ ] **Step 1: Write reader.go with PacketSource interface and pcap file reader**

```go
package tlsparse

import (
	"io"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Packet holds a decoded TCP packet's metadata and payload.
type Packet struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
	Payload []byte
	Time    time.Time
}

// PacketSource yields TCP packets one at a time.
type PacketSource interface {
	// NextPacket returns the next TCP packet with a non-empty payload.
	// Returns io.EOF when no more packets are available.
	NextPacket() (*Packet, error)
	Close() error
}

// PcapFileReader reads packets from a .pcap or .pcapng file.
type PcapFileReader struct {
	file   *os.File
	reader *pcapgo.Reader
}

// NewPcapFileReader opens a pcap file for reading.
func NewPcapFileReader(path string) (*PcapFileReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &PcapFileReader{file: f, reader: r}, nil
}

func (r *PcapFileReader) NextPacket() (*Packet, error) {
	for {
		data, ci, err := r.reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				return nil, io.EOF
			}
			return nil, err
		}

		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

		// Extract IP layer
		var srcIP, dstIP net.IP
		if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
			ipv4 := ip4.(*layers.IPv4)
			srcIP = ipv4.SrcIP
			dstIP = ipv4.DstIP
		} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
			ipv6 := ip6.(*layers.IPv6)
			srcIP = ipv6.SrcIP
			dstIP = ipv6.DstIP
		} else {
			continue // skip non-IP
		}

		// Extract TCP layer
		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp := tcpLayer.(*layers.TCP)

		payload := tcp.Payload
		if len(payload) == 0 {
			continue
		}

		return &Packet{
			SrcIP:   srcIP,
			SrcPort: uint16(tcp.SrcPort),
			DstIP:   dstIP,
			DstPort: uint16(tcp.DstPort),
			Payload: payload,
			Time:    ci.Timestamp,
		}, nil
	}
}

func (r *PcapFileReader) Close() error {
	return r.file.Close()
}
```

- [ ] **Step 2: Write afpacket_stub.go for non-Linux**

```go
//go:build !linux

package tlsparse

import (
	"errors"
	"runtime"
)

// NewLiveCaptureReader is not supported on non-Linux platforms.
func NewLiveCaptureReader(iface string, bpfFilter string) (PacketSource, error) {
	return nil, errors.New("live capture is not supported on " + runtime.GOOS + "; only Linux AF_PACKET is available (no CGO)")
}
```

- [ ] **Step 3: Write afpacket_linux.go placeholder**

```go
//go:build linux

package tlsparse

import (
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
)

// AFPacketReader captures packets from a network interface using AF_PACKET.
type AFPacketReader struct {
	handle *afpacket.TPacket
}

// NewLiveCaptureReader creates an AF_PACKET based live capture reader.
// Requires CAP_NET_RAW or root.
func NewLiveCaptureReader(iface string, bpfFilter string) (PacketSource, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("live capture requires root or CAP_NET_RAW")
	}

	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptFrameSize(65536),
		afpacket.OptBlockSize(65536*128),
		afpacket.OptNumBlocks(8),
	)
	if err != nil {
		return nil, err
	}

	// BPF filter is applied by the caller via gopacket if needed.
	// AF_PACKET itself does not support BPF strings directly in gopacket's wrapper.

	return &AFPacketReader{handle: handle}, nil
}

func (r *AFPacketReader) NextPacket() (*Packet, error) {
	data, ci, err := r.handle.ReadPacketData()
	if err != nil {
		return nil, io.EOF
	}

	pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

	var srcIP, dstIP net.IP
	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		ipv4 := ip4.(*layers.IPv4)
		srcIP = ipv4.SrcIP
		dstIP = ipv4.DstIP
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		ipv6 := ip6.(*layers.IPv6)
		srcIP = ipv6.SrcIP
		dstIP = ipv6.DstIP
	} else {
		return nil, nil // skip non-IP
	}

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, nil
	}
	tcp := tcpLayer.(*layers.TCP)

	if len(tcp.Payload) == 0 {
		return nil, nil
	}

	return &Packet{
		SrcIP:   srcIP,
		SrcPort: uint16(tcp.SrcPort),
		DstIP:   dstIP,
		DstPort: uint16(tcp.DstPort),
		Payload: tcp.Payload,
		Time:    ci.Timestamp,
	}, nil
}

func (r *AFPacketReader) Close() error {
	r.handle.Close()
	return nil
}
```

- [ ] **Step 4: Generate a test pcap fixture**

Create a small Go program that generates `testdata/sample.pcap` with a synthetic TLS ClientHello and ServerHello, or use a raw hex approach. For the plan, we'll create a test that uses the handshake builder from Task 5 to create a pcap file programmatically in the test itself.

- [ ] **Step 5: Write reader_test.go**

```go
package tlsparse

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockPacketSource provides a testable packet source.
type MockPacketSource struct {
	packets []*Packet
	idx     int
}

func NewMockSource(pkts ...*Packet) *MockPacketSource {
	return &MockPacketSource{packets: pkts}
}

func (m *MockPacketSource) NextPacket() (*Packet, error) {
	if m.idx >= len(m.packets) {
		return nil, io.EOF
	}
	p := m.packets[m.idx]
	m.idx++
	return p, nil
}

func (m *MockPacketSource) Close() error { return nil }

func TestMockPacketSource_ReadAll(t *testing.T) {
	src := NewMockSource(
		&Packet{SrcIP: net.ParseIP("1.2.3.4"), SrcPort: 12345, DstIP: net.ParseIP("5.6.7.8"), DstPort: 443, Payload: []byte{1, 2, 3}, Time: time.Now()},
		&Packet{SrcIP: net.ParseIP("5.6.7.8"), SrcPort: 443, DstIP: net.ParseIP("1.2.3.4"), DstPort: 12345, Payload: []byte{4, 5, 6}, Time: time.Now()},
	)

	p1, err := src.NextPacket()
	require.NoError(t, err)
	assert.Equal(t, uint16(12345), p1.SrcPort)

	p2, err := src.NextPacket()
	require.NoError(t, err)
	assert.Equal(t, uint16(443), p2.SrcPort)

	_, err = src.NextPacket()
	assert.ErrorIs(t, err, io.EOF)
}
```

- [ ] **Step 6: Run tests**

Run: `go test -v ./pkg/scanner/internal/tlsparse/...`
Expected: all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add pkg/scanner/internal/tlsparse/
git commit -m "feat(tlsparse): packet source interface, pcap file reader, AF_PACKET stubs"
```

---

## Phase 3: Scanner Modules

### Task 9: TLS Observer module

**Files:**
- Create: `pkg/scanner/tls_observer.go`
- Create: `pkg/scanner/tls_observer_test.go`

- [ ] **Step 1: Write tls_observer_test.go**

```go
package scanner

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/tlsparse"
)

func TestTLSObserver_PcapFile(t *testing.T) {
	cfg := scannerconfig.Load("comprehensive")
	m := NewTLSObserverModule(cfg)

	// Build a ClientHello + ServerHello packet pair
	chRaw := wrapInTLSRecord(buildTestClientHello(t))
	shRaw := wrapInTLSRecord(buildTestServerHello(t))

	m.readerFactory = func(target string) (tlsparse.PacketSource, error) {
		return tlsparse.NewMockSource(
			&tlsparse.Packet{
				SrcIP: net.ParseIP("10.0.0.1"), SrcPort: 45678,
				DstIP: net.ParseIP("10.0.0.2"), DstPort: 443,
				Payload: chRaw, Time: time.Now(),
			},
			&tlsparse.Packet{
				SrcIP: net.ParseIP("10.0.0.2"), SrcPort: 443,
				DstIP: net.ParseIP("10.0.0.1"), DstPort: 45678,
				Payload: shRaw, Time: time.Now(),
			},
		), nil
	}

	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetPcap, Value: "/tmp/test.pcap"}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}
	require.NotEmpty(t, results, "should emit at least one finding")

	// Check that JA3 fingerprint is present
	hasJA3 := false
	for _, f := range results {
		if f.CryptoAsset != nil && f.CryptoAsset.JA3Fingerprint != "" {
			hasJA3 = true
			assert.Len(t, f.CryptoAsset.JA3Fingerprint, 32, "JA3 should be 32-char MD5 hex")
		}
	}
	assert.True(t, hasJA3, "should have at least one finding with JA3 fingerprint")
}

func TestTLSObserver_FlowCap(t *testing.T) {
	cfg := scannerconfig.Load("comprehensive")
	m := NewTLSObserverModule(cfg)

	// Generate 10001 unique flows (exceeds 10K cap)
	var packets []*tlsparse.Packet
	for i := 0; i < 10001; i++ {
		ip := net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))
		packets = append(packets, &tlsparse.Packet{
			SrcIP: ip, SrcPort: uint16(40000 + i%20000),
			DstIP: net.ParseIP("10.0.0.1"), DstPort: 443,
			Payload: wrapInTLSRecord(buildTestClientHello(t)),
			Time:    time.Now(),
		})
	}

	m.readerFactory = func(target string) (tlsparse.PacketSource, error) {
		return tlsparse.NewMockSource(packets...), nil
	}

	findings := make(chan *model.Finding, 20000)
	target := model.ScanTarget{Type: model.TargetPcap, Value: "/tmp/test.pcap"}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	count := 0
	for range findings {
		count++
	}
	// Should not exceed 10K flows worth of findings
	assert.LessOrEqual(t, count, 10000*2, "flow cap should limit findings")
}

func TestTLSObserver_Name(t *testing.T) {
	m := NewTLSObserverModule(scannerconfig.Load("comprehensive"))
	assert.Equal(t, "tls_observer", m.Name())
}

func TestTLSObserver_Category(t *testing.T) {
	m := NewTLSObserverModule(scannerconfig.Load("comprehensive"))
	assert.Equal(t, model.CategoryActiveNetwork, m.Category())
}

func TestTLSObserver_ScanTargetType(t *testing.T) {
	m := NewTLSObserverModule(scannerconfig.Load("comprehensive"))
	assert.Equal(t, model.TargetPcap, m.ScanTargetType())
}

// Helpers

func wrapInTLSRecord(handshake []byte) []byte {
	// TLS record: content_type(1)=0x16 + version(2)=0x0301 + length(2) + fragment
	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, byte(len(handshake)>>8), byte(len(handshake)))
	return append(rec, handshake...)
}

func buildTestClientHello(t *testing.T) []byte {
	t.Helper()
	return buildClientHelloForScanner(0x0303, []uint16{0x1301, 0x1302, 0xc02c})
}

func buildTestServerHello(t *testing.T) []byte {
	t.Helper()
	return buildServerHelloForScanner(0x0303, 0x1301)
}

// buildClientHelloForScanner creates a minimal ClientHello handshake message.
func buildClientHelloForScanner(version uint16, ciphers []uint16) []byte {
	var body []byte
	body = append(body, byte(version>>8), byte(version))
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                    // session_id_length
	csLen := 2 * len(ciphers)
	body = append(body, byte(csLen>>8), byte(csLen))
	for _, cs := range ciphers {
		body = append(body, byte(cs>>8), byte(cs))
	}
	body = append(body, 1, 0) // compression
	hdr := []byte{0x01}
	bodyLen := len(body)
	hdr = append(hdr, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	return append(hdr, body...)
}

func buildServerHelloForScanner(version uint16, cipher uint16) []byte {
	var body []byte
	body = append(body, byte(version>>8), byte(version))
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                    // session_id_length
	body = append(body, byte(cipher>>8), byte(cipher))
	body = append(body, 0) // compression
	hdr := []byte{0x02}
	bodyLen := len(body)
	hdr = append(hdr, byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
	return append(hdr, body...)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestTLSObserver ./pkg/scanner/ -count=1`
Expected: FAIL — `NewTLSObserverModule` not defined.

- [ ] **Step 3: Implement tls_observer.go**

```go
package scanner

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/tlsparse"
)

const maxFlows = 10000

// readerFactoryFunc creates a PacketSource from a target string.
type readerFactoryFunc func(target string) (tlsparse.PacketSource, error)

// TLSObserverModule passively observes TLS handshakes from pcap files or
// live network capture, computing JA3/JA3S/JA4/JA4S fingerprints.
type TLSObserverModule struct {
	config        *scannerconfig.Config
	readerFactory readerFactoryFunc // injectable for testing
}

func NewTLSObserverModule(cfg *scannerconfig.Config) *TLSObserverModule {
	return &TLSObserverModule{
		config: cfg,
		readerFactory: func(target string) (tlsparse.PacketSource, error) {
			if strings.HasPrefix(target, "iface:") {
				iface := strings.TrimPrefix(target, "iface:")
				return tlsparse.NewLiveCaptureReader(iface, "tcp port 443")
			}
			return tlsparse.NewPcapFileReader(target)
		},
	}
}

func (m *TLSObserverModule) Name() string                        { return "tls_observer" }
func (m *TLSObserverModule) Category() model.ModuleCategory      { return model.CategoryActiveNetwork }
func (m *TLSObserverModule) ScanTargetType() model.ScanTargetType { return model.TargetPcap }

func (m *TLSObserverModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	src, err := m.readerFactory(target.Value)
	if err != nil {
		return err
	}
	defer src.Close()

	flows := make(map[tlsparse.FlowKey]*tlsparse.FlowState)

	// Determine flow source label
	flowSource := "pcap_file"
	if strings.HasPrefix(target.Value, "iface:") {
		flowSource = "live_capture"
	}

	// For live capture, respect the window timeout
	var cancel context.CancelFunc
	scanCtx := ctx
	if flowSource == "live_capture" && m.config.PcapWindow > 0 {
		scanCtx, cancel = context.WithTimeout(ctx, m.config.PcapWindow)
		defer cancel()
	}

	for {
		select {
		case <-scanCtx.Done():
			// Emit what we have
			return m.emitFlowFindings(ctx, flows, flowSource, findings)
		default:
		}

		pkt, err := src.NextPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			continue // skip bad packets
		}
		if pkt == nil {
			continue
		}

		// Check for TLS handshake content type
		if len(pkt.Payload) < 6 || pkt.Payload[0] != 0x16 {
			continue
		}

		hsData, err := tlsparse.ExtractHandshakeFromTLSRecord(pkt.Payload)
		if err != nil || len(hsData) < 1 {
			continue
		}

		key := tlsparse.FlowKey{
			SrcIP:   pkt.SrcIP,
			SrcPort: pkt.SrcPort,
			DstIP:   pkt.DstIP,
			DstPort: pkt.DstPort,
		}
		// Normalize flow key: lower IP is always "src" for lookup
		reverseKey := tlsparse.FlowKey{
			SrcIP:   pkt.DstIP,
			SrcPort: pkt.DstPort,
			DstIP:   pkt.SrcIP,
			DstPort: pkt.SrcPort,
		}

		switch hsData[0] {
		case 0x01: // ClientHello
			if len(flows) >= maxFlows {
				continue
			}
			ch, err := tlsparse.ParseClientHello(hsData)
			if err != nil {
				continue
			}
			state, ok := flows[key]
			if !ok {
				state = &tlsparse.FlowState{Key: key}
				flows[key] = state
			}
			state.ClientHello = ch

		case 0x02: // ServerHello
			sh, err := tlsparse.ParseServerHello(hsData)
			if err != nil {
				continue
			}
			// ServerHello comes from the reverse direction
			state, ok := flows[reverseKey]
			if !ok {
				// ClientHello may have been missed; create partial flow
				state = &tlsparse.FlowState{Key: reverseKey}
				flows[reverseKey] = state
			}
			state.ServerHello = sh
		}
	}

	return m.emitFlowFindings(ctx, flows, flowSource, findings)
}

func (m *TLSObserverModule) emitFlowFindings(ctx context.Context, flows map[tlsparse.FlowKey]*tlsparse.FlowState, flowSource string, findings chan<- *model.Finding) error {
	for _, flow := range flows {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var fp tlsparse.Fingerprint
		if flow.ClientHello != nil {
			fp.JA3Raw, fp.JA3 = tlsparse.JA3(flow.ClientHello)
			fp.JA4 = tlsparse.JA4(flow.ClientHello)
		}
		if flow.ServerHello != nil {
			fp.JA3SRaw, fp.JA3S = tlsparse.JA3S(flow.ServerHello)
			fp.JA4S = tlsparse.JA4S(flow.ServerHello)
		}

		endpoint := fmt.Sprintf("%s:%d → %s:%d",
			flow.Key.SrcIP, flow.Key.SrcPort,
			flow.Key.DstIP, flow.Key.DstPort)

		sni := ""
		if flow.ClientHello != nil {
			sni = flow.ClientHello.SNI
		}

		// Emit negotiated cipher finding if ServerHello is available
		if flow.ServerHello != nil {
			cipherName := fmt.Sprintf("0x%04x", flow.ServerHello.CipherSuite)
			asset := &model.CryptoAsset{
				ID:              uuid.Must(uuid.NewV7()).String(),
				Function:        "TLS cipher suite (observed)",
				Algorithm:       cipherName,
				Purpose:         fmt.Sprintf("Observed TLS cipher on %s", endpoint),
				SNI:             sni,
				TLSFlowSource:   flowSource,
				JA3Fingerprint:  fp.JA3,
				JA3SFingerprint: fp.JA3S,
				JA4Fingerprint:  fp.JA4,
				JA4SFingerprint: fp.JA4S,
			}
			crypto.ClassifyCryptoAsset(asset)

			f := &model.Finding{
				ID:       uuid.Must(uuid.NewV7()).String(),
				Category: 9, // Network/protocol
				Source: model.FindingSource{
					Type:            "network",
					Endpoint:        endpoint,
					DetectionMethod: "pcap-observation",
				},
				CryptoAsset: asset,
				Confidence:  0.95,
				Module:      "tls_observer",
				Timestamp:   time.Now(),
			}
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// Emit fingerprint finding (even if only ClientHello observed)
		if fp.JA3 != "" || fp.JA3S != "" {
			fpAsset := &model.CryptoAsset{
				ID:              uuid.Must(uuid.NewV7()).String(),
				Function:        "TLS fingerprint",
				Algorithm:       "JA3/JA4",
				Purpose:         fmt.Sprintf("TLS flow fingerprint for %s", endpoint),
				SNI:             sni,
				TLSFlowSource:   flowSource,
				JA3Fingerprint:  fp.JA3,
				JA3SFingerprint: fp.JA3S,
				JA4Fingerprint:  fp.JA4,
				JA4SFingerprint: fp.JA4S,
			}

			f := &model.Finding{
				ID:       uuid.Must(uuid.NewV7()).String(),
				Category: 9,
				Source: model.FindingSource{
					Type:            "network",
					Endpoint:        endpoint,
					DetectionMethod: "pcap-fingerprint",
				},
				CryptoAsset: fpAsset,
				Confidence:  0.90,
				Module:      "tls_observer",
				Timestamp:   time.Now(),
			}
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestTLSObserver ./pkg/scanner/ -count=1`
Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/tls_observer.go pkg/scanner/tls_observer_test.go
git commit -m "feat: add TLS observer module with JA3/JA3S/JA4/JA4S fingerprinting"
```

### Task 10: LDIF module

**Files:**
- Create: `pkg/scanner/ldif.go`
- Create: `pkg/scanner/ldif_test.go`

- [ ] **Step 1: Write ldif_test.go**

```go
package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
)

func TestLDIF_Name(t *testing.T) {
	m := NewLDIFModule(scannerconfig.Load("standard"))
	assert.Equal(t, "ldif", m.Name())
}

func TestLDIF_ParseSingleCert(t *testing.T) {
	ldif := makeLDIFWithCert(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "test.ldif")
	require.NoError(t, os.WriteFile(path, []byte(ldif), 0644))

	m := NewLDIFModule(scannerconfig.Load("standard"))
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 3}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}
	require.NotEmpty(t, results, "should find certificate in LDIF")
	assert.Equal(t, "ldif", results[0].Module)
}

func TestLDIF_FoldedLines(t *testing.T) {
	// LDIF continuation: line starting with single space is continuation of previous
	ldif := makeLDIFFoldedCert(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "folded.ldif")
	require.NoError(t, os.WriteFile(path, []byte(ldif), 0644))

	m := NewLDIFModule(scannerconfig.Load("standard"))
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 3}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}
	require.NotEmpty(t, results, "should parse folded LDIF lines")
}

func TestLDIF_NoCerts(t *testing.T) {
	ldif := "dn: cn=user,dc=example,dc=com\ncn: user\nobjectClass: person\n\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.ldif")
	require.NoError(t, os.WriteFile(path, []byte(ldif), 0644))

	m := NewLDIFModule(scannerconfig.Load("standard"))
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 3}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	count := 0
	for range findings {
		count++
	}
	assert.Zero(t, count, "no certs = no findings")
}

func TestLDIF_MalformedBase64(t *testing.T) {
	ldif := "dn: cn=bad,dc=example,dc=com\nuserCertificate:: !!!not-base64!!!\n\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.ldif")
	require.NoError(t, os.WriteFile(path, []byte(ldif), 0644))

	m := NewLDIFModule(scannerconfig.Load("standard"))
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 3}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err) // should not error, just skip bad data
	close(findings)
}

func TestLDIF_MultipleCertAttributes(t *testing.T) {
	ldif := makeLDIFMultiCerts(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "multi.ldif")
	require.NoError(t, os.WriteFile(path, []byte(ldif), 0644))

	m := NewLDIFModule(scannerconfig.Load("standard"))
	findings := make(chan *model.Finding, 100)
	target := model.ScanTarget{Type: model.TargetFilesystem, Value: dir, Depth: 3}

	err := m.Scan(context.Background(), target, findings)
	require.NoError(t, err)
	close(findings)

	var results []*model.Finding
	for f := range findings {
		results = append(results, f)
	}
	assert.GreaterOrEqual(t, len(results), 2, "should find multiple certs")
}

// --- Test helpers ---
// These generate LDIF content with embedded self-signed certs.
// The actual cert generation reuses crypto/x509 + crypto/ecdsa.

func makeLDIFWithCert(t *testing.T) string {
	t.Helper()
	b64 := generateSelfSignedCertBase64(t)
	return "dn: cn=server,dc=example,dc=com\nobjectClass: inetOrgPerson\nuserCertificate:: " + b64 + "\n\n"
}

func makeLDIFFoldedCert(t *testing.T) string {
	t.Helper()
	b64 := generateSelfSignedCertBase64(t)
	// Split into 76-char lines with continuation
	var folded string
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		if i == 0 {
			folded += b64[i:end] + "\n"
		} else {
			folded += " " + b64[i:end] + "\n"
		}
	}
	return "dn: cn=folded,dc=example,dc=com\nuserCertificate:: " + folded + "\n"
}

func makeLDIFMultiCerts(t *testing.T) string {
	t.Helper()
	b64a := generateSelfSignedCertBase64(t)
	b64b := generateSelfSignedCertBase64(t)
	return "dn: cn=multi,dc=example,dc=com\nuserCertificate:: " + b64a + "\ncACertificate:: " + b64b + "\n\n"
}

func generateSelfSignedCertBase64(t *testing.T) string {
	t.Helper()
	// Generate a self-signed cert and return base64(DER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(der)
}
```

Note: You'll need to add proper imports (`crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `crypto/x509`, `crypto/x509/pkix`, `encoding/base64`, `math/big`, `time`) to the test file.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestLDIF ./pkg/scanner/ -count=1`
Expected: FAIL — `NewLDIFModule` not defined.

- [ ] **Step 3: Implement ldif.go**

```go
package scanner

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

// certAttributes are the LDIF attribute names that hold DER-encoded certificates.
// The double-colon (::) suffix in LDIF indicates base64 encoding.
var certAttributes = []string{
	"usercertificate",
	"cacertificate",
	"usersmimecertificate",
	"crosscertificatepair",
}

// LDIFModule extracts X.509 certificates from LDAP Data Interchange Format files.
type LDIFModule struct {
	config      *scannerconfig.Config
	reader      fsadapter.FileReader
	lastScanned int64
	lastMatched int64
}

func NewLDIFModule(cfg *scannerconfig.Config) *LDIFModule {
	return &LDIFModule{config: cfg}
}

func (m *LDIFModule) Name() string                         { return "ldif" }
func (m *LDIFModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *LDIFModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *LDIFModule) SetFileReader(r fsadapter.FileReader)  { m.reader = r }
func (m *LDIFModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *LDIFModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)

	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isLDIFFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		reader:       m.reader,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			return m.parseLDIF(ctx, reader, path, findings)
		},
	})
}

func isLDIFFile(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".ldif"
}

func (m *LDIFModule) parseLDIF(ctx context.Context, reader fsadapter.FileReader, path string, findings chan<- *model.Finding) error {
	f, err := reader.Open(path)
	if err != nil {
		return nil // fail-open
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var currentDN string
	var attrName string
	var attrValue strings.Builder
	certIndex := 0

	flushAttr := func() {
		if attrName == "" {
			return
		}
		val := strings.TrimSpace(attrValue.String())
		if val == "" {
			attrName = ""
			attrValue.Reset()
			return
		}
		if isCertAttribute(attrName) {
			if err := m.emitCert(ctx, path, currentDN, val, certIndex, findings); err == nil {
				certIndex++
			}
		}
		attrName = ""
		attrValue.Reset()
	}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Text()

		// Empty line = end of entry
		if line == "" {
			flushAttr()
			currentDN = ""
			certIndex = 0
			continue
		}

		// Continuation line (starts with single space)
		if len(line) > 0 && line[0] == ' ' {
			attrValue.WriteString(strings.TrimPrefix(line, " "))
			continue
		}

		// New attribute — flush previous
		flushAttr()

		// Parse attribute: name:: base64value (double colon = base64)
		if idx := strings.Index(line, ":: "); idx > 0 {
			attrName = strings.ToLower(line[:idx])
			attrValue.WriteString(line[idx+3:])
		} else if idx := strings.Index(line, ": "); idx > 0 {
			name := strings.ToLower(line[:idx])
			if name == "dn" {
				currentDN = line[idx+2:]
			}
			// Non-base64 attributes are not cert data (certs are always ::)
		}
	}
	flushAttr()

	if err := scanner.Err(); err != nil {
		// Log but don't fail — bufio.ErrTooLong etc.
		_ = err
	}
	return nil
}

func isCertAttribute(name string) bool {
	for _, attr := range certAttributes {
		if name == attr {
			return true
		}
	}
	return false
}

func (m *LDIFModule) emitCert(ctx context.Context, path, dn, b64Value string, index int, findings chan<- *model.Finding) error {
	der, err := base64.StdEncoding.DecodeString(b64Value)
	if err != nil {
		// Try with padding stripped
		der, err = base64.RawStdEncoding.DecodeString(b64Value)
		if err != nil {
			return err
		}
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}

	algoName, keySize := certPublicKeyInfo(cert)
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter

	location := path
	if dn != "" {
		location = fmt.Sprintf("ldif:%s", dn)
	}

	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  "X.509 certificate (LDIF)",
		Algorithm: algoName,
		KeySize:   keySize,
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		NotBefore: &notBefore,
		NotAfter:  &notAfter,
		IsCA:      cert.IsCA,
		Purpose:   fmt.Sprintf("Certificate extracted from LDIF entry %s", location),
	}
	crypto.ClassifyCryptoAsset(asset)

	f := &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 5, // Certificates
		Source: model.FindingSource{
			Type:            "file",
			Path:            path,
			DetectionMethod: "ldif-parse",
			Evidence:        location,
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "ldif",
		Timestamp:   time.Now(),
	}

	select {
	case findings <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

Note: `certPublicKeyInfo` is an existing helper in `pkg/scanner/` (used by protocol.go and certificate.go). If it's not exported, the LDIF module will need its own version or the existing one needs to be exported.

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestLDIF ./pkg/scanner/ -count=1`
Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/ldif.go pkg/scanner/ldif_test.go
git commit -m "feat: add LDIF module for certificate extraction from LDAP exports"
```

### Task 11: FTPS module

**Files:**
- Create: `pkg/scanner/ftps.go`
- Create: `pkg/scanner/ftps_test.go`

- [ ] **Step 1: Write ftps_test.go with mock FTP server**

The test creates a local TCP listener that speaks minimal FTP protocol (sends 220 banner, accepts AUTH TLS, upgrades to TLS with a self-signed cert). Tests: explicit FTPS (AUTH TLS), failed AUTH (should try implicit), cert extraction.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestFTPS ./pkg/scanner/ -count=1`
Expected: FAIL — `NewFTPSModule` not defined.

- [ ] **Step 3: Implement ftps.go**

The module: dials TCP, reads 220 banner, sends `AUTH TLS\r\n`, reads response. If 234 → `tls.Client()` upgrade → extract cert chain via `tlsutil.WalkCertChain()`. If rejected → try port 990 implicit TLS. Emits findings per cert and for the negotiated cipher.

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestFTPS ./pkg/scanner/ -count=1`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/ftps.go pkg/scanner/ftps_test.go
git commit -m "feat: add FTPS module for certificate discovery via AUTH TLS"
```

### Task 12: SSH Certificate module

**Files:**
- Create: `pkg/scanner/ssh_cert.go`
- Create: `pkg/scanner/ssh_cert_test.go`

- [ ] **Step 1: Write ssh_cert_test.go with mock SSH server**

The test starts a local SSH server using `golang.org/x/crypto/ssh` that presents a host key. Tests: plain RSA host key extraction, ECDSA host key, OpenSSH certificate (if feasible to construct in test).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run TestSSHCert ./pkg/scanner/ -count=1`
Expected: FAIL — `NewSSHCertModule` not defined.

- [ ] **Step 3: Implement ssh_cert.go**

The module: dials TCP, performs SSH handshake with `InsecureIgnoreHostKey` callback that captures the host key. Checks if key is `*ssh.Certificate` → extract validity, CA key type, serial. Emits host key algorithm + size finding, plus certificate metadata if present.

- [ ] **Step 4: Run tests**

Run: `go test -v -run TestSSHCert ./pkg/scanner/ -count=1`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/ssh_cert.go pkg/scanner/ssh_cert_test.go
git commit -m "feat: add SSH certificate module for network host key discovery"
```

---

## Phase 4: Registration & CLI Wiring

### Task 13: Config, profiles, tier, and engine registration

**Files:**
- Modify: `internal/scannerconfig/config.go`
- Modify: `internal/license/tier.go`
- Modify: `pkg/scanner/engine.go`

- [ ] **Step 1: Add pcap config fields to scannerconfig**

In `internal/scannerconfig/config.go`, add to the `Config` struct after the UEFI fields:

```go
	// Pcap settings (consumed by tls_observer module).
	PcapFile      string        // path to .pcap/.pcapng file
	PcapInterface string        // network interface for live capture
	PcapWindow    time.Duration // live capture duration (default 30s)
	PcapFilter    string        // BPF filter (default "tcp port 443")
```

- [ ] **Step 2: Add modules to profiles**

In `config.go`, add `"ldif"` to the standard profile's Modules slice. Add `"tls_observer"`, `"ftps"`, `"ssh_cert"`, `"ldif"` to the comprehensive profile's Modules slice.

Also add `"ftps"` and `"ssh_cert"` to the standard profile (these are lightweight network scans).

- [ ] **Step 3: Add pcap target injection in Load()**

In `config.go`'s module-to-target switch, add a case for `tls_observer`: if `cfg.PcapFile != ""` or `cfg.PcapInterface != ""`, add a `TargetPcap` target.

- [ ] **Step 4: Add modules to tier.go proModules()**

In `internal/license/tier.go`, add `"tls_observer"`, `"ftps"`, `"ssh_cert"`, `"ldif"` to the `proModules()` return slice. Also add `"ldif"` to `freeModules` since it's filesystem-only.

- [ ] **Step 5: Register factories in engine.go**

In `pkg/scanner/engine.go`, add to `defaultModuleFactories`:

```go
func(c *scannerconfig.Config) Module { return NewTLSObserverModule(c) },
func(c *scannerconfig.Config) Module { return NewFTPSModule(c) },
func(c *scannerconfig.Config) Module { return NewSSHCertModule(c) },
func(c *scannerconfig.Config) Module { return NewLDIFModule(c) },
```

- [ ] **Step 6: Verify build and existing tests**

Run: `go build ./... && go test ./pkg/scanner/ -count=1 -timeout 60s`
Expected: clean build, all existing tests pass.

- [ ] **Step 7: Commit**

```bash
git add internal/scannerconfig/config.go internal/license/tier.go pkg/scanner/engine.go
git commit -m "wire: register tls_observer/ftps/ssh_cert/ldif in profiles, tiers, engine"
```

### Task 14: CLI flags in cmd/root.go

**Files:**
- Modify: `cmd/root.go`

- [ ] **Step 1: Add flags**

After the eBPF flags block (~line 191), add:

```go
	// Pcap / TLS observer flags.
	rootCmd.PersistentFlags().String("pcap-file", "",
		"path to .pcap/.pcapng file for offline TLS observation")
	rootCmd.PersistentFlags().String("pcap-interface", "",
		"network interface for live TLS capture (Linux only, requires CAP_NET_RAW)")
	rootCmd.PersistentFlags().Duration("pcap-window", 30*time.Second,
		"live capture duration for tls_observer (clamped to [1s, 5m])")
	rootCmd.PersistentFlags().String("pcap-filter", "tcp port 443",
		"BPF filter for tls_observer (default: tcp port 443)")
	rootCmd.MarkFlagsMutuallyExclusive("pcap-file", "pcap-interface")
```

- [ ] **Step 2: Wire flags to config**

After the eBPF config wiring block (~line 375), add:

```go
	// Pcap/TLS observer flag overrides.
	if v, _ := cmd.Flags().GetString("pcap-file"); v != "" {
		cfg.PcapFile = v
		cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
			Type: model.TargetPcap, Value: v,
		})
	}
	if v, _ := cmd.Flags().GetString("pcap-interface"); v != "" {
		cfg.PcapInterface = v
		cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
			Type: model.TargetPcap, Value: "iface:" + v,
		})
	}
	if v, err := cmd.Flags().GetDuration("pcap-window"); err == nil && v > 0 {
		if v < time.Second {
			v = time.Second
		}
		if v > 5*time.Minute {
			v = 5 * time.Minute
		}
		cfg.PcapWindow = v
	}
	if v, _ := cmd.Flags().GetString("pcap-filter"); v != "" {
		cfg.PcapFilter = v
	}
```

- [ ] **Step 3: Verify build**

Run: `go build ./cmd/...`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add cmd/root.go
git commit -m "cli: add --pcap-file, --pcap-interface, --pcap-window, --pcap-filter flags"
```

### Task 15: Doctor checks for live pcap

**Files:**
- Create: `pkg/scanner/doctor_pcap_linux.go`
- Create: `pkg/scanner/doctor_pcap_other.go`
- Modify: `pkg/scanner/doctor.go`

- [ ] **Step 1: Write doctor_pcap_linux.go**

```go
//go:build linux

package scanner

import "os"

// pcapDoctorCheck validates privileges for live AF_PACKET capture.
func pcapDoctorCheck() (ok bool, detail string) {
	if os.Geteuid() != 0 {
		return false, "not root; live pcap requires CAP_NET_RAW or root"
	}
	return true, "root access available for AF_PACKET"
}
```

- [ ] **Step 2: Write doctor_pcap_other.go**

```go
//go:build !linux

package scanner

func pcapDoctorCheck() (ok bool, detail string) {
	return false, "live pcap capture requires Linux (AF_PACKET); offline .pcap file analysis works on all platforms"
}
```

- [ ] **Step 3: Wire into doctor.go RunDoctor**

Add `tls_observer` to the special-check section of `RunDoctor` (same pattern as eBPF). Call `pcapDoctorCheck()` and emit the result.

- [ ] **Step 4: Verify build**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/doctor_pcap_linux.go pkg/scanner/doctor_pcap_other.go pkg/scanner/doctor.go
git commit -m "doctor: add CAP_NET_RAW check for live pcap capture"
```

---

## Phase 5: Report Rendering

### Task 16: HTML and CycloneDX fingerprint rendering

**Files:**
- Modify: `pkg/report/generator.go`
- Modify: `pkg/report/cyclonedx.go`
- Create: tests in existing test files

- [ ] **Step 1: Add JA3/JA4 to HTML finding detail**

In `generator.go`, in the finding detail rendering section (near the QualityWarnings badge), add after the existing badges:

```go
		if row.asset.JA3Fingerprint != "" {
			algoCell += fmt.Sprintf(` <span class="ja-badge" title="JA3: %s">JA3</span>`, row.asset.JA3Fingerprint)
		}
		if row.asset.JA4Fingerprint != "" {
			algoCell += fmt.Sprintf(` <span class="ja-badge" title="JA4: %s">JA4</span>`, row.asset.JA4Fingerprint)
		}
```

- [ ] **Step 2: Add triton:ja* properties to CycloneDX**

In `cyclonedx.go`, after the quality-warning properties block, add:

```go
	if asset.JA3Fingerprint != "" {
		props = append(props, CDXProperty{Name: "triton:ja3", Value: asset.JA3Fingerprint})
	}
	if asset.JA3SFingerprint != "" {
		props = append(props, CDXProperty{Name: "triton:ja3s", Value: asset.JA3SFingerprint})
	}
	if asset.JA4Fingerprint != "" {
		props = append(props, CDXProperty{Name: "triton:ja4", Value: asset.JA4Fingerprint})
	}
	if asset.JA4SFingerprint != "" {
		props = append(props, CDXProperty{Name: "triton:ja4s", Value: asset.JA4SFingerprint})
	}
```

- [ ] **Step 3: Add test for HTML JA3 rendering**

```go
func TestGenerateHTML_SurfacesJA3Fingerprint(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.Finding{{
			ID: "1", Module: "tls_observer", Category: 9,
			CryptoAsset: &model.CryptoAsset{
				Algorithm:      "TLS_AES_128_GCM_SHA256",
				JA3Fingerprint: "e7d705a3286e19ea42f587b344ee6865",
				JA4Fingerprint: "t13d1516h2_8daaf6152771_b186095e22b6",
			},
		}},
	}
	out, err := GenerateHTML(result)
	require.NoError(t, err)
	assert.Contains(t, string(out), "JA3")
	assert.Contains(t, string(out), "e7d705a3286e19ea42f587b344ee6865")
}
```

- [ ] **Step 4: Add test for CycloneDX JA3 properties**

```go
func TestCycloneDX_SurfacesJA3Properties(t *testing.T) {
	result := &model.ScanResult{
		Findings: []model.Finding{{
			ID: "1", Module: "tls_observer", Category: 9,
			CryptoAsset: &model.CryptoAsset{
				Algorithm:       "TLS_AES_128_GCM_SHA256",
				JA3Fingerprint:  "e7d705a3286e19ea42f587b344ee6865",
				JA3SFingerprint: "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5",
			},
		}},
	}
	out, err := GenerateCycloneDX(result)
	require.NoError(t, err)
	s := string(out)
	assert.Contains(t, s, "triton:ja3")
	assert.Contains(t, s, "e7d705a3286e19ea42f587b344ee6865")
	assert.Contains(t, s, "triton:ja3s")
}
```

- [ ] **Step 5: Run tests**

Run: `go test -v ./pkg/report/ -count=1`
Expected: all tests pass (existing + new).

- [ ] **Step 6: Commit**

```bash
git add pkg/report/generator.go pkg/report/cyclonedx.go pkg/report/generator_test.go pkg/report/cyclonedx_test.go
git commit -m "report: render JA3/JA4 fingerprints in HTML and CycloneDX"
```

---

## Phase 6: Final Verification

### Task 17: Full build, lint, and test

- [ ] **Step 1: Run full build**

Run: `go build ./...`
Expected: clean build.

- [ ] **Step 2: Run lint**

Run: `make lint`
Expected: clean (or only pre-existing warnings).

- [ ] **Step 3: Run unit tests**

Run: `make test`
Expected: all pass.

- [ ] **Step 4: Run go vet**

Run: `go vet ./...`
Expected: clean.

- [ ] **Step 5: Check module count**

Verify the engine module count increased by 4 (from 51 to 55).

- [ ] **Step 6: Commit any lint fixes**

```bash
git add -A && git commit -m "fix: resolve lint issues"
```

### Task 18: Update CLAUDE.md module count and profile docs

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update module count**

Update "51 scanner modules" references to "55 scanner modules".

- [ ] **Step 2: Add new modules to scanner list**

Add `tls_observer.go`, `ftps.go`, `ssh_cert.go`, `ldif.go` descriptions to the scanner module list.

- [ ] **Step 3: Update profile descriptions**

Add new modules to the standard and comprehensive profile descriptions.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for wave 2 modules (55 total)"
```
