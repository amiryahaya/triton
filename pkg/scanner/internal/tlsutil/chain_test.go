package tlsutil_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/scanner/internal/tlsutil"
)

// selfSignedCert creates a minimal self-signed certificate for testing.
func selfSignedCert(t *testing.T, opts certOptions) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial := big.NewInt(1)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: opts.cn,
		},
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
		DNSNames:              opts.dnsNames,
		IPAddresses:           opts.ipAddresses,
	}

	if opts.sigAlgo != x509.UnknownSignatureAlgorithm {
		template.SignatureAlgorithm = opts.sigAlgo
	}

	// Self-sign
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// syntheticCert creates a synthetic x509.Certificate with a specified
// SignatureAlgorithm for testing purposes (bypassing Go's algorithm restrictions
// during cert creation). The public key is real but the signature is fabricated.
func syntheticCert(t *testing.T, sigAlgo x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	// Start from a valid cert and override the signature algorithm field.
	// This is safe for unit-testing the classification logic because
	// WalkCertChain only inspects cert.SignatureAlgorithm, not verifies signatures.
	base := selfSignedCert(t, defaultCertOpts("synthetic"))
	// x509.Certificate is a value type with exported fields — we can copy and modify.
	modified := *base
	modified.SignatureAlgorithm = sigAlgo
	return &modified
}

type certOptions struct {
	cn          string
	notBefore   time.Time
	notAfter    time.Time
	isCA        bool
	sigAlgo     x509.SignatureAlgorithm
	dnsNames    []string
	ipAddresses []net.IP
}

func defaultCertOpts(cn string) certOptions {
	now := time.Now()
	return certOptions{
		cn:        cn,
		notBefore: now.Add(-time.Hour),
		notAfter:  now.Add(365 * 24 * time.Hour),
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestWalkCertChain_Empty(t *testing.T) {
	entries := tlsutil.WalkCertChain(nil)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nil chain, got %d", len(entries))
	}

	entries = tlsutil.WalkCertChain([]*x509.Certificate{})
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for empty chain, got %d", len(entries))
	}
}

func TestWalkCertChain_SingleLeaf(t *testing.T) {
	opts := defaultCertOpts("leaf.example.com")
	cert := selfSignedCert(t, opts)

	entries := tlsutil.WalkCertChain([]*x509.Certificate{cert})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if e.Cert != cert {
		t.Error("expected Cert to be the input certificate")
	}
	if e.Position != "leaf" {
		t.Errorf("expected position=leaf, got %q", e.Position)
	}
	if e.WeakSignature {
		t.Error("ECDSA P-256 cert should not be flagged as weak signature")
	}
	if e.ExpiryWarning {
		t.Error("cert valid for 365 days should not have expiry warning")
	}
}

func TestWalkCertChain_WeakSHA1Signature(t *testing.T) {
	cert := syntheticCert(t, x509.SHA1WithRSA)

	entries := tlsutil.WalkCertChain([]*x509.Certificate{cert})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if !e.WeakSignature {
		t.Error("SHA-1 signed cert should be flagged as WeakSignature")
	}
	if e.WeakSigAlgo != "SHA-1" {
		t.Errorf("expected WeakSigAlgo=SHA-1, got %q", e.WeakSigAlgo)
	}
}

func TestWalkCertChain_ExpiryWarning30Days(t *testing.T) {
	now := time.Now()
	opts := certOptions{
		cn:        "expiring.example.com",
		notBefore: now.Add(-365 * 24 * time.Hour),
		notAfter:  now.Add(10 * 24 * time.Hour), // expires in 10 days
	}
	cert := selfSignedCert(t, opts)

	entries := tlsutil.WalkCertChain([]*x509.Certificate{cert})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if !e.ExpiryWarning {
		t.Error("cert expiring in 10 days should have ExpiryWarning")
	}
	if e.DaysRemaining < 9 || e.DaysRemaining > 11 {
		t.Errorf("expected DaysRemaining ~10, got %d", e.DaysRemaining)
	}
}

func TestWalkCertChain_NoExpiryWarningAt45Days(t *testing.T) {
	now := time.Now()
	opts := certOptions{
		cn:        "fine.example.com",
		notBefore: now.Add(-365 * 24 * time.Hour),
		notAfter:  now.Add(45 * 24 * time.Hour), // expires in 45 days — well outside 30-day warning window
	}
	cert := selfSignedCert(t, opts)

	entries := tlsutil.WalkCertChain([]*x509.Certificate{cert})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ExpiryWarning {
		t.Error("cert expiring in 45 days should NOT have ExpiryWarning")
	}
}

func TestWalkCertChain_AlreadyExpired(t *testing.T) {
	now := time.Now()
	opts := certOptions{
		cn:        "expired.example.com",
		notBefore: now.Add(-365 * 24 * time.Hour),
		notAfter:  now.Add(-24 * time.Hour), // already expired
	}
	cert := selfSignedCert(t, opts)

	entries := tlsutil.WalkCertChain([]*x509.Certificate{cert})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	// Already expired certs should NOT get an expiry warning (they're already past)
	if entries[0].ExpiryWarning {
		t.Error("already-expired cert should NOT have ExpiryWarning (only certs still valid but expiring soon)")
	}
}

func TestWalkCertChain_LeafIntermediateRoot(t *testing.T) {
	now := time.Now()
	base := certOptions{
		notBefore: now.Add(-time.Hour),
		notAfter:  now.Add(365 * 24 * time.Hour),
		isCA:      true,
	}

	leaf := selfSignedCert(t, certOptions{cn: "leaf.example.com", notBefore: base.notBefore, notAfter: base.notAfter})
	inter := selfSignedCert(t, certOptions{cn: "intermediate CA", notBefore: base.notBefore, notAfter: base.notAfter, isCA: true})
	root := selfSignedCert(t, certOptions{cn: "Root CA", notBefore: base.notBefore, notAfter: base.notAfter, isCA: true})

	entries := tlsutil.WalkCertChain([]*x509.Certificate{leaf, inter, root})

	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	if entries[0].Position != "leaf" {
		t.Errorf("index 0: expected position=leaf, got %q", entries[0].Position)
	}
	if entries[1].Position != "intermediate" {
		t.Errorf("index 1: expected position=intermediate, got %q", entries[1].Position)
	}
	if entries[2].Position != "root" {
		t.Errorf("index 2: expected position=root, got %q", entries[2].Position)
	}
}

func TestWalkCertChain_SANsOnLeaf(t *testing.T) {
	opts := certOptions{
		cn:          "example.com",
		notBefore:   time.Now().Add(-time.Hour),
		notAfter:    time.Now().Add(365 * 24 * time.Hour),
		dnsNames:    []string{"example.com", "www.example.com"},
		ipAddresses: []net.IP{net.ParseIP("192.168.1.1")},
	}
	cert := selfSignedCert(t, opts)

	entries := tlsutil.WalkCertChain([]*x509.Certificate{cert})

	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	e := entries[0]
	if len(e.SANs) != 3 {
		t.Errorf("expected 3 SANs (2 DNS + 1 IP), got %d: %v", len(e.SANs), e.SANs)
	}

	// Check DNS names present
	sanSet := make(map[string]bool)
	for _, s := range e.SANs {
		sanSet[s] = true
	}
	for _, want := range []string{"example.com", "www.example.com", "192.168.1.1"} {
		if !sanSet[want] {
			t.Errorf("expected SAN %q to be present, got %v", want, e.SANs)
		}
	}
}

func TestWalkCertChain_SANsOnNonLeaf(t *testing.T) {
	now := time.Now()
	leaf := selfSignedCert(t, certOptions{cn: "leaf.example.com", notBefore: now.Add(-time.Hour), notAfter: now.Add(365 * 24 * time.Hour)})
	// Intermediate with SANs — SANs should only be populated for the leaf
	inter := selfSignedCert(t, certOptions{
		cn:        "intermediate CA",
		notBefore: now.Add(-time.Hour),
		notAfter:  now.Add(365 * 24 * time.Hour),
		isCA:      true,
		dnsNames:  []string{"intermediate.example.com"},
	})

	entries := tlsutil.WalkCertChain([]*x509.Certificate{leaf, inter})

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if len(entries[1].SANs) != 0 {
		t.Errorf("expected no SANs on non-leaf (index 1), got %v", entries[1].SANs)
	}
}

// ---------------------------------------------------------------------------
// CertAlgoName tests
// ---------------------------------------------------------------------------

func TestCertAlgoName_ECDSA(t *testing.T) {
	cert := selfSignedCert(t, defaultCertOpts("test"))
	name := tlsutil.CertAlgoName(cert)
	if name == "" {
		t.Error("CertAlgoName should return non-empty string for ECDSA cert")
	}
}

// ---------------------------------------------------------------------------
// SigAlgoToPQCName tests
// ---------------------------------------------------------------------------

func TestSigAlgoToPQCName_SHA1(t *testing.T) {
	got := tlsutil.SigAlgoToPQCName(x509.SHA1WithRSA)
	if got != "SHA-1" {
		t.Errorf("expected SHA-1, got %q", got)
	}
}

func TestSigAlgoToPQCName_MD5(t *testing.T) {
	got := tlsutil.SigAlgoToPQCName(x509.MD5WithRSA)
	if got != "MD5" {
		t.Errorf("expected MD5, got %q", got)
	}
}

func TestSigAlgoToPQCName_SHA256(t *testing.T) {
	got := tlsutil.SigAlgoToPQCName(x509.SHA256WithRSA)
	if got != "SHA-256" {
		t.Errorf("expected SHA-256, got %q", got)
	}
}

func TestSigAlgoToPQCName_Ed25519(t *testing.T) {
	got := tlsutil.SigAlgoToPQCName(x509.PureEd25519)
	if got != "Ed25519" {
		t.Errorf("expected Ed25519, got %q", got)
	}
}

func TestSigAlgoToPQCName_Unknown(t *testing.T) {
	// Unknown algorithm should fall back to the .String() representation
	got := tlsutil.SigAlgoToPQCName(x509.UnknownSignatureAlgorithm)
	if got == "" {
		t.Error("SigAlgoToPQCName should return non-empty for unknown algorithm")
	}
}
