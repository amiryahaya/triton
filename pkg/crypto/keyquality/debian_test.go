package keyquality

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

// makeRSAKeyWithFingerprint constructs an rsa.PublicKey whose DER marshalling
// produces the specified SHA-1. Used to synthesise "known weak" keys for tests.
//
// Strategy: since we control what fingerprint to target via the test blocklist
// stubs (all-zeros...0001/0002), we do the OPPOSITE — we load a real key,
// compute its fingerprint, and put that into the blocklist at init time via
// a test-only hook. That requires exposing the fingerprint registry.
//
// The plan instead asserts behaviour by: (a) fingerprinting a freshly-generated
// key, (b) injecting that fingerprint into the blocklist set via a test-only
// exported function, (c) asserting the check now fires.

func TestDebianWeakCheck_HitsKeyInBlocklist(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := publicKeyFingerprintForTest(&key.PublicKey)

	injectBlocklistFingerprintForTest(debianRSA2048Set, fp)
	defer removeBlocklistFingerprintForTest(debianRSA2048Set, fp)

	w, ok := debianWeakCheck(&key.PublicKey, "RSA", 2048)
	if !ok {
		t.Fatal("expected warning on fingerprint injected into blocklist")
	}
	if w.Code != CodeDebianWeak {
		t.Errorf("Code = %q, want DEBIAN-WEAK", w.Code)
	}
	if w.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", w.Severity)
	}
	if w.CVE != "CVE-2008-0166" {
		t.Errorf("CVE = %q, want CVE-2008-0166", w.CVE)
	}
}

func TestDebianWeakCheck_MissNotInBlocklist(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if w, ok := debianWeakCheck(&key.PublicKey, "RSA", 2048); ok {
		t.Errorf("fresh key triggered Debian check: %+v", w)
	}
}

func TestDebianWeakCheck_UsesCorrectSetForDSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	fp := publicKeyFingerprintForTest(&key.PublicKey)
	// Inject into the DSA-1024 set, then check with algo="RSA" keySize=2048.
	// Must NOT fire (sets are keyed by algo+size).
	injectBlocklistFingerprintForTest(debianDSA1024Set, fp)
	defer removeBlocklistFingerprintForTest(debianDSA1024Set, fp)

	if _, ok := debianWeakCheck(&key.PublicKey, "RSA", 2048); ok {
		t.Error("DSA-1024 blocklist fired for RSA-2048 key; set-routing broken")
	}
}

func TestDebianWeakCheck_UnsupportedAlgoSizeSkips(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// RSA-4096 isn't in our blocklist set (no Debian weak-key corpus exists for it).
	if _, ok := debianWeakCheck(&key.PublicKey, "RSA", 4096); ok {
		t.Error("RSA-4096 should not be checked (no Debian blocklist for that size)")
	}
}

func TestDebianWeakCheck_EmbeddedStubLoads(t *testing.T) {
	// The package init should have loaded the four stub blocklists without error.
	if debianRSA1024Set == nil || debianRSA2048Set == nil ||
		debianDSA1024Set == nil || debianDSA2048Set == nil {
		t.Fatal("blocklist sets not initialised")
	}
	// Each stub contains exactly one fingerprint.
	if len(debianRSA1024Set) != 1 || len(debianRSA2048Set) != 1 ||
		len(debianDSA1024Set) != 1 || len(debianDSA2048Set) != 1 {
		t.Errorf("expected 1 fingerprint per stub set; got %d/%d/%d/%d",
			len(debianRSA1024Set), len(debianRSA2048Set),
			len(debianDSA1024Set), len(debianDSA2048Set))
	}
}

func TestDebianWeakCheck_NilSafe(t *testing.T) {
	if _, ok := debianWeakCheck(nil, "RSA", 2048); ok {
		t.Error("nil key fired warning")
	}
	// A key whose N is nil should not panic.
	if _, ok := debianWeakCheck(&rsa.PublicKey{N: new(big.Int), E: 0}, "RSA", 2048); ok {
		t.Error("empty key fired warning")
	}
}
