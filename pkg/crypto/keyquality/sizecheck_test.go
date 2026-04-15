package keyquality

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestSizeMismatchCheck_MatchingSize(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	w, ok := sizeMismatchCheck(&key.PublicKey, 2048)
	if ok {
		t.Errorf("matching size fired warning: %+v", w)
	}
}

func TestSizeMismatchCheck_OneBitTolerance(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// 2047 (off-by-one) should NOT fire.
	if _, ok := sizeMismatchCheck(&key.PublicKey, 2047); ok {
		t.Errorf("off-by-one fired warning; tolerance violated")
	}
}

func TestSizeMismatchCheck_HighDelta(t *testing.T) {
	// Claim 2048, actual modulus 1024 → HIGH warning.
	key, _ := rsa.GenerateKey(rand.Reader, 1024)
	w, ok := sizeMismatchCheck(&key.PublicKey, 2048)
	if !ok {
		t.Fatal("expected warning on claimed=2048 actual=1024")
	}
	if w.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want HIGH", w.Severity)
	}
	if w.Code != CodeSizeMismatch {
		t.Errorf("Code = %q, want SIZE-MISMATCH", w.Code)
	}
}

func TestSizeMismatchCheck_Critical(t *testing.T) {
	// Claimed >= 2048 and actual < 1024 bits → CRITICAL.
	n := new(big.Int).Lsh(big.NewInt(1), 511) // 512-bit modulus
	pub := &rsa.PublicKey{N: n, E: 65537}
	w, ok := sizeMismatchCheck(pub, 2048)
	if !ok {
		t.Fatal("expected warning")
	}
	if w.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", w.Severity)
	}
}

func TestSizeMismatchCheck_NonRSASkips(t *testing.T) {
	if _, ok := sizeMismatchCheck(nil, 256); ok {
		t.Error("nil key fired warning")
	}
	if _, ok := sizeMismatchCheck("not a key", 256); ok {
		t.Error("non-key type fired warning")
	}
}
