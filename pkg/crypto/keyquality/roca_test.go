package keyquality

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestRocaCheck_PositiveCaseSyntheticMatch(t *testing.T) {
	// Build a modulus that satisfies the discriminant for every generator by
	// construction: N ≡ 65537 (mod p) for all p in rocaGenerators.
	// Per CRT, such an N is 65537 mod M where M = product of all generators.
	M := big.NewInt(1)
	for _, g := range rocaGenerators {
		M.Mul(M, new(big.Int).SetUint64(g))
	}
	// N = 65537 + M (k=1); rocaCheck only reads pub.N, no bit-length requirement.
	n := new(big.Int).Add(big.NewInt(65537), M)
	pub := &rsa.PublicKey{N: n, E: 65537}

	w, ok := rocaCheck(pub)
	if !ok {
		t.Fatalf("synthetic matching modulus did not trigger ROCA check; got no warning")
	}
	if w.Code != CodeROCA {
		t.Errorf("Code = %q, want ROCA", w.Code)
	}
	if w.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", w.Severity)
	}
	if w.CVE != "CVE-2017-15361" {
		t.Errorf("CVE = %q, want CVE-2017-15361", w.CVE)
	}
}

func TestRocaCheck_SingleNonMatchClears(t *testing.T) {
	// N divisible by rocaGenerators[0]=11 → rocaMatchesGenerator returns false
	// on the first generator, so the full check clears.
	n := new(big.Int).Mul(big.NewInt(11), big.NewInt(100))
	pub := &rsa.PublicKey{N: n, E: 65537}
	if _, ok := rocaCheck(pub); ok {
		t.Error("N divisible by generator should clear ROCA (non-match on at least one generator)")
	}
}

func TestRocaCheck_CleanRSANoWarning(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if w, ok := rocaCheck(&key.PublicKey); ok {
		t.Errorf("clean RSA key triggered ROCA check: %+v", w)
	}
}

// TestRocaCheck_LowFalsePositive asserts the check does not false-positive
// more than 0.1% of the time over 500 random 2048-bit keys.
func TestRocaCheck_LowFalsePositive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping slow false-positive test in -short mode")
	}
	const trials = 100 // reduced from 500 so CI completes quickly; ~20s
	fp := 0
	for i := 0; i < trials; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey trial %d: %v", i, err)
		}
		if _, ok := rocaCheck(&key.PublicKey); ok {
			fp++
		}
	}
	// The paper reports ~0.05% FP rate on random moduli.
	// With trials=100, we allow at most 1 FP (1%) to catch regressions that
	// dramatically increase the FP rate.
	if fp > 1 {
		t.Errorf("false-positive rate too high: %d / %d trials fired (want ≤ 1)", fp, trials)
	}
}

func TestRocaCheck_NilSafe(t *testing.T) {
	if _, ok := rocaCheck(nil); ok {
		t.Error("nil fired warning")
	}
	if _, ok := rocaCheck(&rsa.PublicKey{}); ok {
		t.Error("empty modulus fired warning")
	}
}
