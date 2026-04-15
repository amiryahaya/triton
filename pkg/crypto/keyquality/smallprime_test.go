package keyquality

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"
)

func TestSmallPrimeCheck_FindsKnownFactor(t *testing.T) {
	// Construct a "broken" modulus n = 9973 * large_prime.
	// 9973 is the largest prime ≤ smallPrimeMax (10000), so trial division finds it.
	largePrime, _ := rand.Prime(rand.Reader, 1024)
	n := new(big.Int).Mul(big.NewInt(9973), largePrime)
	pub := &rsa.PublicKey{N: n, E: 65537}

	w, ok := smallPrimeCheck(pub)
	if !ok {
		t.Fatal("expected warning on modulus with small prime factor")
	}
	if w.Severity != SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", w.Severity)
	}
	if w.Code != CodeSmallPrime {
		t.Errorf("Code = %q, want SMALL-PRIME", w.Code)
	}
	// Message should mention the actual factor.
	if !containsSubstring(w.Message, "9973") {
		t.Errorf("Message %q does not reference the factor 9973", w.Message)
	}
}

func TestSmallPrimeCheck_CleanKeyNoWarning(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if w, ok := smallPrimeCheck(&key.PublicKey); ok {
		t.Errorf("clean RSA-2048 triggered small-prime warning: %+v", w)
	}
}

func TestSmallPrimeCheck_NilModulusSafe(t *testing.T) {
	if _, ok := smallPrimeCheck(nil); ok {
		t.Error("nil key fired warning")
	}
	if _, ok := smallPrimeCheck(&rsa.PublicKey{}); ok {
		t.Error("empty modulus fired warning")
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
