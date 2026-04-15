package keyquality

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
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

func TestSmallPrimeCheck_ExerciseRangeOfFactors(t *testing.T) {
	for _, factor := range []int64{2, 3, 7, 9973} {
		largePrime, _ := rand.Prime(rand.Reader, 1024)
		n := new(big.Int).Mul(big.NewInt(factor), largePrime)
		pub := &rsa.PublicKey{N: n, E: 65537}
		w, ok := smallPrimeCheck(pub)
		if !ok {
			t.Errorf("factor=%d: expected warning", factor)
			continue
		}
		if !strings.Contains(w.Message, fmt.Sprintf("%d", factor)) {
			t.Errorf("factor=%d: message %q doesn't reference factor", factor, w.Message)
		}
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
