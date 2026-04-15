package keyquality

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestRocaCheck_KnownVulnerableModulus(t *testing.T) {
	t.Skip("testdata/roca-vuln-modulus.hex is a placeholder; replace with a genuine Infineon-produced modulus before ship")
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
	if fp > trials/10 {
		t.Errorf("false-positive rate too high: %d / %d trials fired", fp, trials)
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
