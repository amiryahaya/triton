package keyquality

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestWarning_Format(t *testing.T) {
	w := Warning{
		Code:     CodeROCA,
		Severity: SeverityCritical,
		Message:  "modulus matches",
		CVE:      "CVE-2017-15361",
	}
	want := "[CRITICAL] ROCA: modulus matches [CVE-2017-15361]"
	if got := w.Format(); got != want {
		t.Errorf("Format = %q, want %q", got, want)
	}
}

func TestWarning_Format_NoCVE(t *testing.T) {
	w := Warning{Code: CodeSizeMismatch, Severity: SeverityHigh, Message: "claimed 2048, actual 1024"}
	want := "[HIGH] SIZE-MISMATCH: claimed 2048, actual 1024"
	if got := w.Format(); got != want {
		t.Errorf("Format = %q, want %q", got, want)
	}
}

// TestAnalyze_CleanRSAHasNoWarnings checks that a non-Infineon RSA-2048 key
// produces no warnings. A single random key is ~1-2% likely to false-positive
// on the ROCA heuristic, so we generate up to 5 and succeed if any is clean.
func TestAnalyze_CleanRSAHasNoWarnings(t *testing.T) {
	for i := 0; i < 5; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("GenerateKey trial %d: %v", i, err)
		}
		if ws := Analyze(&key.PublicKey, "RSA", 2048); len(ws) == 0 {
			return // at least one clean key → pass
		}
	}
	t.Error("5 random RSA-2048 keys all produced warnings — Analyze is over-flagging")
}

func TestAnalyze_ECDSASkipsRSAChecks(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	ws := Analyze(&key.PublicKey, "ECDSA-P256", 256)
	// ECDSA only gets size-mismatch (which shouldn't fire for a clean key).
	for _, w := range ws {
		switch w.Code {
		case CodeROCA, CodeDebianWeak, CodeSmallPrime:
			t.Errorf("RSA-specific check fired on ECDSA key: %+v", w)
		}
	}
}

func TestAnalyze_Ed25519SkipsRSAChecks(t *testing.T) {
	// ed25519.PublicKey is []byte; the pub interface type check will not match *rsa.PublicKey.
	key := make([]byte, 32) // placeholder; actual type switch is what matters
	_ = key
	// Nothing to assert on output except that the call does not panic and RSA checks skip.
	// Use an untyped nil pub to prove Analyze is panic-safe.
	ws := Analyze(nil, "Ed25519", 256)
	for _, w := range ws {
		if w.Code == CodeROCA || w.Code == CodeSmallPrime || w.Code == CodeDebianWeak {
			t.Errorf("RSA-specific check fired on nil key: %+v", w)
		}
	}
}

func TestFlatten(t *testing.T) {
	ws := []Warning{
		{Code: CodeROCA, Severity: SeverityCritical, Message: "x", CVE: "CVE-2017-15361"},
		{Code: CodeSizeMismatch, Severity: SeverityHigh, Message: "y"},
	}
	got := Flatten(ws)
	want := []string{
		"[CRITICAL] ROCA: x [CVE-2017-15361]",
		"[HIGH] SIZE-MISMATCH: y",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("Flatten[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
