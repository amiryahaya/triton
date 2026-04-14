package crypto

import "testing"

func TestLookupJavaAlgorithm_JCAStandardNames(t *testing.T) {
	cases := []struct {
		literal    string
		wantAlg    string
		wantStatus PQCStatus
	}{
		{"AES/GCM/NoPadding", "AES", SAFE},
		{"AES/CBC/PKCS5Padding", "AES", TRANSITIONAL},
		{"DES/ECB/NoPadding", "DES", UNSAFE},
		{"DESede/CBC/PKCS5Padding", "3DES", DEPRECATED},
		{"RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA", TRANSITIONAL},
		{"SHA-256", "SHA-256", TRANSITIONAL},
		{"SHA-1", "SHA-1", DEPRECATED},
		{"MD5", "MD5", UNSAFE},
		{"SHA256withRSA", "SHA256withRSA", TRANSITIONAL},
		{"SHA1withDSA", "SHA1withDSA", DEPRECATED},
		{"Ed25519", "Ed25519", TRANSITIONAL},
		{"ML-DSA-65", "ML-DSA-65", SAFE},
		{"ML-KEM-768", "ML-KEM-768", SAFE},
	}
	for _, c := range cases {
		entry, ok := LookupJavaAlgorithm(c.literal)
		if !ok {
			t.Errorf("literal %q: not found in registry", c.literal)
			continue
		}
		if entry.Algorithm != c.wantAlg {
			t.Errorf("literal %q: got algorithm %q, want %q", c.literal, entry.Algorithm, c.wantAlg)
		}
		if entry.Status != c.wantStatus {
			t.Errorf("literal %q: got status %s, want %s", c.literal, entry.Status, c.wantStatus)
		}
	}
}

func TestLookupJavaAlgorithm_Unknown(t *testing.T) {
	if _, ok := LookupJavaAlgorithm("not-a-real-alg"); ok {
		t.Error("expected lookup miss on gibberish")
	}
}
