package crypto

import "testing"

func TestOIDRegistryMinimumCoverage(t *testing.T) {
	if len(oidRegistry) < 30 {
		t.Fatalf("expected registry size >= 30, got %d", len(oidRegistry))
	}
	// Spot-check critical entries
	must := []string{
		"2.16.840.1.101.3.4.4.1",  // ML-KEM-512
		"2.16.840.1.101.3.4.3.17", // ML-DSA-44
		"1.2.840.113549.1.1.11",   // sha256WithRSAEncryption
		"1.3.101.112",             // Ed25519
	}
	for _, oid := range must {
		if _, ok := oidRegistry[oid]; !ok {
			t.Errorf("missing critical OID: %s", oid)
		}
	}
}

func TestOIDRegistryExpandedCoverage(t *testing.T) {
	if len(oidRegistry) < 200 {
		t.Fatalf("expected registry size >= 200 after expansion, got %d", len(oidRegistry))
	}

	// Representative entries across families
	cases := []struct {
		oid     string
		wantAlg string
	}{
		// Hash families
		{"1.2.840.113549.2.5", "MD5"},
		{"1.3.14.3.2.26", "SHA-1"},
		{"2.16.840.1.101.3.4.2.1", "SHA-256"},
		{"2.16.840.1.101.3.4.2.8", "SHA3-256"},
		// Symmetric
		{"2.16.840.1.101.3.4.1.2", "AES-128-CBC"},
		{"2.16.840.1.101.3.4.1.42", "AES-256-CBC"},
		{"2.16.840.1.101.3.4.1.46", "AES-256-GCM"},
		{"1.2.840.113549.3.7", "3DES-CBC"},
		// EC curves
		{"1.2.840.10045.3.1.7", "ECDSA-P256"},
		{"1.3.132.0.34", "ECDSA-P384"},
		{"1.3.132.0.35", "ECDSA-P521"},
		// Diffie-Hellman
		{"1.2.840.113549.1.3.1", "DH"},
		// DSA
		{"1.2.840.10040.4.1", "DSA"},
		// Kerberos
		{"1.2.840.113554.1.2.2", "Kerberos"},
		// RSA-PSS / OAEP
		{"1.2.840.113549.1.1.10", "RSA-PSS"},
		{"1.2.840.113549.1.1.7", "RSA-OAEP"},
	}
	for _, c := range cases {
		entry, ok := oidRegistry[c.oid]
		if !ok {
			t.Errorf("missing OID %s (%s)", c.oid, c.wantAlg)
			continue
		}
		if entry.Algorithm != c.wantAlg {
			t.Errorf("OID %s: got algorithm %q, want %q", c.oid, entry.Algorithm, c.wantAlg)
		}
	}
}
