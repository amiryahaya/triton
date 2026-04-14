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
