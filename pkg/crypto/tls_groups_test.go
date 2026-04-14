package crypto

import "testing"

func TestTLSGroupRegistry_ClassicalPresent(t *testing.T) {
	cases := []struct {
		id     uint16
		name   string
		hybrid bool
	}{
		{0x0017, "secp256r1", false},
		{0x0018, "secp384r1", false},
		{0x0019, "secp521r1", false},
		{0x001D, "x25519", false},
		{0x001E, "x448", false},
		{0x0100, "ffdhe2048", false},
	}
	for _, c := range cases {
		g, ok := LookupTLSGroup(c.id)
		if !ok {
			t.Errorf("missing group 0x%04X (%s)", c.id, c.name)
			continue
		}
		if g.Name != c.name {
			t.Errorf("group 0x%04X: got name %q, want %q", c.id, g.Name, c.name)
		}
		if g.IsHybrid != c.hybrid {
			t.Errorf("group 0x%04X: IsHybrid=%v, want %v", c.id, g.IsHybrid, c.hybrid)
		}
	}
}

func TestTLSGroupRegistry_HybridPQCPresent(t *testing.T) {
	cases := []struct {
		id         uint16
		name       string
		components []string
	}{
		{0x11EC, "X25519MLKEM768", []string{"X25519", "ML-KEM-768"}},
		{0x11EB, "SecP256r1MLKEM768", []string{"secp256r1", "ML-KEM-768"}},
		{0x11ED, "SecP384r1MLKEM1024", []string{"secp384r1", "ML-KEM-1024"}},
		// Draft / pre-standard hybrids — buyers are deploying these today
		{0x6399, "X25519Kyber768Draft00", []string{"X25519", "Kyber-768"}},
		{0x639A, "SecP256r1Kyber768Draft00", []string{"secp256r1", "Kyber-768"}},
	}
	for _, c := range cases {
		g, ok := LookupTLSGroup(c.id)
		if !ok {
			t.Errorf("missing hybrid group 0x%04X (%s)", c.id, c.name)
			continue
		}
		if !g.IsHybrid {
			t.Errorf("group 0x%04X (%s): expected IsHybrid=true", c.id, c.name)
		}
		if g.Status != SAFE {
			t.Errorf("group 0x%04X (%s): hybrid groups should be SAFE, got %v", c.id, c.name, g.Status)
		}
		if len(g.ComponentAlgorithms) != 2 {
			t.Errorf("group 0x%04X (%s): expected 2 components, got %v", c.id, c.name, g.ComponentAlgorithms)
		}
	}
}

// TestHybridGroupStatusConsistentWithAlgorithmRegistry pins the Status
// field between tls_groups.go (TLS named group registry) and pqc.go
// (algorithm registry) for hybrid + pure-PQ lattice entries, so a drift
// in one registry is caught at test time instead of producing
// inconsistent report output. Classical entries are skipped — their
// names ("secp256r1", "x25519") are classified via substring logic in
// ClassifyAlgorithm and are not expected to have a direct registry
// entry under their TLS group name.
func TestHybridGroupStatusConsistentWithAlgorithmRegistry(t *testing.T) {
	for _, g := range tlsGroupData() {
		// Only pin hybrids and pure-PQ groups (both surface via
		// ComponentAlgorithms populated in tls_groups.go). Classical
		// ECDHE/DHE groups don't have their TLS-group name in the
		// algorithm registry.
		if !g.IsHybrid && len(g.ComponentAlgorithms) == 0 {
			continue
		}
		// Only compare when the algorithm registry has a direct
		// entry for this name — otherwise ClassifyAlgorithm's
		// fallback chain (substring, family-prefix, TRANSITIONAL
		// default) may disagree with the TLS-group registry for
		// reasons unrelated to drift (e.g. "frodo640aes" matches a
		// generic "FrodoKEM" entry with different granularity).
		info, ok := algorithmRegistry[g.Name]
		if !ok {
			continue
		}
		if info.Status != g.Status {
			t.Errorf("drift: group %s tls_groups=%s vs algorithm-registry=%s",
				g.Name, g.Status, info.Status)
		}
	}
}

func TestTLSGroupRegistry_NameLookup(t *testing.T) {
	// Name-based lookup is used by config-file scanners (nginx ssl_ecdh_curve X25519MLKEM768)
	if _, ok := LookupTLSGroupByName("X25519MLKEM768"); !ok {
		t.Error("expected name lookup for X25519MLKEM768")
	}
	if _, ok := LookupTLSGroupByName("x25519mlkem768"); !ok {
		t.Error("name lookup should be case-insensitive")
	}
}
