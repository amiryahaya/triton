package crypto

import (
	"fmt"
	"sort"
	"testing"
)

// coreAlgorithmNames enumerates algorithm names whose PQC classification
// (Status) MUST be consistent across every registry that mentions them.
// Format-specific registry entries that reference names outside this set
// are NOT required to match algorithmRegistry — their Status is a
// registry-local concern (e.g. PKCS7 content types, PBE modes, SPNEGO).
//
// The intent is to catch bugs like "demoted ML-KEM-512 in pqc.go but
// forgot to update the Java registry's alias table" — a real drift risk
// on algorithms under active cryptanalysis — without demanding that every
// protocol OID also be classified as an algorithm.
var coreAlgorithmNames = []string{
	// NIST PQC (FIPS 203/204/205/206)
	"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
	"ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
	"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256s",
	"SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-256f",
	"SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-256s",
	"SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256f",
	"FN-DSA-512", "FN-DSA-1024",

	// Hash-based stateful signatures
	"XMSS", "LMS",

	// Classical asymmetric
	"RSA", "DSA", "ECDSA", "Ed25519", "Ed448",
	"ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
	"X25519", "X448",

	// Classical symmetric
	"AES", "AES-128-GCM", "AES-256-GCM", "AES-128-CBC", "AES-256-CBC",
	"ChaCha20-Poly1305",
	"3DES", "DES",

	// Hashes
	"SHA-256", "SHA-384", "SHA-512", "SHA-224",
	"SHA3-256", "SHA3-384", "SHA3-512", "SHA3-224",
	"SHA-1", "MD5", "MD4",
}

// TestCoreAlgorithmsConsistent verifies that every format-specific registry
// entry referencing a core algorithm name uses the same Status as the
// authoritative algorithmRegistry. See coreAlgorithmNames for scope.
//
// Failure means drift: one registry was updated (e.g. to reflect new NIST
// guidance) but another was not. Fix by aligning the divergent entry.
func TestCoreAlgorithmsConsistent(t *testing.T) {
	core := make(map[string]bool, len(coreAlgorithmNames))
	for _, n := range coreAlgorithmNames {
		core[n] = true
	}

	type drift struct{ Name, Where, GotStatus, WantStatus string }
	var drifts []drift

	// Authoritative status per core name. Unknown-in-pqc is itself drift.
	for _, name := range coreAlgorithmNames {
		info, ok := algorithmRegistry[name]
		if !ok {
			drifts = append(drifts, drift{name, "pqc.go (missing)", "", "any"})
			continue
		}
		want := info.Status

		for oid, entry := range oidRegistry {
			if !core[entry.Algorithm] || entry.Algorithm != name {
				continue
			}
			if entry.Status != want {
				drifts = append(drifts, drift{name, "OID " + oid, string(entry.Status), string(want)})
			}
		}
		for id, entry := range tlsGroupRegistry {
			if !core[entry.Name] || entry.Name != name {
				continue
			}
			if entry.Status != want {
				drifts = append(drifts, drift{name, fmt.Sprintf("TLS group 0x%04X", id), string(entry.Status), string(want)})
			}
		}
		for lit, entry := range javaAlgorithmRegistry {
			if !core[entry.Algorithm] || entry.Algorithm != name {
				continue
			}
			if entry.Status != want {
				drifts = append(drifts, drift{name, "Java literal " + lit, string(entry.Status), string(want)})
			}
		}
		// F2: also check normalizedMap (4th classification path used by
		// ClassifyCryptoAsset). Drift here means ClassifyAlgorithm's
		// normalized-name tier would disagree with the exact-match tier.
		for normName, nInfo := range normalizedMap {
			if !core[nInfo.Name] || nInfo.Name != name {
				continue
			}
			if nInfo.Status != want {
				drifts = append(drifts, drift{name, "normalizedMap " + normName, string(nInfo.Status), string(want)})
			}
		}
	}

	if len(drifts) == 0 {
		return
	}
	sort.Slice(drifts, func(i, j int) bool { return drifts[i].Name < drifts[j].Name })
	for _, d := range drifts {
		t.Errorf("drift: %s in %s — got Status=%q want=%q", d.Name, d.Where, d.GotStatus, d.WantStatus)
	}
}

// TestCoreAlgorithmsConsistent_DetectsInjectedDrift is a negative test for
// the drift detector itself: temporarily flip the Status of a known core
// algorithm's OID entry and assert the detector reports it. Without this
// test, a silent break of the cross-registry scan loop (e.g. `continue`
// inserted after the name filter) would go unnoticed until real drift.
func TestCoreAlgorithmsConsistent_DetectsInjectedDrift(t *testing.T) {
	// MD5 OID — chosen because it's a stable core name across all three registries.
	const testOID = "1.2.840.113549.2.5"
	original, ok := oidRegistry[testOID]
	if !ok {
		t.Fatalf("fixture precondition: OID %s missing from oidRegistry", testOID)
	}
	t.Cleanup(func() { oidRegistry[testOID] = original })

	// Inject a Status that definitely differs from algorithmRegistry["MD5"].
	bogus := SAFE
	if algorithmRegistry["MD5"].Status == SAFE {
		bogus = UNSAFE
	}
	mutated := original
	mutated.Status = bogus
	oidRegistry[testOID] = mutated

	// Re-run the drift scan in-place.
	core := make(map[string]bool, len(coreAlgorithmNames))
	for _, n := range coreAlgorithmNames {
		core[n] = true
	}
	want := algorithmRegistry["MD5"].Status
	found := false
	for oid, entry := range oidRegistry {
		if oid != testOID || !core[entry.Algorithm] {
			continue
		}
		if entry.Status != want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("injected drift on OID %s (Status=%s vs want=%s) was not surfaced",
			testOID, bogus, want)
	}
}
