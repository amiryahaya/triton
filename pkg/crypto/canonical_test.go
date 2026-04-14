package crypto

import (
	"sort"
	"testing"
)

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
				drifts = append(drifts, drift{name, "TLS group 0x" + hex16(id), string(entry.Status), string(want)})
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
	}

	if len(drifts) == 0 {
		return
	}
	sort.Slice(drifts, func(i, j int) bool { return drifts[i].Name < drifts[j].Name })
	for _, d := range drifts {
		t.Errorf("drift: %s in %s — got Status=%q want=%q", d.Name, d.Where, d.GotStatus, d.WantStatus)
	}
}

func hex16(v uint16) string {
	const h = "0123456789ABCDEF"
	return string([]byte{h[v>>12&0xF], h[v>>8&0xF], h[v>>4&0xF], h[v&0xF]})
}
