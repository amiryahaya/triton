package crypto

import "testing"

func TestLookupMissingRevocations_AllPresent(t *testing.T) {
	// Build a set containing every hash in the registry.
	all := map[string]bool{}
	for _, r := range uefiRevocationRegistry {
		all[r.SHA256Hex] = true
	}
	missing := LookupMissingRevocations(all)
	if len(missing) != 0 {
		t.Errorf("all-present returned %d missing, want 0", len(missing))
	}
}

func TestLookupMissingRevocations_NonePresent(t *testing.T) {
	missing := LookupMissingRevocations(map[string]bool{})
	if len(missing) != len(uefiRevocationRegistry) {
		t.Errorf("none-present returned %d, want %d", len(missing), len(uefiRevocationRegistry))
	}
	// Verify the three known CVEs are present.
	cves := map[string]bool{}
	for _, r := range missing {
		cves[r.CVE] = true
	}
	for _, want := range []string{"CVE-2023-24932", "CVE-2020-10713", "CVE-2022-21894"} {
		if !cves[want] {
			t.Errorf("missing CVE %s not in results", want)
		}
	}
}

func TestLookupMissingRevocations_PartialPresence(t *testing.T) {
	// Include only the first hash → the other two should be missing.
	partial := map[string]bool{
		uefiRevocationRegistry[0].SHA256Hex: true,
	}
	missing := LookupMissingRevocations(partial)
	if len(missing) != len(uefiRevocationRegistry)-1 {
		t.Errorf("got %d missing, want %d", len(missing), len(uefiRevocationRegistry)-1)
	}
}

func TestUEFIRevocationRegistry_HashesAre64Hex(t *testing.T) {
	for _, r := range uefiRevocationRegistry {
		if len(r.SHA256Hex) != 64 {
			t.Errorf("CVE %s hash len = %d, want 64", r.CVE, len(r.SHA256Hex))
		}
		for _, c := range r.SHA256Hex {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Errorf("CVE %s hash has non-lowercase-hex char %c", r.CVE, c)
			}
		}
	}
}
