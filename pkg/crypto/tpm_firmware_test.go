package crypto

import "testing"

func TestLookupTPMFirmwareCVEs_InfineonROCA(t *testing.T) {
	// Infineon firmware ≤ 4.33.4 → CVE-2017-15361 fires.
	cases := []struct {
		version string
		wantFP  bool // should fire?
	}{
		{"4.32.1.2", true},
		{"4.33.0", true},
		{"4.33.4", true},
		{"4.34.0", false},
		{"5.0.0", false},
	}
	for _, c := range cases {
		cves := LookupTPMFirmwareCVEs("Infineon", c.version)
		found := false
		for _, cve := range cves {
			if cve.CVE == "CVE-2017-15361" {
				found = true
				break
			}
		}
		if found != c.wantFP {
			t.Errorf("version=%q: ROCA CVE found=%v, want %v", c.version, found, c.wantFP)
		}
	}
}

func TestLookupTPMFirmwareCVEs_TCGLibBugs(t *testing.T) {
	// TPM 2.0 library ≤ 1.59 → CVE-2023-1017 and CVE-2023-1018 fire for any vendor.
	cves := LookupTPMFirmwareCVEs("Infineon", "4.40.0")
	// Firmware 4.40.0 is past ROCA, but TCG library bugs still fire IF firmware
	// implements the affected library version. For PR #1 we're conservative:
	// TCG-lib CVEs are only registered when we know the firmware ships that
	// library version, which we don't generically — so they should NOT fire
	// just based on vendor+version here. Expect empty.
	for _, c := range cves {
		if c.CVE == "CVE-2023-1017" || c.CVE == "CVE-2023-1018" {
			t.Errorf("TCG lib CVE fired without library-version context: %s", c.CVE)
		}
	}
}

func TestLookupTPMFirmwareCVEs_UnknownVendorNoCVEs(t *testing.T) {
	cves := LookupTPMFirmwareCVEs("SomeRandomVendor", "1.2.3")
	if len(cves) != 0 {
		t.Errorf("unknown vendor returned %d CVEs, want 0", len(cves))
	}
}

func TestLookupTPMFirmwareCVEs_FreshInfineonClean(t *testing.T) {
	cves := LookupTPMFirmwareCVEs("Infineon", "5.0.0")
	if len(cves) != 0 {
		t.Errorf("fresh Infineon firmware returned %d CVEs, want 0", len(cves))
	}
}

func TestCompareVersion_DottedIntegers(t *testing.T) {
	cases := []struct {
		a, b string
		want int // -1 if a<b, 0 if equal, 1 if a>b
	}{
		{"4.32.1.2", "4.33.0", -1},
		{"4.33.4", "4.33.4", 0},
		{"4.33.5", "4.33.4", 1},
		{"5.0", "4.99.99", 1},
		{"4.33", "4.33.4", -1}, // shorter version is "less" when missing components
	}
	for _, c := range cases {
		got := compareVersion(c.a, c.b)
		if got != c.want {
			t.Errorf("compareVersion(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
