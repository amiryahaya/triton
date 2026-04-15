//go:build linux

package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/crypto"
)

func TestWorstSeverity(t *testing.T) {
	cases := []struct {
		name       string
		cves       []crypto.TPMFirmwareCVE
		wantStatus string
	}{
		{"empty", nil, "SAFE"},
		{"medium only", []crypto.TPMFirmwareCVE{{Severity: "MEDIUM"}}, "TRANSITIONAL"},
		{"high only", []crypto.TPMFirmwareCVE{{Severity: "HIGH"}}, "DEPRECATED"},
		{"critical only", []crypto.TPMFirmwareCVE{{Severity: "CRITICAL"}}, "UNSAFE"},
		{"medium then critical", []crypto.TPMFirmwareCVE{{Severity: "MEDIUM"}, {Severity: "CRITICAL"}}, "UNSAFE"},
		{"critical then medium", []crypto.TPMFirmwareCVE{{Severity: "CRITICAL"}, {Severity: "MEDIUM"}}, "UNSAFE"},
		{"unknown severity ignored", []crypto.TPMFirmwareCVE{{Severity: "BOGUS"}}, "SAFE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotStatus := worstSeverity(c.cves)
			if gotStatus != c.wantStatus {
				t.Errorf("status = %q, want %q", gotStatus, c.wantStatus)
			}
		})
	}
}
