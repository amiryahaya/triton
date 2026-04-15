package crypto

import (
	"strconv"
	"strings"
)

// TPMFirmwareCVE describes a known-vulnerable TPM firmware range.
// MinVersion / MaxVersion are inclusive bounds; empty string means "any".
// Version comparison uses dotted-integer semantics for vendors with
// well-documented version schemes; for other vendors, MinVersion must
// equal the firmware string exactly.
type TPMFirmwareCVE struct {
	Vendor      string
	CVE         string
	MinVersion  string
	MaxVersion  string
	Description string
	Severity    string // CRITICAL | HIGH | MEDIUM
}

// tpmFirmwareCVEs is the committed registry of known vulnerabilities.
var tpmFirmwareCVEs = []TPMFirmwareCVE{
	{
		Vendor:      "Infineon",
		CVE:         "CVE-2017-15361",
		MinVersion:  "",
		MaxVersion:  "4.33.4",
		Description: "ROCA — weak prime generation in Infineon RSA library",
		Severity:    "CRITICAL",
	},
	{
		Vendor:      "Intel",
		CVE:         "CVE-2017-5689",
		MinVersion:  "",
		MaxVersion:  "11.6",
		Description: "Intel ME / AMT authentication bypass (adjacent to Intel PTT firmware TPM)",
		Severity:    "HIGH",
	},
	{
		Vendor:      "STMicroelectronics",
		CVE:         "CVE-2019-16863",
		MinVersion:  "73.04",
		MaxVersion:  "73.04",
		Description: "ECDSA nonce bias in ST33 family TPM",
		Severity:    "HIGH",
	},
}

// rangeComparableVendors lists vendors whose firmware versions use dotted
// integers and can therefore be range-compared. Other vendors fall back
// to exact-match against the MinVersion field.
var rangeComparableVendors = map[string]bool{
	"Infineon": true,
	"Intel":    true,
}

// LookupTPMFirmwareCVEs returns every CVE in the registry whose vendor
// and firmware-version range matches the inputs.
func LookupTPMFirmwareCVEs(vendor, firmwareVersion string) []TPMFirmwareCVE {
	if vendor == "" || firmwareVersion == "" {
		return nil
	}
	out := []TPMFirmwareCVE{}
	for _, cve := range tpmFirmwareCVEs {
		if cve.Vendor != vendor {
			continue
		}
		if !versionInRange(vendor, firmwareVersion, cve.MinVersion, cve.MaxVersion) {
			continue
		}
		out = append(out, cve)
	}
	return out
}

// versionInRange returns true if firmwareVersion is within [min, max]
// (inclusive; empty bound = open-ended). For range-comparable vendors,
// uses compareVersion; otherwise requires firmwareVersion == min.
func versionInRange(vendor, firmwareVersion, minV, maxV string) bool {
	if !rangeComparableVendors[vendor] {
		// Non-range vendors: exact match against MinVersion only.
		return minV != "" && firmwareVersion == minV
	}
	if minV != "" {
		cmp := compareVersion(firmwareVersion, minV)
		if cmp == -2 || cmp < 0 {
			return false
		}
	}
	if maxV != "" {
		cmp := compareVersion(firmwareVersion, maxV)
		if cmp == -2 || cmp > 0 {
			return false
		}
	}
	return true
}

// compareVersion compares two dotted-integer version strings.
// Returns -1 if a < b, 0 if equal, 1 if a > b, -2 if either string contains
// a non-numeric segment (treated as incomparable).
// Missing components are treated as 0 (so "4.33" < "4.33.4").
func compareVersion(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai := 0
		if i < len(as) {
			v, err := strconv.Atoi(as[i])
			if err != nil {
				return -2
			}
			ai = v
		}
		bi := 0
		if i < len(bs) {
			v, err := strconv.Atoi(bs[i])
			if err != nil {
				return -2
			}
			bi = v
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}
