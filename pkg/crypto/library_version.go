package crypto

import (
	"strconv"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

// libKeyMapping maps filename prefixes to canonical library keys.
// Order matters: longer prefixes first to avoid premature matching.
var libKeyMapping = []struct {
	prefix string
	key    string
}{
	{"libmbedcrypto", "mbedtls"},
	{"libmbedtls", "mbedtls"},
	{"mbedtls", "mbedtls"},
	{"libcrypto", "openssl"},
	{"libssl", "openssl"},
	{"openssl", "openssl"},
	{"libwolfssl", "wolfssl"},
	{"wolfssl", "wolfssl"},
	{"libgnutls", "gnutls"},
	{"gnutls", "gnutls"},
	{"libnss", "nss"},
	{"nss", "nss"},
	{"libgcrypt", "libgcrypt"},
	{"libsodium", "libsodium"},
	{"libnettle", "nettle"},
	{"nettle", "nettle"},
	{"libboringssl", "boringssl"},
	{"boringssl", "boringssl"},
	{"openssh", "openssh"},
	{"gnupg", "gnupg"},
	{"gpg", "gnupg"},
	{"libressl", "libressl"},
}

// versionRule defines the minimum version that is NOT deprecated.
// Versions below minMajor.minMinor are classified as DEPRECATED.
// Versions at or above the threshold get upgradeStatus.
type versionRule struct {
	minMajor      int       // minimum non-deprecated major version
	minMinor      int       // minimum non-deprecated minor version (when major == minMajor)
	upgradeStatus PQCStatus // status for versions at or above threshold
}

// libraryRules maps canonical library keys to their version classification rules.
var libraryRules = map[string]versionRule{
	"openssl":   {minMajor: 1, minMinor: 1, upgradeStatus: TRANSITIONAL},
	"gnutls":    {minMajor: 3, minMinor: 6, upgradeStatus: TRANSITIONAL},
	"mbedtls":   {minMajor: 2, minMinor: 0, upgradeStatus: TRANSITIONAL},
	"wolfssl":   {minMajor: 4, minMinor: 0, upgradeStatus: TRANSITIONAL},
	"nss":       {minMajor: 3, minMinor: 44, upgradeStatus: TRANSITIONAL},
	"libgcrypt": {minMajor: 1, minMinor: 8, upgradeStatus: TRANSITIONAL},
	"nettle":    {minMajor: 3, minMinor: 4, upgradeStatus: TRANSITIONAL},
	"boringssl": {minMajor: 0, minMinor: 0, upgradeStatus: TRANSITIONAL}, // no semver; always current
	"openssh":   {minMajor: 7, minMinor: 0, upgradeStatus: TRANSITIONAL},
	"gnupg":     {minMajor: 2, minMinor: 0, upgradeStatus: TRANSITIONAL},
	"libressl":  {minMajor: 3, minMinor: 0, upgradeStatus: TRANSITIONAL},
}

// alwaysSafeLibs are libraries that use modern-only algorithms by design.
var alwaysSafeLibs = map[string]bool{
	"libsodium": true,
}

// normalizeLibKey maps a library name (filename or package name) to a canonical key.
func normalizeLibKey(name string) string {
	lower := strings.ToLower(name)
	for _, m := range libKeyMapping {
		if strings.HasPrefix(lower, m.prefix) {
			return m.key
		}
	}
	return ""
}

// stripNonDigits removes leading/trailing non-digit characters from a version component.
const alphaChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// parseVersion extracts major and minor version numbers from a version string.
// Handles common formats: "3.0.2", "1.1.1k", "v3.6.0", "1.0.2u".
// Returns (major, minor, true) on success or (0, 0, false) if unparseable.
func parseVersion(version string) (major, minor int, ok bool) {
	if version == "" {
		return 0, 0, false
	}

	// Strip leading v/V prefix (common in git tags and Go modules)
	version = strings.TrimLeft(version, "vV")
	if version == "" {
		return 0, 0, false
	}

	parts := strings.SplitN(version, ".", 3)

	// Strip trailing alpha from major component
	majStr := strings.TrimRight(parts[0], alphaChars)
	if majStr == "" {
		return 0, 0, false
	}
	maj, err := strconv.Atoi(majStr)
	if err != nil {
		return 0, 0, false
	}
	if maj < 0 {
		return 0, 0, false
	}

	minor = 0
	if len(parts) >= 2 {
		// Strip trailing alpha characters (e.g., "1k" from "1.1.1k")
		minStr := strings.TrimRight(parts[1], alphaChars)
		if minStr != "" {
			minor, err = strconv.Atoi(minStr)
			if err != nil {
				return maj, 0, true // major parsed, minor unparseable — still usable
			}
			if minor < 0 {
				return maj, 0, true
			}
		}
	}

	return maj, minor, true
}

// ClassifyLibraryAsset sets PQCStatus and NACSALabel on a CryptoAsset based on the
// library identity and version. This replaces the hardcoded TRANSITIONAL for library
// and package scanner findings.
func ClassifyLibraryAsset(asset *model.CryptoAsset, libName, version string) {
	if asset == nil {
		return
	}

	key := normalizeLibKey(libName)

	// Always-safe libraries (e.g., libsodium — modern-only crypto by design)
	if alwaysSafeLibs[key] {
		asset.PQCStatus = string(SAFE)
		asset.NACSALabel = string(NACSAPatuh)
		return
	}

	// Unknown library → conservative TRANSITIONAL
	if key == "" {
		asset.PQCStatus = string(TRANSITIONAL)
		asset.NACSALabel = string(NACSAPeralihan)
		return
	}

	rule, hasRule := libraryRules[key]
	if !hasRule {
		asset.PQCStatus = string(TRANSITIONAL)
		asset.NACSALabel = string(NACSAPeralihan)
		return
	}

	major, minor, ok := parseVersion(version)
	if !ok {
		// No parseable version → conservative TRANSITIONAL
		asset.PQCStatus = string(TRANSITIONAL)
		asset.NACSALabel = string(NACSAPeralihan)
		return
	}

	if major < rule.minMajor || (major == rule.minMajor && minor < rule.minMinor) {
		asset.PQCStatus = string(DEPRECATED)
		asset.NACSALabel = string(NACSATidakPatuh)
		return
	}

	asset.PQCStatus = string(rule.upgradeStatus)
	nacsa := nacsaLabelForStatus(rule.upgradeStatus)
	asset.NACSALabel = string(nacsa)
}

// nacsaLabelForStatus returns the NACSA label corresponding to a PQC status.
// Note: for SAFE, this returns NACSAPeralihan (not NACSAPatuh) because CNSA 2.0
// approval cannot be determined from version alone. Use AssessNACSA for full checks.
func nacsaLabelForStatus(status PQCStatus) NACSALabel {
	switch status {
	case SAFE:
		return NACSAPeralihan // conservative: CNSA 2.0 not checked at library level
	case TRANSITIONAL:
		return NACSAPeralihan
	case DEPRECATED:
		return NACSATidakPatuh
	case UNSAFE:
		return NACSATindakanSegera
	default:
		return NACSAPeralihan
	}
}
