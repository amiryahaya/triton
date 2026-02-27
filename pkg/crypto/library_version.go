package crypto

import (
	"strconv"
	"strings"

	"github.com/amiryahaya/triton/pkg/model"
)

// libKeyMapping maps filename prefixes to canonical library keys.
var libKeyMapping = []struct {
	prefix string
	key    string
}{
	// Order matters: longer prefixes first to avoid premature matching.
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

// versionRule defines the version threshold at which a library transitions from DEPRECATED.
type versionRule struct {
	// Library with major < deprecatedBelow.major is DEPRECATED.
	// Library with major == deprecatedBelow.major and minor < deprecatedBelow.minor is DEPRECATED.
	// Otherwise it gets the upgradeStatus.
	deprecatedMajor int
	deprecatedMinor int
	upgradeStatus   PQCStatus
}

// libraryRules maps canonical library keys to their version classification rules.
var libraryRules = map[string]versionRule{
	"openssl":   {deprecatedMajor: 1, deprecatedMinor: 1, upgradeStatus: TRANSITIONAL},
	"gnutls":    {deprecatedMajor: 3, deprecatedMinor: 6, upgradeStatus: TRANSITIONAL},
	"mbedtls":   {deprecatedMajor: 2, deprecatedMinor: 0, upgradeStatus: TRANSITIONAL},
	"wolfssl":   {deprecatedMajor: 4, deprecatedMinor: 0, upgradeStatus: TRANSITIONAL},
	"nss":       {deprecatedMajor: 3, deprecatedMinor: 44, upgradeStatus: TRANSITIONAL},
	"libgcrypt": {deprecatedMajor: 1, deprecatedMinor: 8, upgradeStatus: TRANSITIONAL},
	"nettle":    {deprecatedMajor: 3, deprecatedMinor: 4, upgradeStatus: TRANSITIONAL},
	"boringssl": {deprecatedMajor: 0, deprecatedMinor: 0, upgradeStatus: TRANSITIONAL}, // always current
	"openssh":   {deprecatedMajor: 7, deprecatedMinor: 0, upgradeStatus: TRANSITIONAL},
	"gnupg":     {deprecatedMajor: 2, deprecatedMinor: 0, upgradeStatus: TRANSITIONAL},
	"libressl":  {deprecatedMajor: 3, deprecatedMinor: 0, upgradeStatus: TRANSITIONAL},
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

// parseVersion extracts major and minor version numbers from a version string.
// Returns (major, minor, true) on success or (0, 0, false) if unparseable.
func parseVersion(version string) (major, minor int, ok bool) {
	if version == "" {
		return 0, 0, false
	}

	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 1 {
		return 0, 0, false
	}

	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}

	min := 0
	if len(parts) >= 2 {
		// Strip trailing non-digit characters (e.g., "1k" from "1.1.1k")
		minStr := strings.TrimRight(parts[1], "abcdefghijklmnopqrstuvwxyz")
		if minStr != "" {
			min, err = strconv.Atoi(minStr)
			if err != nil {
				return maj, 0, true // major parsed, minor unparseable — still usable
			}
		}
	}

	return maj, min, true
}

// ClassifyLibraryAsset sets PQCStatus and NACSALabel on a CryptoAsset based on the
// library identity and version. This replaces the hardcoded TRANSITIONAL for library
// and package scanner findings.
func ClassifyLibraryAsset(asset *model.CryptoAsset, libName, version string) {
	key := normalizeLibKey(libName)

	// Always-safe libraries (e.g., libsodium)
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

	if major < rule.deprecatedMajor || (major == rule.deprecatedMajor && minor < rule.deprecatedMinor) {
		asset.PQCStatus = string(DEPRECATED)
		asset.NACSALabel = string(NACSATidakPatuh)
		return
	}

	asset.PQCStatus = string(rule.upgradeStatus)
	nacsa := nacsaLabelForStatus(rule.upgradeStatus)
	asset.NACSALabel = string(nacsa)
}

// nacsaLabelForStatus returns the NACSA label corresponding to a PQC status.
func nacsaLabelForStatus(status PQCStatus) NACSALabel {
	switch status {
	case SAFE:
		return NACSAPatuh
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
