package tlsparse

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// JA4 computes the JA4 fingerprint for a ClientHello.
//
// Format: {t|q}{version}{d|i}{cipherCount:02d}{extCount:02d}_{alpn}_{sortedCipherHash12}_{sortedExtHash12}
//
// Rules:
//   - t = TLS (always for us, q = QUIC)
//   - version: two-digit string derived from TLS version (e.g. "13", "12", "10")
//   - d = SNI domain present, i = no SNI / IP
//   - counts are 2-digit zero-padded, capped at 99; GREASE excluded
//   - ALPN: first+last char of first protocol; "00" if no ALPN
//   - Cipher hash: first 12 chars of SHA-256 hex of sorted comma-separated decimal values (GREASE filtered)
//   - Extension hash: first 12 chars of SHA-256 hex of sorted comma-separated decimal values
//     (GREASE filtered, SNI 0x0000 and ALPN 0x0010 excluded from hash)
func JA4(ch *ClientHelloInfo) string {
	// Determine TLS version string
	version := ja4TLSVersion(ch)

	// SNI indicator
	sniChar := byte('i')
	if ch.SNI != "" {
		sniChar = 'd'
	}

	// Filter GREASE from ciphers and extensions
	ciphers := FilterGREASE(ch.CipherSuites)
	exts := FilterGREASE(ch.Extensions)

	// Counts (capped at 99)
	cipherCount := min99(len(ciphers))
	extCount := min99(len(exts))

	// Part 0: t + version(2) + sniChar + cipherCount(02d) + extCount(02d)
	part0 := fmt.Sprintf("t%s%c%02d%02d", version, sniChar, cipherCount, extCount)

	// ALPN: first+last char of first protocol, or "00"
	alpnPart := ja4ALPNCode(ch.ALPNProtocols)

	// Cipher hash: sorted, comma-separated decimal, SHA-256[:12]
	sortedCiphers := sortedUint16Strs(ciphers)
	cipherHash := sha256Prefix12(strings.Join(sortedCiphers, ","))

	// Extension hash: sorted, comma-separated decimal, exclude SNI (0x0000) and ALPN (0x0010)
	filteredExts := filterExtForHash(exts)
	sortedExts := sortedUint16Strs(filteredExts)
	extHash := sha256Prefix12(strings.Join(sortedExts, ","))

	return fmt.Sprintf("%s_%s_%s_%s", part0, alpnPart, cipherHash, extHash)
}

// JA4S computes the JA4S fingerprint for a ServerHello.
//
// Format: {t}{version}{extCount:02d}_{cipherSuiteHex4}_{sortedExtHash12}
func JA4S(sh *ServerHelloInfo) string {
	version := ja4SVersionStr(sh.TLSVersion)

	exts := FilterGREASE(sh.Extensions)
	extCount := min99(len(exts))

	// Part 0: t + version(2) + extCount(02d)
	part0 := fmt.Sprintf("t%s%02d", version, extCount)

	// Part 1: cipher suite as 4-hex-char lowercase
	part1 := fmt.Sprintf("%04x", sh.CipherSuite)

	// Part 2: sorted ext hash (first 12 chars of SHA-256)
	sortedExts := sortedUint16Strs(exts)
	extHash := sha256Prefix12(strings.Join(sortedExts, ","))

	return fmt.Sprintf("%s_%s_%s", part0, part1, extHash)
}

// ja4TLSVersion returns the 2-char TLS version string for JA4 part[0].
// If supported_versions extension (0x002b) is present, version is "13".
func ja4TLSVersion(ch *ClientHelloInfo) string {
	for _, ext := range ch.Extensions {
		if ext == 0x002b {
			return "13"
		}
	}
	return tlsVersionStr(ch.TLSVersion)
}

// ja4SVersionStr converts a TLS version uint16 to a 2-char string.
func ja4SVersionStr(v uint16) string {
	return tlsVersionStr(v)
}

// tlsVersionStr converts TLS version to 2-char decimal string.
func tlsVersionStr(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return fmt.Sprintf("%02x", v&0xff)
	}
}

// ja4ALPNCode returns the 2-char ALPN code: first+last char of first protocol, or "00".
func ja4ALPNCode(protos []string) string {
	if len(protos) == 0 {
		return "00"
	}
	p := protos[0]
	if p == "" {
		return "00"
	}
	if len(p) == 1 {
		return string([]byte{p[0], p[0]})
	}
	return string([]byte{p[0], p[len(p)-1]})
}

// filterExtForHash removes SNI (0x0000) and ALPN (0x0010) from the extension list
// before hashing (per JA4 spec).
func filterExtForHash(exts []uint16) []uint16 {
	out := make([]uint16, 0, len(exts))
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 {
			out = append(out, e)
		}
	}
	return out
}

// sortedUint16Strs returns sorted decimal string representations of the values.
func sortedUint16Strs(vals []uint16) []string {
	sorted := make([]uint16, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	strs := make([]string, len(sorted))
	for i, v := range sorted {
		strs[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strs
}

// sha256Prefix12 returns the first 12 chars of the lowercase SHA-256 hex digest.
func sha256Prefix12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)[:12]
}

// min99 returns n capped at 99.
func min99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}
