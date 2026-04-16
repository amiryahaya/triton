package tlsparse

import (
	"crypto/md5" //nolint:gosec // JA3 spec requires MD5
	"fmt"
	"strconv"
	"strings"
)

// JA3 computes the JA3 fingerprint for a ClientHello.
// Returns the raw string and its MD5 hex hash.
//
// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
// All values decimal, dash-separated within groups, GREASE-filtered.
func JA3(ch *ClientHelloInfo) (raw, hash string) {
	ciphers := FilterGREASE(ch.CipherSuites)
	exts := FilterGREASE(ch.Extensions)
	curves := FilterGREASE(ch.EllipticCurves)

	raw = fmt.Sprintf("%d,%s,%s,%s,%s",
		ch.TLSVersion,
		joinUint16(ciphers),
		joinUint16(exts),
		joinUint16(curves),
		joinUint8(ch.ECPointFormats, "-"),
	)

	sum := md5.Sum([]byte(raw)) //nolint:gosec // JA3 spec requires MD5
	hash = fmt.Sprintf("%x", sum)
	return raw, hash
}

// JA3S computes the JA3S fingerprint for a ServerHello.
// Returns the raw string and its MD5 hex hash.
//
// Format: TLSVersion,CipherSuite,Extensions
func JA3S(sh *ServerHelloInfo) (raw, hash string) {
	exts := FilterGREASE(sh.Extensions)

	raw = fmt.Sprintf("%d,%d,%s",
		sh.TLSVersion,
		sh.CipherSuite,
		joinUint16(exts),
	)

	sum := md5.Sum([]byte(raw)) //nolint:gosec // JA3 spec requires MD5
	hash = fmt.Sprintf("%x", sum)
	return raw, hash
}

// joinUint16 converts a slice of uint16 to a "-"-joined decimal string.
func joinUint16(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, "-")
}

// joinUint8 converts a slice of uint8 to a "-"-joined decimal string.
func joinUint8(vals []uint8, sep string) string {
	if len(vals) == 0 {
		return ""
	}
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, sep)
}
