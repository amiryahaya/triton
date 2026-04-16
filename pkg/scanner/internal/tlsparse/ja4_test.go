package tlsparse

import (
	"strings"
	"testing"
)

func TestJA4_Structure(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x1301, 0x1302, 0xc02b},
		Extensions:   []uint16{0x0000, 0x000a, 0x000b, 0x0010},
		SNI:          "example.com",
		ALPNProtocols: []string{"h2"},
	}
	fp := JA4(ch)

	// Must start with "t" (TLS, not QUIC)
	if !strings.HasPrefix(fp, "t") {
		t.Errorf("JA4 must start with 't', got %q", fp)
	}
	// Must contain exactly 3 underscores (4 parts)
	parts := strings.Split(fp, "_")
	if len(parts) != 4 {
		t.Errorf("JA4 must have 4 underscore-separated parts, got %d: %q", len(parts), fp)
	}
	// First part: t + version(2) + d/i + cipherCount(02d) + extCount(02d) — length 8
	if len(parts[0]) != 8 {
		t.Errorf("JA4 part[0] len = %d, want 8: %q", len(parts[0]), parts[0])
	}
	// SNI present → 'd' at position 3
	if parts[0][3] != 'd' {
		t.Errorf("JA4 part[0][3] = %c, want 'd' (SNI present)", parts[0][3])
	}
	t.Logf("JA4: %s", fp)
}

func TestJA4_NoSNI(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x000a},
		SNI:          "", // no SNI
	}
	fp := JA4(ch)
	parts := strings.Split(fp, "_")
	if len(parts) != 4 {
		t.Fatalf("JA4 must have 4 parts, got %d: %q", len(parts), fp)
	}
	if parts[0][3] != 'i' {
		t.Errorf("JA4 part[0][3] = %c, want 'i' (no SNI)", parts[0][3])
	}
}

func TestJA4_GREASEFiltered(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x0a0a, 0x1301}, // GREASE + real
		Extensions:   []uint16{0x0a0a, 0x000a},  // GREASE + real
		SNI:          "test.local",
	}
	fp := JA4(ch)
	parts := strings.Split(fp, "_")
	if len(parts) != 4 {
		t.Fatalf("JA4 must have 4 parts, got %d", len(parts))
	}
	// cipher count should be 1 (GREASE excluded), ext count should be 1 (GREASE excluded)
	// part[0] format: t{ver}{d/i}{cc}{ec}
	cipherCount := parts[0][4:6]
	extCount := parts[0][6:8]
	if cipherCount != "01" {
		t.Errorf("JA4 cipher count = %q, want %q", cipherCount, "01")
	}
	if extCount != "01" {
		t.Errorf("JA4 ext count = %q, want %q", extCount, "01")
	}
}

func TestJA4S_Structure(t *testing.T) {
	sh := &ServerHelloInfo{
		TLSVersion:  0x0303,
		CipherSuite: 0x1301,
		Extensions:  []uint16{0x0010, 0xff01},
	}
	fp := JA4S(sh)

	// JA4S format: t{version}{extCount:02d}_{cipherHex}_{sortedExtHash12}
	// 3 underscore-separated parts
	parts := strings.Split(fp, "_")
	if len(parts) != 3 {
		t.Errorf("JA4S must have 3 parts, got %d: %q", len(parts), fp)
	}
	if !strings.HasPrefix(fp, "t") {
		t.Errorf("JA4S must start with 't', got %q", fp)
	}
	// Part[1]: cipher suite as 4-hex-char (zero-padded)
	if len(parts[1]) != 4 {
		t.Errorf("JA4S cipher part len = %d, want 4: %q", len(parts[1]), parts[1])
	}
	// Part[2]: first 12 chars of SHA-256 hash
	if len(parts[2]) != 12 {
		t.Errorf("JA4S ext hash part len = %d, want 12: %q", len(parts[2]), parts[2])
	}
	t.Logf("JA4S: %s", fp)
}

func TestJA4_SortedCiphersAndExtensions(t *testing.T) {
	// Same ciphers/extensions in different order should produce same JA4 hash parts
	ch1 := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x1301, 0x1302, 0xc02b},
		Extensions:   []uint16{0x000a, 0x000b, 0x000d},
		SNI:          "test.local",
	}
	ch2 := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0xc02b, 0x1301, 0x1302}, // different order
		Extensions:   []uint16{0x000d, 0x000a, 0x000b}, // different order
		SNI:          "test.local",
	}
	fp1 := JA4(ch1)
	fp2 := JA4(ch2)

	parts1 := strings.Split(fp1, "_")
	parts2 := strings.Split(fp2, "_")

	// Hash parts (cipher hash and ext hash) should be identical
	if parts1[2] != parts2[2] {
		t.Errorf("JA4 cipher hash differs with reordered ciphers: %q vs %q", parts1[2], parts2[2])
	}
	if parts1[3] != parts2[3] {
		t.Errorf("JA4 ext hash differs with reordered extensions: %q vs %q", parts1[3], parts2[3])
	}
}

func TestJA4_TLS13Detection(t *testing.T) {
	// TLS 1.3 ClientHello: legacy version is 0x0303, but supported_versions extension (0x002b)
	// lists 0x0304 (TLS 1.3). JA4 should detect "13".
	ch := &ClientHelloInfo{
		TLSVersion:   0x0303, // legacy field
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x002b}, // supported_versions
		SNI:          "example.com",
	}
	fp := JA4(ch)
	// version should be "13" (positions 1-2 in part[0])
	parts := strings.Split(fp, "_")
	version := parts[0][1:3]
	if version != "13" {
		t.Errorf("JA4 version = %q, want %q for TLS 1.3 (supported_versions ext present)", version, "13")
	}
}

func TestJA4_ALPNEncoding(t *testing.T) {
	// h2 → "h2", http/1.1 → "h1"
	ch := &ClientHelloInfo{
		TLSVersion:    0x0303,
		CipherSuites:  []uint16{0x1301},
		Extensions:    []uint16{0x0010},
		ALPNProtocols: []string{"h2"},
		SNI:           "example.com",
	}
	fp := JA4(ch)
	parts := strings.Split(fp, "_")
	// part[1] is the ALPN indicator
	if parts[1] != "h2" {
		t.Errorf("JA4 ALPN part = %q, want %q", parts[1], "h2")
	}
}

func TestJA4_ALPNEncoding_HTTP11(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:    0x0303,
		CipherSuites:  []uint16{0x1301},
		Extensions:    []uint16{0x0010},
		ALPNProtocols: []string{"http/1.1"},
		SNI:           "example.com",
	}
	fp := JA4(ch)
	parts := strings.Split(fp, "_")
	if parts[1] != "h1" {
		t.Errorf("JA4 ALPN part for http/1.1 = %q, want %q", parts[1], "h1")
	}
}

func TestJA4_NoALPN(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:    0x0303,
		CipherSuites:  []uint16{0x1301},
		Extensions:    []uint16{0x000a},
		ALPNProtocols: nil,
		SNI:           "example.com",
	}
	fp := JA4(ch)
	parts := strings.Split(fp, "_")
	// no ALPN → "00"
	if parts[1] != "00" {
		t.Errorf("JA4 ALPN part with no ALPN = %q, want %q", parts[1], "00")
	}
}
