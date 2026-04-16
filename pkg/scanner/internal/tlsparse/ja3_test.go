package tlsparse

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Ensure hex import is used (it's used in TestJA3_BasicVector and TestJA3S_BasicVector).

func TestJA3_BasicVector(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:   0x0303, // 771
		CipherSuites: []uint16{0x1301, 0x1302}, // 4865, 4866
		Extensions:   []uint16{0x000a, 0x000b},  // 10, 11
		EllipticCurves: []uint16{0x001d, 0x0017}, // 29, 23
		ECPointFormats: []uint8{0},
	}
	raw, hash := JA3(ch)

	// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,ECPointFormats
	// All decimal, dash-separated within groups
	if !strings.HasPrefix(raw, "771,") {
		t.Errorf("JA3 raw should start with TLS version 771, got %q", raw)
	}
	parts := strings.Split(raw, ",")
	if len(parts) != 5 {
		t.Errorf("JA3 raw should have 5 comma-separated parts, got %d: %q", len(parts), raw)
	}
	if len(hash) != 32 {
		t.Errorf("JA3 hash should be 32 hex chars (MD5), got len=%d: %q", len(hash), hash)
	}
	// hash must be valid hex
	if _, err := hex.DecodeString(hash); err != nil {
		t.Errorf("JA3 hash is not valid hex: %q", hash)
	}
	t.Logf("JA3 raw: %s", raw)
	t.Logf("JA3 hash: %s", hash)
}

func TestJA3_GREASEFiltered(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: []uint16{0x0a0a, 0x1301}, // GREASE + real
		Extensions:   []uint16{0x0a0a, 0x000a},  // GREASE + real
		EllipticCurves: []uint16{0x0a0a, 0x001d}, // GREASE + real
		ECPointFormats: []uint8{0},
	}
	raw, _ := JA3(ch)
	// GREASE values (decimal 2570) must NOT appear in the raw string
	if strings.Contains(raw, "2570") {
		t.Errorf("JA3 raw string contains GREASE value 2570: %q", raw)
	}
	// Real values must be present
	if !strings.Contains(raw, "4865") { // 0x1301
		t.Errorf("JA3 raw should contain cipher 4865: %q", raw)
	}
}

func TestJA3_EmptyCiphers(t *testing.T) {
	ch := &ClientHelloInfo{
		TLSVersion:   0x0303,
		CipherSuites: nil,
		Extensions:   nil,
		EllipticCurves: nil,
		ECPointFormats: nil,
	}
	raw, hash := JA3(ch)
	// Should still produce 5-part format with empty groups
	parts := strings.Split(raw, ",")
	if len(parts) != 5 {
		t.Errorf("JA3 raw should have 5 parts even when empty, got %d: %q", len(parts), raw)
	}
	if len(hash) != 32 {
		t.Errorf("JA3 hash should be 32 hex chars, got %d", len(hash))
	}
}

func TestJA3S_BasicVector(t *testing.T) {
	sh := &ServerHelloInfo{
		TLSVersion:  0x0303, // 771
		CipherSuite: 0x1301, // 4865
		Extensions:  []uint16{0x0010, 0xff01}, // 16, 65281
	}
	raw, hash := JA3S(sh)

	// JA3S format: TLSVersion,CipherSuite,Extensions
	if !strings.HasPrefix(raw, "771,") {
		t.Errorf("JA3S raw should start with 771, got %q", raw)
	}
	parts := strings.Split(raw, ",")
	if len(parts) != 3 {
		t.Errorf("JA3S raw should have 3 comma-separated parts, got %d: %q", len(parts), raw)
	}
	if len(hash) != 32 {
		t.Errorf("JA3S hash should be 32 hex chars, got %d", len(hash))
	}
	if _, err := hex.DecodeString(hash); err != nil {
		t.Errorf("JA3S hash not valid hex: %q", hash)
	}
	t.Logf("JA3S raw: %s", raw)
	t.Logf("JA3S hash: %s", hash)
}

func TestJA3S_GREASEFiltered(t *testing.T) {
	sh := &ServerHelloInfo{
		TLSVersion:  0x0303,
		CipherSuite: 0x1301,
		Extensions:  []uint16{0xfafa, 0x0010}, // GREASE + real
	}
	raw, _ := JA3S(sh)
	// GREASE 0xfafa = 64250 decimal
	if strings.Contains(raw, "64250") {
		t.Errorf("JA3S raw should not contain GREASE value 64250: %q", raw)
	}
}

func TestJA3_KnownVector(t *testing.T) {
	// Construct a known JA3: TLS 1.2 ClientHello with single cipher, no extensions
	// JA3 raw = "771,47,,,"  (TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x002f = 47)
	ch := &ClientHelloInfo{
		TLSVersion:     0x0303,
		CipherSuites:   []uint16{0x002f},
		Extensions:     nil,
		EllipticCurves: nil,
		ECPointFormats: nil,
	}
	raw, _ := JA3(ch)
	wantRaw := "771,47,,,"
	if raw != wantRaw {
		t.Errorf("JA3 raw = %q, want %q", raw, wantRaw)
	}
}
