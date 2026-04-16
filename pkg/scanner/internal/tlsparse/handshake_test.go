package tlsparse

import (
	"encoding/binary"
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// helpers to build raw TLS records / handshake messages
// ---------------------------------------------------------------------------

// putU8 appends a single byte.
func putU8(b []byte, v uint8) []byte { return append(b, v) }

// putU16BE appends a big-endian uint16.
func putU16BE(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// putU24BE appends a big-endian uint24 (used for handshake length).
func putU24BE(b []byte, v uint32) []byte {
	return append(b, byte(v>>16), byte(v>>8), byte(v))
}

// lenPrefixed16 wraps body with a 2-byte length prefix.
func lenPrefixed16(body []byte) []byte {
	out := putU16BE(nil, uint16(len(body)))
	return append(out, body...)
}

// buildExtension builds a single TLS extension: type(2) + length(2) + data.
func buildExtension(extType uint16, data []byte) []byte {
	var b []byte
	b = putU16BE(b, extType)
	b = append(b, lenPrefixed16(data)...)
	return b
}

// buildSNIExtension builds the SNI extension (type 0x0000).
func buildSNIExtension(hostname string) []byte {
	// server_name_list: list_length(2) + name_type(1) + name_length(2) + name
	var name []byte
	name = putU8(name, 0) // host_name type
	name = append(name, lenPrefixed16([]byte(hostname))...)
	listBody := lenPrefixed16(name)
	return buildExtension(0x0000, listBody)
}

// buildSupportedGroupsExtension builds supported_groups (type 0x000a).
func buildSupportedGroupsExtension(curves []uint16) []byte {
	var list []byte
	for _, c := range curves {
		list = putU16BE(list, c)
	}
	data := lenPrefixed16(list)
	return buildExtension(0x000a, data)
}

// buildECPointFormatsExtension builds ec_point_formats (type 0x000b).
func buildECPointFormatsExtension(formats []uint8) []byte {
	var data []byte
	data = putU8(data, uint8(len(formats)))
	data = append(data, formats...)
	return buildExtension(0x000b, data)
}

// buildSignatureAlgorithmsExtension builds signature_algorithms (type 0x000d).
func buildSignatureAlgorithmsExtension(schemes []uint16) []byte {
	var list []byte
	for _, s := range schemes {
		list = putU16BE(list, s)
	}
	data := lenPrefixed16(list)
	return buildExtension(0x000d, data)
}

// buildALPNExtension builds the ALPN extension (type 0x0010).
func buildALPNExtension(protocols []string) []byte {
	var protoList []byte
	for _, p := range protocols {
		protoList = putU8(protoList, uint8(len(p)))
		protoList = append(protoList, []byte(p)...)
	}
	data := lenPrefixed16(protoList)
	return buildExtension(0x0010, data)
}

// buildClientHello assembles a raw ClientHello starting at the handshake type byte.
func buildClientHello(version uint16, ciphers []uint16, exts []byte) []byte {
	var body []byte
	// version
	body = putU16BE(body, version)
	// random (32 bytes)
	body = append(body, make([]byte, 32)...)
	// session_id (1-byte length = 0)
	body = putU8(body, 0)
	// cipher_suites: 2-byte length + 2 bytes per suite
	var csBytes []byte
	for _, c := range ciphers {
		csBytes = putU16BE(csBytes, c)
	}
	body = append(body, lenPrefixed16(csBytes)...)
	// compression_methods: 1 byte length + 1 byte (null)
	body = putU8(body, 1)
	body = putU8(body, 0)
	// extensions (optional)
	if len(exts) > 0 {
		body = append(body, lenPrefixed16(exts)...)
	}

	// Wrap in handshake header: type(1) + length(3)
	var msg []byte
	msg = putU8(msg, 0x01) // ClientHello
	msg = putU24BE(msg, uint32(len(body)))
	msg = append(msg, body...)
	return msg
}

// buildServerHello assembles a raw ServerHello starting at the handshake type byte.
func buildServerHello(version uint16, cipher uint16, exts []byte) []byte {
	var body []byte
	body = putU16BE(body, version)
	body = append(body, make([]byte, 32)...) // random
	body = putU8(body, 0)                    // session_id len
	body = putU16BE(body, cipher)            // selected cipher
	body = putU8(body, 0)                    // compression (null)
	if len(exts) > 0 {
		body = append(body, lenPrefixed16(exts)...)
	}

	var msg []byte
	msg = putU8(msg, 0x02) // ServerHello
	msg = putU24BE(msg, uint32(len(body)))
	msg = append(msg, body...)
	return msg
}

// buildTLSRecord wraps a handshake message in a TLS record header.
func buildTLSRecord(handshake []byte) []byte {
	var rec []byte
	rec = putU8(rec, 0x16)      // content_type: handshake
	rec = putU16BE(rec, 0x0303) // version TLS 1.2
	rec = append(rec, lenPrefixed16(handshake)...)
	return rec
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestParseClientHello_Minimal(t *testing.T) {
	msg := buildClientHello(0x0303, []uint16{0x1301}, nil)
	ch, err := ParseClientHello(msg)
	if err != nil {
		t.Fatalf("ParseClientHello error: %v", err)
	}
	if ch.TLSVersion != 0x0303 {
		t.Errorf("TLSVersion = %#04x, want 0x0303", ch.TLSVersion)
	}
	if len(ch.CipherSuites) != 1 || ch.CipherSuites[0] != 0x1301 {
		t.Errorf("CipherSuites = %v, want [0x1301]", ch.CipherSuites)
	}
	if ch.SNI != "" {
		t.Errorf("SNI = %q, want empty", ch.SNI)
	}
}

func TestParseClientHello_WithSNI(t *testing.T) {
	exts := buildSNIExtension("example.com")
	msg := buildClientHello(0x0303, []uint16{0x1301, 0x1302}, exts)
	ch, err := ParseClientHello(msg)
	if err != nil {
		t.Fatalf("ParseClientHello error: %v", err)
	}
	if ch.SNI != "example.com" {
		t.Errorf("SNI = %q, want %q", ch.SNI, "example.com")
	}
	if len(ch.CipherSuites) != 2 {
		t.Errorf("CipherSuites len = %d, want 2", len(ch.CipherSuites))
	}
}

func TestParseClientHello_WithGREASE(t *testing.T) {
	// Include GREASE cipher and a GREASE extension type
	var exts []byte
	exts = append(exts, buildExtension(0x0a0a, []byte{})...) // GREASE extension
	exts = append(exts, buildSNIExtension("test.local")...)

	msg := buildClientHello(0x0303, []uint16{0x0a0a, 0x1301}, exts)
	ch, err := ParseClientHello(msg)
	if err != nil {
		t.Fatalf("ParseClientHello error: %v", err)
	}
	// CipherSuites raw must include GREASE (parser doesn't filter; JA3 does)
	if len(ch.CipherSuites) != 2 {
		t.Errorf("CipherSuites len = %d, want 2 (raw, GREASE included)", len(ch.CipherSuites))
	}
	// Extensions list should include GREASE type
	found := false
	for _, e := range ch.Extensions {
		if e == 0x0a0a {
			found = true
		}
	}
	if !found {
		t.Errorf("Extensions does not contain GREASE 0x0a0a: %v", ch.Extensions)
	}
}

func TestParseClientHello_Truncated(t *testing.T) {
	// Just the type byte + partial length
	_, err := ParseClientHello([]byte{0x01, 0x00})
	if !errors.Is(err, ErrTruncated) {
		t.Errorf("expected ErrTruncated, got %v", err)
	}
}

func TestParseClientHello_WrongType(t *testing.T) {
	msg := buildClientHello(0x0303, []uint16{0x1301}, nil)
	msg[0] = 0x02 // wrong type
	_, err := ParseClientHello(msg)
	if !errors.Is(err, ErrNotHandshake) {
		t.Errorf("expected ErrNotHandshake, got %v", err)
	}
}

func TestParseClientHello_WithEllipticCurves(t *testing.T) {
	curves := []uint16{0x001d, 0x0017, 0x0018}
	var exts []byte
	exts = append(exts, buildSupportedGroupsExtension(curves)...)
	exts = append(exts, buildECPointFormatsExtension([]uint8{0})...)

	msg := buildClientHello(0x0303, []uint16{0x1301}, exts)
	ch, err := ParseClientHello(msg)
	if err != nil {
		t.Fatalf("ParseClientHello error: %v", err)
	}
	if len(ch.EllipticCurves) != 3 {
		t.Errorf("EllipticCurves len = %d, want 3", len(ch.EllipticCurves))
	}
	if ch.EllipticCurves[0] != 0x001d {
		t.Errorf("EllipticCurves[0] = %#04x, want 0x001d", ch.EllipticCurves[0])
	}
	if len(ch.ECPointFormats) != 1 || ch.ECPointFormats[0] != 0 {
		t.Errorf("ECPointFormats = %v, want [0]", ch.ECPointFormats)
	}
}

func TestParseClientHello_WithALPN(t *testing.T) {
	var exts []byte
	exts = append(exts, buildALPNExtension([]string{"h2", "http/1.1"})...)
	msg := buildClientHello(0x0303, []uint16{0x1301}, exts)
	ch, err := ParseClientHello(msg)
	if err != nil {
		t.Fatalf("ParseClientHello error: %v", err)
	}
	if len(ch.ALPNProtocols) != 2 {
		t.Errorf("ALPNProtocols len = %d, want 2", len(ch.ALPNProtocols))
	}
	if ch.ALPNProtocols[0] != "h2" {
		t.Errorf("ALPNProtocols[0] = %q, want %q", ch.ALPNProtocols[0], "h2")
	}
}

func TestParseClientHello_WithSignatureAlgorithms(t *testing.T) {
	schemes := []uint16{0x0403, 0x0804}
	var exts []byte
	exts = append(exts, buildSignatureAlgorithmsExtension(schemes)...)
	msg := buildClientHello(0x0303, []uint16{0x1301}, exts)
	ch, err := ParseClientHello(msg)
	if err != nil {
		t.Fatalf("ParseClientHello error: %v", err)
	}
	if len(ch.SignatureSchemes) != 2 {
		t.Errorf("SignatureSchemes len = %d, want 2", len(ch.SignatureSchemes))
	}
}

func TestParseServerHello_Minimal(t *testing.T) {
	msg := buildServerHello(0x0303, 0x1301, nil)
	sh, err := ParseServerHello(msg)
	if err != nil {
		t.Fatalf("ParseServerHello error: %v", err)
	}
	if sh.TLSVersion != 0x0303 {
		t.Errorf("TLSVersion = %#04x, want 0x0303", sh.TLSVersion)
	}
	if sh.CipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %#04x, want 0x1301", sh.CipherSuite)
	}
	if sh.SelectedALPN != "" {
		t.Errorf("SelectedALPN = %q, want empty", sh.SelectedALPN)
	}
}

func TestParseServerHello_WithALPN(t *testing.T) {
	// ServerHello ALPN extension: same format but only one protocol selected
	alpnExt := buildALPNExtension([]string{"h2"})
	msg := buildServerHello(0x0303, 0x1301, alpnExt)
	sh, err := ParseServerHello(msg)
	if err != nil {
		t.Fatalf("ParseServerHello error: %v", err)
	}
	if sh.SelectedALPN != "h2" {
		t.Errorf("SelectedALPN = %q, want %q", sh.SelectedALPN, "h2")
	}
}

func TestParseServerHello_Truncated(t *testing.T) {
	_, err := ParseServerHello([]byte{0x02, 0x00})
	if !errors.Is(err, ErrTruncated) {
		t.Errorf("expected ErrTruncated, got %v", err)
	}
}

func TestParseServerHello_WrongType(t *testing.T) {
	msg := buildServerHello(0x0303, 0x1301, nil)
	msg[0] = 0x01
	_, err := ParseServerHello(msg)
	if !errors.Is(err, ErrNotHandshake) {
		t.Errorf("expected ErrNotHandshake, got %v", err)
	}
}

func TestExtractHandshakeFromTLSRecord(t *testing.T) {
	inner := buildClientHello(0x0303, []uint16{0x1301}, nil)
	rec := buildTLSRecord(inner)
	got, err := ExtractHandshakeFromTLSRecord(rec)
	if err != nil {
		t.Fatalf("ExtractHandshakeFromTLSRecord error: %v", err)
	}
	if len(got) != len(inner) {
		t.Errorf("length mismatch: got %d, want %d", len(got), len(inner))
	}
}

func TestExtractHandshakeFromTLSRecord_TooShort(t *testing.T) {
	_, err := ExtractHandshakeFromTLSRecord([]byte{0x16, 0x03})
	if !errors.Is(err, ErrTruncated) {
		t.Errorf("expected ErrTruncated, got %v", err)
	}
}

func TestExtractHandshakeFromTLSRecord_NotHandshake(t *testing.T) {
	rec := buildTLSRecord(buildClientHello(0x0303, []uint16{0x1301}, nil))
	rec[0] = 0x17 // application data
	_, err := ExtractHandshakeFromTLSRecord(rec)
	if !errors.Is(err, ErrNotHandshake) {
		t.Errorf("expected ErrNotHandshake, got %v", err)
	}
}

// Regression: ensure binary.BigEndian is imported in tests (used by helpers).
var _ = binary.BigEndian
