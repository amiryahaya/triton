package scanner

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/internal/tlsparse"
)

// ---------------------------------------------------------------------------
// Interface compliance
// ---------------------------------------------------------------------------

func TestTLSObserver_Name(t *testing.T) {
	m := NewTLSObserverModule(nil)
	if got := m.Name(); got != "tls_observer" {
		t.Fatalf("Name() = %q, want %q", got, "tls_observer")
	}
}

func TestTLSObserver_Category(t *testing.T) {
	m := NewTLSObserverModule(nil)
	if got := m.Category(); got != model.CategoryActiveNetwork {
		t.Fatalf("Category() = %v, want CategoryActiveNetwork", got)
	}
}

func TestTLSObserver_ScanTargetType(t *testing.T) {
	m := NewTLSObserverModule(nil)
	if got := m.ScanTargetType(); got != model.TargetPcap {
		t.Fatalf("ScanTargetType() = %v, want TargetPcap", got)
	}
}

// ---------------------------------------------------------------------------
// TLS record helpers
// ---------------------------------------------------------------------------

// wrapInTLSRecord wraps a handshake payload in a 5-byte TLS record header.
func wrapInTLSRecord(handshake []byte) []byte {
	rec := make([]byte, 5+len(handshake))
	rec[0] = 0x16 // handshake content type
	rec[1] = 0x03
	rec[2] = 0x01 // TLS 1.0 legacy version
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(handshake)))
	copy(rec[5:], handshake)
	return rec
}

// buildHandshakeMessage prepends the handshake type and 3-byte length.
func buildHandshakeMessage(msgType byte, body []byte) []byte {
	msg := make([]byte, 4+len(body))
	msg[0] = msgType
	msg[1] = byte(len(body) >> 16)
	msg[2] = byte(len(body) >> 8)
	msg[3] = byte(len(body))
	copy(msg[4:], body)
	return msg
}

// buildTestClientHelloBody constructs a minimal ClientHello body (after the
// 4-byte handshake header).
func buildTestClientHelloBody(t *testing.T) []byte {
	t.Helper()
	// client_version: TLS 1.2 (0x0303)
	var buf []byte
	buf = append(buf, 0x03, 0x03)
	// random: 32 bytes
	buf = append(buf, make([]byte, 32)...)
	// session_id length: 0
	buf = append(buf, 0x00)
	// cipher_suites: 2 suites (4 bytes) + 2-byte length
	// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
	// TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
	buf = append(buf, 0x00, 0x04) // length = 4
	buf = append(buf, 0xC0, 0x2F) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	buf = append(buf, 0x00, 0x2F) // TLS_RSA_WITH_AES_128_CBC_SHA
	// compression_methods: 1 byte (null compression)
	buf = append(buf, 0x01, 0x00)

	// Extensions: SNI for "example.com"
	// SNI extension: type=0x0000, value = list_len(2) + name_type(1) + name_len(2) + name
	sniName := []byte("example.com")
	sniValue := make([]byte, 5+len(sniName))
	binary.BigEndian.PutUint16(sniValue[0:2], uint16(3+len(sniName))) // list_len
	sniValue[2] = 0x00                                                // name_type = host_name
	binary.BigEndian.PutUint16(sniValue[3:5], uint16(len(sniName)))
	copy(sniValue[5:], sniName)

	// supported_groups extension: type=0x000a
	// x25519 (0x001D) + secp256r1 (0x0017)
	groupsValue := []byte{0x00, 0x04, 0x00, 0x1D, 0x00, 0x17} // list_len(2) + 2 groups

	// ec_point_formats: type=0x000b
	pointFmtsValue := []byte{0x01, 0x00} // len=1, uncompressed

	// Build extension block
	extBlock := buildExtension(0x0000, sniValue)
	extBlock = append(extBlock, buildExtension(0x000a, groupsValue)...)
	extBlock = append(extBlock, buildExtension(0x000b, pointFmtsValue)...)

	// extensions total length (2 bytes)
	extLen := make([]byte, 2)
	binary.BigEndian.PutUint16(extLen, uint16(len(extBlock)))
	buf = append(buf, extLen...)
	buf = append(buf, extBlock...)

	return buf
}

// buildExtension encodes a single TLS extension: type(2) + length(2) + data.
func buildExtension(extType uint16, data []byte) []byte {
	ext := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(ext[0:2], extType)
	binary.BigEndian.PutUint16(ext[2:4], uint16(len(data)))
	copy(ext[4:], data)
	return ext
}

// buildTestClientHello returns a complete TLS record containing a ClientHello.
func buildTestClientHello(t *testing.T) []byte {
	t.Helper()
	body := buildTestClientHelloBody(t)
	hs := buildHandshakeMessage(0x01, body) // type = ClientHello
	return wrapInTLSRecord(hs)
}

// buildTestServerHelloBody constructs a minimal ServerHello body.
func buildTestServerHelloBody(t *testing.T) []byte {
	t.Helper()
	var buf []byte
	// server_version: TLS 1.2 (0x0303)
	buf = append(buf, 0x03, 0x03)
	// random: 32 bytes
	buf = append(buf, make([]byte, 32)...)
	// session_id length: 0
	buf = append(buf, 0x00)
	// cipher_suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
	buf = append(buf, 0xC0, 0x2F)
	// compression_method: null (0x00)
	buf = append(buf, 0x00)
	// No extensions
	return buf
}

// buildTestServerHello returns a complete TLS record containing a ServerHello.
func buildTestServerHello(t *testing.T) []byte {
	t.Helper()
	body := buildTestServerHelloBody(t)
	hs := buildHandshakeMessage(0x02, body) // type = ServerHello
	return wrapInTLSRecord(hs)
}

// makePacket creates a mock TCP packet from the given payload.
func makePacket(src, dst string, srcPort, dstPort uint16, payload []byte) *tlsparse.Packet {
	return &tlsparse.Packet{
		SrcIP:   net.ParseIP(src),
		SrcPort: srcPort,
		DstIP:   net.ParseIP(dst),
		DstPort: dstPort,
		Payload: payload,
		Time:    time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Core behaviour tests
// ---------------------------------------------------------------------------

func TestTLSObserver_PcapFile(t *testing.T) {
	chPkt := makePacket("10.0.0.1", "10.0.0.2", 54321, 443, buildTestClientHello(t))
	shPkt := makePacket("10.0.0.2", "10.0.0.1", 443, 54321, buildTestServerHello(t))

	src := tlsparse.NewMockSource(chPkt, shPkt)

	cfg := &scannerconfig.Config{}
	m := NewTLSObserverModule(cfg)
	m.readerFactory = func(_ string) (tlsparse.PacketSource, error) {
		return src, nil
	}

	target := model.ScanTarget{Type: model.TargetPcap, Value: "test.pcap"}
	findings := make(chan *model.Finding, 32)
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	close(findings)

	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	if len(got) == 0 {
		t.Fatal("expected at least one finding, got none")
	}

	// At minimum we expect a negotiated cipher finding and a fingerprint finding.
	var hasFingerprint, hasCipher bool
	var fpFinding *model.Finding
	for _, f := range got {
		if f.CryptoAsset == nil {
			continue
		}
		if f.CryptoAsset.JA3Fingerprint != "" {
			hasFingerprint = true
			fpFinding = f
		}
		if f.CryptoAsset.Algorithm != "" && f.CryptoAsset.JA3Fingerprint == "" {
			hasCipher = true
		}
		// Verify module name
		if f.Module != "tls_observer" {
			t.Errorf("Module = %q, want %q", f.Module, "tls_observer")
		}
		// Verify source type
		if f.Source.Type != "network" {
			t.Errorf("Source.Type = %q, want %q", f.Source.Type, "network")
		}
		// Verify TLSFlowSource
		if f.CryptoAsset.TLSFlowSource != "pcap_file" {
			t.Errorf("TLSFlowSource = %q, want %q", f.CryptoAsset.TLSFlowSource, "pcap_file")
		}
		// Verify SNI was captured
		if f.CryptoAsset.SNI != "example.com" && f.CryptoAsset.JA3Fingerprint != "" {
			t.Errorf("SNI = %q, want %q", f.CryptoAsset.SNI, "example.com")
		}
	}

	if !hasFingerprint {
		t.Error("expected a finding with JA3 fingerprint, found none")
	}
	if !hasCipher {
		t.Error("expected a finding with negotiated cipher, found none")
	}

	// The test sends both ClientHello and ServerHello, so all 4 fingerprints must be set.
	if fpFinding != nil {
		if fpFinding.CryptoAsset.JA3SFingerprint == "" {
			t.Error("expected JA3S fingerprint to be set (ServerHello was sent)")
		}
		if fpFinding.CryptoAsset.JA4Fingerprint == "" {
			t.Error("expected JA4 fingerprint to be set (ClientHello was sent)")
		}
		if fpFinding.CryptoAsset.JA4SFingerprint == "" {
			t.Error("expected JA4S fingerprint to be set (ServerHello was sent)")
		}
	}
}

func TestTLSObserver_ClientHelloOnly(t *testing.T) {
	// Only a ClientHello — no ServerHello in the flow.
	// Should still emit a fingerprint finding (no cipher finding).
	chPkt := makePacket("10.0.0.1", "10.0.0.2", 54321, 443, buildTestClientHello(t))

	src := tlsparse.NewMockSource(chPkt)

	cfg := &scannerconfig.Config{}
	m := NewTLSObserverModule(cfg)
	m.readerFactory = func(_ string) (tlsparse.PacketSource, error) {
		return src, nil
	}

	target := model.ScanTarget{Type: model.TargetPcap, Value: "client_only.pcap"}
	findings := make(chan *model.Finding, 32)
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	close(findings)

	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	if len(got) == 0 {
		t.Fatal("expected at least one finding for ClientHello-only flow, got none")
	}

	var hasFingerprint bool
	for _, f := range got {
		if f.CryptoAsset != nil && f.CryptoAsset.JA3Fingerprint != "" {
			hasFingerprint = true
		}
	}
	if !hasFingerprint {
		t.Error("expected a fingerprint finding for ClientHello-only flow")
	}
}

func TestTLSObserver_NonTLSPacketsIgnored(t *testing.T) {
	// Packet with a non-TLS payload (first byte != 0x16).
	nonTLS := &tlsparse.Packet{
		SrcIP:   net.ParseIP("10.0.0.1"),
		SrcPort: 12345,
		DstIP:   net.ParseIP("10.0.0.2"),
		DstPort: 80,
		Payload: []byte{0x47, 0x45, 0x54, 0x20, 0x2F}, // "GET /"
		Time:    time.Now(),
	}

	src := tlsparse.NewMockSource(nonTLS)

	cfg := &scannerconfig.Config{}
	m := NewTLSObserverModule(cfg)
	m.readerFactory = func(_ string) (tlsparse.PacketSource, error) {
		return src, nil
	}

	target := model.ScanTarget{Type: model.TargetPcap, Value: "nontls.pcap"}
	findings := make(chan *model.Finding, 32)
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	close(findings)

	var count int
	for range findings {
		count++
	}

	if count != 0 {
		t.Fatalf("expected 0 findings for non-TLS traffic, got %d", count)
	}
}

func TestTLSObserver_FlowCap(t *testing.T) {
	// Generate 10001 unique ClientHello flows to verify the 10K cap.
	const flowsToSend = 10_001

	pkts := make([]*tlsparse.Packet, 0, flowsToSend)
	chPayload := buildTestClientHello(t)
	for i := 0; i < flowsToSend; i++ {
		// Each packet has a unique source port to create a unique flow.
		pkt := &tlsparse.Packet{
			SrcIP:   net.ParseIP("10.0.0.1"),
			SrcPort: uint16(i % 65535),
			DstIP:   net.ParseIP("10.0.0.2"),
			DstPort: 443,
			Payload: chPayload,
			Time:    time.Now(),
		}
		pkts = append(pkts, pkt)
	}

	src := tlsparse.NewMockSource(pkts...)

	cfg := &scannerconfig.Config{}
	m := NewTLSObserverModule(cfg)
	m.readerFactory = func(_ string) (tlsparse.PacketSource, error) {
		return src, nil
	}

	target := model.ScanTarget{Type: model.TargetPcap, Value: "bigcap.pcap"}
	findings := make(chan *model.Finding, flowsToSend+10)

	// Should not panic and should complete without error.
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	close(findings)

	var count int
	for range findings {
		count++
	}

	// Findings should be <= maxFlows (10_000) since additional flows are dropped.
	const maxFlows = 10_000
	if count > maxFlows {
		t.Errorf("findings = %d, want <= %d (maxFlows cap)", count, maxFlows)
	}
}

func TestTLSObserver_LiveCapture(t *testing.T) {
	// Verify that the "iface:" prefix triggers live capture path.
	// The mock factory intercepts the call regardless of prefix.
	chPkt := makePacket("192.168.1.1", "192.168.1.2", 11111, 443, buildTestClientHello(t))
	src := tlsparse.NewMockSource(chPkt)

	cfg := &scannerconfig.Config{}
	m := NewTLSObserverModule(cfg)
	m.readerFactory = func(target string) (tlsparse.PacketSource, error) {
		return src, nil
	}

	target := model.ScanTarget{Type: model.TargetPcap, Value: "iface:eth0"}
	findings := make(chan *model.Finding, 32)
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	close(findings)

	var got []*model.Finding
	for f := range findings {
		got = append(got, f)
	}

	if len(got) == 0 {
		t.Fatal("expected at least one finding from live capture target")
	}

	// All findings should have TLSFlowSource = "live_capture".
	for _, f := range got {
		if f.CryptoAsset == nil {
			continue
		}
		if f.CryptoAsset.TLSFlowSource != "live_capture" {
			t.Errorf("TLSFlowSource = %q, want %q", f.CryptoAsset.TLSFlowSource, "live_capture")
		}
	}
}

func TestTLSObserver_EmptySource(t *testing.T) {
	// Empty source should emit no findings and no error.
	src := tlsparse.NewMockSource()

	cfg := &scannerconfig.Config{}
	m := NewTLSObserverModule(cfg)
	m.readerFactory = func(_ string) (tlsparse.PacketSource, error) {
		return src, nil
	}

	target := model.ScanTarget{Type: model.TargetPcap, Value: "empty.pcap"}
	findings := make(chan *model.Finding, 8)
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	close(findings)

	var count int
	for range findings {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 findings for empty source, got %d", count)
	}
}

func TestTLSObserver_ShortPayloadIgnored(t *testing.T) {
	// A payload shorter than 6 bytes should be silently skipped.
	short := &tlsparse.Packet{
		SrcIP:   net.ParseIP("1.2.3.4"),
		SrcPort: 1000,
		DstIP:   net.ParseIP("5.6.7.8"),
		DstPort: 443,
		Payload: []byte{0x16, 0x03}, // only 2 bytes, < 6
		Time:    time.Now(),
	}

	src := tlsparse.NewMockSource(short)
	cfg := &scannerconfig.Config{}
	m := NewTLSObserverModule(cfg)
	m.readerFactory = func(_ string) (tlsparse.PacketSource, error) {
		return src, nil
	}

	target := model.ScanTarget{Type: model.TargetPcap, Value: "short.pcap"}
	findings := make(chan *model.Finding, 8)
	if err := m.Scan(context.Background(), target, findings); err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	close(findings)

	var count int
	for range findings {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 findings for short payload, got %d", count)
	}
}

func TestTLSObserver_ReaderFactoryError(t *testing.T) {
	cfg := scannerconfig.Load("comprehensive")
	m := NewTLSObserverModule(cfg)
	m.readerFactory = func(_ string) (tlsparse.PacketSource, error) {
		return nil, errors.New("file not found")
	}
	findings := make(chan *model.Finding, 8)
	target := model.ScanTarget{Type: model.TargetPcap, Value: "missing.pcap"}
	err := m.Scan(context.Background(), target, findings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "file not found")
}
