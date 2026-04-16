package tlsparse

import "net"

// ClientHelloInfo holds parsed fields from a TLS ClientHello message.
type ClientHelloInfo struct {
	TLSVersion       uint16
	CipherSuites     []uint16
	Extensions       []uint16
	EllipticCurves   []uint16 // supported_groups
	ECPointFormats   []uint8
	SNI              string
	ALPNProtocols    []string
	SignatureSchemes []uint16
}

// ServerHelloInfo holds parsed fields from a TLS ServerHello message.
type ServerHelloInfo struct {
	TLSVersion   uint16
	CipherSuite  uint16
	Extensions   []uint16
	SelectedALPN string
}

// FlowKey identifies a unique TCP flow.
type FlowKey struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
}

// FlowState tracks handshake progress for a single TLS flow.
type FlowState struct {
	Key         FlowKey
	ClientHello *ClientHelloInfo
	ServerHello *ServerHelloInfo
}

// Fingerprint holds computed fingerprints for a TLS flow.
type Fingerprint struct {
	JA3     string // MD5 hex of JA3 raw string
	JA3S    string
	JA4     string // structured JA4 fingerprint
	JA4S    string
	JA3Raw  string
	JA3SRaw string
}
