// Package scanrunner is the shared foundation for all external scan binaries
// (triton-portscan, future triton-sshscan). It defines the Scanner interface
// and the shared types used across the scan lifecycle.
package scanrunner

import (
	"context"
	"time"
)

// Scanner is the pluggable scan engine contract.
// FingerprintxScanner implements this; future: NmapScanner, SSHAgentlessScanner.
type Scanner interface {
	Scan(ctx context.Context, target Target, onFinding func(Finding)) error
}

// Target describes a single host to scan.
type Target struct {
	IP           string
	Profile      string     // "quick" | "standard" | "comprehensive"
	RateLimit    int        // max new TCP connections/sec; 0 = profile default
	PortOverride []uint16   // non-nil overrides profile port list; nil = profile default
	Credentials  *Credentials // nil for port survey; non-nil for SSH agentless
}

// Credentials holds optional SSH/auth material for agentless scan types.
type Credentials struct {
	Username   string
	Password   string
	PrivateKey []byte
	Port       int // default 22 for SSH
}

// Finding is one detected service on a host port.
type Finding struct {
	Port    uint16
	Service string      // "ssh", "https", "smtp" etc.
	Banner  string      // version string / banner
	TLSCert *TLSCertInfo // non-nil when TLS certificate was extracted
}

// TLSCertInfo holds crypto-relevant fields from a TLS certificate.
type TLSCertInfo struct {
	Subject      string
	Issuer       string
	Algorithm    string // "RSA", "ECDSA"
	KeyBits      int
	NotBefore    time.Time
	NotAfter     time.Time
	SANs         []string
	SerialNumber string
	IsSelfSigned bool
}
