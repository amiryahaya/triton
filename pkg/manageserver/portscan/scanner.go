package portscan

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

// PortScanProfile aliases scanjobs.Profile for use in this package.
type PortScanProfile = scanjobs.Profile

// Ports returns the ordered TCP port list for the given profile.
func Ports(p PortScanProfile) []uint16 {
	switch p {
	case scanjobs.ProfileComprehensive:
		return top10000Ports
	case scanjobs.ProfileStandard:
		return top1000Ports
	default:
		return top100Ports
	}
}

// TLSCertInfo holds crypto-relevant fields from a TLS certificate.
// Full implementation in tls.go.
type TLSCertInfo struct {
	Subject      string
	Issuer       string
	Algorithm    string
	KeyBits      int
	NotBefore    time.Time
	NotAfter     time.Time
	SANs         []string
	SerialNumber string
	IsSelfSigned bool
}

// Scanner wraps fingerprintx with profile-derived aggressiveness.
type Scanner struct {
	Profile        PortScanProfile
	TimeoutSeconds int
	Concurrency    int
}

// NewScanner returns a Scanner tuned to the given profile.
func NewScanner(p PortScanProfile) *Scanner {
	s := &Scanner{Profile: p}
	switch p {
	case scanjobs.ProfileComprehensive:
		s.TimeoutSeconds = 5
		s.Concurrency = 500
	case scanjobs.ProfileStandard:
		s.TimeoutSeconds = 3
		s.Concurrency = 200
	default:
		s.TimeoutSeconds = 3
		s.Concurrency = 50
	}
	return s
}

// Finding is one detected service on a host port.
type Finding struct {
	IP      string
	Port    uint16
	Service *plugins.Service // nil if port open but unidentified
	TLSCert *TLSCertInfo     // non-nil when TLS certificate was extracted
}

// Scan probes ip using the profile's port list.
// onFinding is called for each open/identified port.
func (s *Scanner) Scan(ctx context.Context, ip string, onFinding func(Finding)) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("portscan: invalid ip %q: %w", ip, err)
	}

	ports := Ports(s.Profile)
	targets := make([]plugins.Target, len(ports))
	for i, p := range ports {
		targets[i] = plugins.Target{
			Address: netip.AddrPortFrom(addr, p),
		}
	}

	cfg := scan.Config{
		DefaultTimeout: time.Duration(s.TimeoutSeconds) * time.Second,
		FastMode:       s.Profile == scanjobs.ProfileQuick,
		Verbose:        false,
		UDP:            false,
	}

	results, err := scan.ScanTargets(targets, cfg)
	if err != nil {
		return fmt.Errorf("portscan: fingerprintx %s: %w", ip, err)
	}

	for i := range results {
		svc := &results[i]
		f := Finding{
			IP:      ip,
			Port:    uint16(svc.Port), //nolint:gosec // port is always in [1,65535]
			Service: svc,
		}
		if isTLSService(svc) {
			f.TLSCert = extractTLSCert(ctx, ip, svc.Port,
				time.Duration(s.TimeoutSeconds)*time.Second)
		}
		onFinding(f)
	}
	return nil
}

// isTLSService returns true when the service typically uses TLS.
func isTLSService(s *plugins.Service) bool {
	if s == nil {
		return false
	}
	switch s.Protocol {
	case plugins.ProtoHTTPS, "tls", plugins.ProtoSMTPS,
		plugins.ProtoIMAPS, plugins.ProtoPOP3S, "ftps",
		plugins.ProtoLDAPS, plugins.ProtoRDP:
		return true
	}
	return false
}

