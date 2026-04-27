// Package portscan implements scanrunner.Scanner using fingerprintx.
package portscan

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/praetorian-inc/fingerprintx/pkg/scan"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/scanrunner"
)

// FingerprintxScanner implements scanrunner.Scanner using fingerprintx.
type FingerprintxScanner struct{}

// NewFingerprintxScanner returns a FingerprintxScanner ready to use.
func NewFingerprintxScanner() *FingerprintxScanner {
	return &FingerprintxScanner{}
}

// Scan probes the target using fingerprintx and calls onFinding for each result.
func (s *FingerprintxScanner) Scan(ctx context.Context, target scanrunner.Target, onFinding func(scanrunner.Finding)) error {
	addr, err := netip.ParseAddr(target.IP)
	if err != nil {
		return fmt.Errorf("portscan: invalid ip %q: %w", target.IP, err)
	}

	profile := scanjobs.Profile(target.Profile)
	ports := effectivePorts(profile, target.PortOverride)
	targets := make([]plugins.Target, len(ports))
	for i, p := range ports {
		targets[i] = plugins.Target{Address: netip.AddrPortFrom(addr, p)}
	}

	timeoutSec := profileParams(profile)
	cfg := scan.Config{
		DefaultTimeout: time.Duration(timeoutSec) * time.Second,
		FastMode:       profile == scanjobs.ProfileQuick,
		Verbose:        false,
		UDP:            false,
	}

	results, err := scan.ScanTargets(targets, cfg)
	if err != nil {
		return fmt.Errorf("portscan: fingerprintx %s: %w", target.IP, err)
	}

	for i := range results {
		svc := &results[i]
		f := scanrunner.Finding{
			Port:    uint16(svc.Port), //nolint:gosec // port always in [1,65535]
			Service: svc.Protocol,
			Banner:  svc.Version,
		}
		if isTLSService(svc) {
			f.TLSCert = extractTLSCert(ctx, target.IP, svc.Port,
				time.Duration(timeoutSec)*time.Second)
		}
		onFinding(f)
	}
	return nil
}

// Ports returns the ordered TCP port list for the given profile.
func Ports(p scanjobs.Profile) []uint16 {
	switch p {
	case scanjobs.ProfileComprehensive:
		return top10000Ports
	case scanjobs.ProfileStandard:
		return top1000Ports
	default:
		return top100Ports
	}
}

func effectivePorts(p scanjobs.Profile, override []uint16) []uint16 {
	if len(override) > 0 {
		return override
	}
	return Ports(p)
}

func profileParams(p scanjobs.Profile) (timeoutSec int) {
	switch p {
	case scanjobs.ProfileComprehensive:
		return 5
	case scanjobs.ProfileStandard:
		return 3
	default:
		return 3
	}
}

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
