package portscan

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
	"github.com/amiryahaya/triton/pkg/model"
)

type hostResolver interface {
	Get(ctx context.Context, id uuid.UUID) (hosts.Host, error)
}

// NewPortScanFunc builds the ScanFunc for port_survey jobs.
// It resolves the host's IP, runs the port scanner, and returns a ScanResult.
func NewPortScanFunc(hl hostResolver) scanjobs.ScanFunc {
	return func(ctx context.Context, j scanjobs.Job) (*model.ScanResult, error) {
		h, err := hl.Get(ctx, j.HostID)
		if err != nil {
			return nil, fmt.Errorf("portscan: resolve host %s: %w", j.HostID, err)
		}
		if h.IP == "" {
			return nil, fmt.Errorf("portscan: host %s has no IP address", j.HostID)
		}

		scanner := NewScanner(j.Profile)
		var findings []Finding
		if err := scanner.Scan(ctx, h.IP, func(f Finding) {
			findings = append(findings, f)
		}); err != nil {
			return nil, fmt.Errorf("portscan: scan %s: %w", h.IP, err)
		}

		hostname := h.Hostname
		if hostname == "" {
			hostname = h.IP
		}
		return MapToScanResult(hostname, string(j.Profile), findings), nil
	}
}
