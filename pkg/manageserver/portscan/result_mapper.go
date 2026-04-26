package portscan

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// MapToScanResult converts port scan findings into a model.ScanResult
// ready for submission to the report portal via scanresults.Enqueue.
func MapToScanResult(hostname, profile string, findings []Finding) *model.ScanResult {
	result := &model.ScanResult{
		ID: uuid.NewString(),
		Metadata: model.ScanMetadata{
			Timestamp:   time.Now(),
			Hostname:    hostname,
			ScanProfile: profile,
		},
		Findings: make([]model.Finding, 0, len(findings)),
	}

	for i := range findings {
		f := &findings[i]
		endpoint := fmt.Sprintf("tcp://%s:%d", f.IP, f.Port)

		// TLS certificate finding.
		if f.TLSCert != nil {
			nb := f.TLSCert.NotBefore
			na := f.TLSCert.NotAfter
			asset := &model.CryptoAsset{
				ID:        uuid.NewString(),
				Algorithm: f.TLSCert.Algorithm,
				KeySize:   f.TLSCert.KeyBits,
				Subject:   f.TLSCert.Subject,
				Issuer:    f.TLSCert.Issuer,
				NotBefore: &nb,
				NotAfter:  &na,
				SANs:      f.TLSCert.SANs,
				PQCStatus: classifyKeySize(f.TLSCert.Algorithm, f.TLSCert.KeyBits),
				Function:  "authentication",
				State:     "IN_TRANSIT",
			}
			result.Findings = append(result.Findings, model.Finding{
				ID:       uuid.NewString(),
				Category: int(model.CategoryActiveNetwork),
				Source: model.FindingSource{
					Type:            "network",
					Endpoint:        endpoint,
					DetectionMethod: "tls-handshake",
				},
				CryptoAsset: asset,
				Confidence:  0.95,
				Module:      "port_survey",
				Timestamp:   time.Now(),
			})
		}

		// Service protocol finding.
		if f.Service != nil {
			if asset := serviceToAsset(f, endpoint); asset != nil {
				result.Findings = append(result.Findings, model.Finding{
					ID:       uuid.NewString(),
					Category: int(model.CategoryActiveNetwork),
					Source: model.FindingSource{
						Type:            "network",
						Endpoint:        endpoint,
						DetectionMethod: "banner-grab",
					},
					CryptoAsset: asset,
					Confidence:  0.85,
					Module:      "port_survey",
					Timestamp:   time.Now(),
				})
			}
		}
	}
	return result
}

func serviceToAsset(f *Finding, _ string) *model.CryptoAsset {
	if f.Service == nil {
		return nil
	}
	proto := strings.ToLower(f.Service.Protocol)
	switch proto {
	case "ssh":
		return &model.CryptoAsset{
			ID:        uuid.NewString(),
			Algorithm: "SSH",
			Subject:   f.Service.Version,
			PQCStatus: model.PQCStatusTransitional,
			Function:  "authentication",
			State:     "IN_TRANSIT",
		}
	case "http", "https":
		if f.Service.Version == "" {
			return nil
		}
		return &model.CryptoAsset{
			ID:        uuid.NewString(),
			Algorithm: strings.ToUpper(proto),
			Subject:   f.Service.Version,
			PQCStatus: model.PQCStatusTransitional,
			Function:  "encryption",
			State:     "IN_TRANSIT",
		}
	}
	return nil
}

func classifyKeySize(algo string, bits int) string {
	switch strings.ToUpper(algo) {
	case "RSA":
		if bits >= 2048 {
			return model.PQCStatusTransitional
		}
		return model.PQCStatusDeprecated
	case "ECDSA", "EC":
		if bits >= 256 {
			return model.PQCStatusTransitional
		}
		return model.PQCStatusDeprecated
	}
	return model.PQCStatusTransitional
}
