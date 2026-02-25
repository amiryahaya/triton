package scanner

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

type CertificateModule struct {
	config *config.Config
}

func NewCertificateModule(cfg *config.Config) *CertificateModule {
	return &CertificateModule{config: cfg}
}

func (m *CertificateModule) Name() string {
	return "certificates"
}

func (m *CertificateModule) Scan(ctx context.Context, target string, findings chan<- *model.Finding) error {
	return filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors, continue scanning
		}

		if info.IsDir() {
			if m.shouldSkipDir(path) {
				return filepath.SkipDir
			}
			return nil
		}

		if !m.isCertificateFile(path) {
			return nil
		}

		certs, err := m.parseCertificateFile(path)
		if err != nil {
			return nil // Skip parse errors
		}

		for _, cert := range certs {
			finding := m.createFinding(path, cert)
			select {
			case findings <- finding:
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		return nil
	})
}

func (m *CertificateModule) isCertificateFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".pem" || ext == ".crt" || ext == ".cer" ||
		ext == ".der" || ext == ".p7b" || ext == ".p7c"
}

func (m *CertificateModule) shouldSkipDir(path string) bool {
	for _, exclude := range m.config.ExcludePatterns {
		if strings.Contains(path, exclude) {
			return true
		}
	}
	return false
}

func (m *CertificateModule) parseCertificateFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate

	// Try PEM format
	if strings.Contains(string(data), "BEGIN CERTIFICATE") {
		block, rest := pem.Decode(data)
		for block != nil {
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					certs = append(certs, cert)
				}
			}
			block, rest = pem.Decode(rest)
		}
	}

	// Try DER format if no PEM certs found
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			certs = append(certs, cert)
		}
	}

	return certs, nil
}

func (m *CertificateModule) createFinding(path string, cert *x509.Certificate) *model.Finding {
	return &model.Finding{
		Type: "certificate",
		Path: path,
		CryptoAsset: &model.CryptoAsset{
			Type:         "certificate",
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.String(),
			NotBefore:    cert.NotBefore.Unix(),
			NotAfter:     cert.NotAfter.Unix(),
			Algorithm:    cert.SignatureAlgorithm.String(),
			KeySize:      m.estimateKeySize(cert),
			IsCA:         cert.IsCA,
		},
		Confidence: 1.0,
	}
}

func (m *CertificateModule) estimateKeySize(cert *x509.Certificate) int {
	// Estimate key size based on public key type
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		// We'd need to parse the actual key to get size
		return 2048 // Default assumption
	case x509.ECDSA:
		return 256
	case x509.Ed25519:
		return 256
	default:
		return 0
	}
}
