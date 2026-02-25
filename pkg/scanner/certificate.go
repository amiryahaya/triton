package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/google/uuid"
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

func (m *CertificateModule) Category() model.ModuleCategory {
	return model.CategoryPassiveFile
}

func (m *CertificateModule) ScanTargetType() model.ScanTargetType {
	return model.TargetFilesystem
}

func (m *CertificateModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	return walkTarget(walkerConfig{
		target:    target,
		config:    m.config,
		matchFile: m.isCertificateFile,
		processFile: func(path string) error {
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
		},
	})
}

func (m *CertificateModule) isCertificateFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".pem" || ext == ".crt" || ext == ".cer" ||
		ext == ".der" || ext == ".p7b" || ext == ".p7c"
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
	now := time.Now()
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter

	keySize := m.extractKeySize(cert)

	// Build algorithm name with key size for PQC lookup
	algoWithSize := fmt.Sprintf("%s-%d", m.publicKeyAlgoName(cert), keySize)

	asset := &model.CryptoAsset{
		ID:           uuid.New().String(),
		Function:     "Certificate authentication",
		Algorithm:    algoWithSize,
		KeySize:      keySize,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    &notBefore,
		NotAfter:     &notAfter,
		IsCA:         cert.IsCA,
	}
	crypto.ClassifyCryptoAsset(asset)

	return &model.Finding{
		ID:       uuid.New().String(),
		Category: 5, // Certificate scanning
		Source: model.FindingSource{
			Type: "file",
			Path: path,
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "certificates",
		Timestamp:   now,
	}
}

func (m *CertificateModule) publicKeyAlgoName(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA-P"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return "Unknown"
	}
}

func (m *CertificateModule) extractKeySize(cert *x509.Certificate) int {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return pub.N.BitLen()
		}
		return 2048
	case x509.ECDSA:
		if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
			return pub.Curve.Params().BitSize
		}
		return 256
	case x509.Ed25519:
		return 256
	default:
		return 0
	}
}
