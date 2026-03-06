package scanner

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// CertStoreModule scans the operating system's certificate store for
// installed certificates and their cryptographic properties.
type CertStoreModule struct {
	config *config.Config
}

func NewCertStoreModule(cfg *config.Config) *CertStoreModule {
	return &CertStoreModule{config: cfg}
}

func (m *CertStoreModule) Name() string                         { return "certstore" }
func (m *CertStoreModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *CertStoreModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }

// Scan reads the OS certificate store and emits findings for each certificate.
func (m *CertStoreModule) Scan(ctx context.Context, _ model.ScanTarget, findings chan<- *model.Finding) error {
	var pemData []byte
	var err error

	switch runtime.GOOS {
	case "darwin":
		pemData, err = m.readMacOSCerts(ctx)
	case "linux":
		pemData, err = m.readLinuxCerts()
	default:
		// Unsupported OS — skip silently
		return nil
	}

	if err != nil {
		return nil // Non-fatal: cert store may not be accessible
	}

	return m.parsePEMCerts(ctx, pemData, findings)
}

// readMacOSCerts reads certificates from macOS system keychain.
func (m *CertStoreModule) readMacOSCerts(ctx context.Context) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "security", "find-certificate", "-a", "-p",
		"/System/Library/Keychains/SystemRootCertificates.keychain")
	return cmd.Output()
}

// readLinuxCerts reads the system CA certificate bundle.
func (m *CertStoreModule) readLinuxCerts() ([]byte, error) {
	paths := []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("no CA bundle found")
}

// parsePEMCerts decodes PEM data and emits findings for each certificate.
func (m *CertStoreModule) parsePEMCerts(ctx context.Context, pemData []byte, findings chan<- *model.Finding) error {
	rest := pemData

	for len(rest) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		algoName, keySize := certKeyInfo(cert)

		notBefore := cert.NotBefore
		notAfter := cert.NotAfter

		asset := &model.CryptoAsset{
			ID:           uuid.Must(uuid.NewV7()).String(),
			Function:     "OS certificate store",
			Algorithm:    algoName,
			KeySize:      keySize,
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.String(),
			NotBefore:    &notBefore,
			NotAfter:     &notAfter,
			IsCA:         cert.IsCA,
			Purpose:      "System trust anchor",
		}
		crypto.ClassifyCryptoAsset(asset)

		finding := &model.Finding{
			ID:       uuid.Must(uuid.NewV7()).String(),
			Category: 2, // Certificates
			Source: model.FindingSource{
				Type:            "file",
				Path:            "os:certstore",
				DetectionMethod: "configuration",
			},
			CryptoAsset: asset,
			Confidence:  0.95,
			Module:      "certstore",
			Timestamp:   time.Now(),
		}

		select {
		case findings <- finding:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// certKeyInfo extracts the algorithm name and key size from a certificate.
// It delegates to the shared certPublicKeyInfo helper.
func certKeyInfo(cert *x509.Certificate) (algo string, size int) {
	return certPublicKeyInfo(cert)
}
