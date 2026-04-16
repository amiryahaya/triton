package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/crypto/keyquality"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/store"
)

type CertificateModule struct {
	config      *scannerconfig.Config
	lastScanned int64
	lastMatched int64
	store       store.Store
	reader      fsadapter.FileReader
}

func (m *CertificateModule) SetStore(s store.Store)               { m.store = s }
func (m *CertificateModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

func NewCertificateModule(cfg *scannerconfig.Config) *CertificateModule {
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

func (m *CertificateModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *CertificateModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    m.isCertificateFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		reader:       m.reader,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			ext := strings.ToLower(filepath.Ext(path))

			certs, err := m.parseCertificateFile(ctx, reader, path)

			// JKS files can't be fully parsed but should produce a finding
			if (ext == ".jks") && err == nil && len(certs) == 0 {
				finding := m.createContainerFinding(path, "JKS")
				select {
				case findings <- finding:
				case <-ctx.Done():
					return ctx.Err()
				}
				return nil
			}

			if err != nil {
				// PKCS#12/PFX: emit a locked-container finding instead of silently skipping.
				if err == errPKCS12Locked && (ext == ".p12" || ext == ".pfx") {
					finding := m.createLockedContainerFinding(path, "PKCS#12")
					select {
					case findings <- finding:
					case <-ctx.Done():
						return ctx.Err()
					}
					return nil
				}
				return nil // Skip other parse errors
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
		ext == ".der" || ext == ".p7b" || ext == ".p7c" ||
		ext == ".p12" || ext == ".pfx" || ext == ".jks"
}

func (m *CertificateModule) parseCertificateFile(ctx context.Context, reader fsadapter.FileReader, path string) ([]*x509.Certificate, error) {
	data, err := reader.ReadFile(ctx, path)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(path))

	// PKCS#12 / PFX containers
	if ext == ".p12" || ext == ".pfx" {
		return m.parsePKCS12(data)
	}

	// JKS (Java KeyStore) — detect magic bytes, report as opaque container
	if ext == ".jks" {
		return m.parseJKS(data)
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

var errPKCS12Locked = fmt.Errorf("could not decode PKCS#12 with known passwords")

// keystorePasswords returns a merged, deduplicated password list: user-configured
// passwords first, then built-in defaults.
func (m *CertificateModule) keystorePasswords() []string {
	builtins := []string{"", "changeit", "changeme", "password", "secret", "triton", "server", "client", "keystore"}
	if m.config == nil || len(m.config.KeystorePasswords) == 0 {
		return builtins
	}
	seen := make(map[string]struct{}, len(m.config.KeystorePasswords)+len(builtins))
	var merged []string
	for _, pw := range append(m.config.KeystorePasswords, builtins...) {
		if _, ok := seen[pw]; !ok {
			seen[pw] = struct{}{}
			merged = append(merged, pw)
		}
	}
	return merged
}

// parsePKCS12 attempts to decode a PKCS#12/PFX container.
// Tries all passwords from keystorePasswords(). Returns errPKCS12Locked when
// no password works, enabling the caller to emit a locked-container finding.
func (m *CertificateModule) parsePKCS12(data []byte) ([]*x509.Certificate, error) {
	for _, pw := range m.keystorePasswords() {
		_, cert, caCerts, err := pkcs12.DecodeChain(data, pw)
		if err == nil {
			var certs []*x509.Certificate
			if cert != nil {
				certs = append(certs, cert)
			}
			certs = append(certs, caCerts...)
			return certs, nil
		}
	}
	return nil, errPKCS12Locked
}

// createLockedContainerFinding creates a finding for a password-protected crypto
// container that could not be decrypted with any known password.
func (m *CertificateModule) createLockedContainerFinding(path, containerType string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  containerType + " container",
		Algorithm: "Unknown",
		Purpose:   "password-protected container (could not decrypt)",
	}
	crypto.ClassifyCryptoAsset(asset)

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 5,
		Source: model.FindingSource{
			Type: "file",
			Path: path,
		},
		CryptoAsset: asset,
		Confidence:  0.50,
		Module:      "certificates",
		Timestamp:   time.Now(),
	}
}

// parseJKS detects JKS files by magic bytes. Go cannot natively parse JKS,
// so we return nil certs but the caller can still create a finding for the container.
func (m *CertificateModule) parseJKS(data []byte) ([]*x509.Certificate, error) {
	if len(data) < 4 || !isJKSMagic(data[:4]) {
		return nil, fmt.Errorf("not a valid JKS file")
	}
	// JKS detected but we can't parse it natively — return nil certs
	// The Scan method will handle creating a basic finding for this container
	return nil, nil
}

func isJKSMagic(b []byte) bool {
	return len(b) >= 4 && binary.BigEndian.Uint32(b) == 0xFEEDFEED
}

func (m *CertificateModule) createFinding(path string, cert *x509.Certificate) *model.Finding {
	now := time.Now()
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter

	keySize := m.extractKeySize(cert)

	// Build algorithm name consistent with PQC registry (e.g. RSA-2048, ECDSA-P256, Ed25519)
	algoWithSize := m.buildCertAlgorithmName(cert, keySize)

	asset := &model.CryptoAsset{
		ID:           uuid.Must(uuid.NewV7()).String(),
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

	// Detect hybrid/composite certificates
	if isHybrid, components := m.detectHybridCert(cert); isHybrid {
		asset.IsHybrid = true
		asset.ComponentAlgorithms = components
	}

	crypto.ClassifyCryptoAsset(asset)

	// Key-quality audit. Non-blocking: warnings are informational.
	if cert.PublicKey != nil {
		ws := keyquality.Analyze(cert.PublicKey, asset.Algorithm, asset.KeySize)
		if len(ws) > 0 {
			asset.QualityWarnings = keyquality.ToModel(ws)
		}
	}

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
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

// createContainerFinding creates a finding for a crypto container file (JKS, etc.)
// where we detect the file type but can't parse the contents.
func (m *CertificateModule) createContainerFinding(path, containerType string) *model.Finding {
	asset := &model.CryptoAsset{
		ID:        uuid.Must(uuid.NewV7()).String(),
		Function:  containerType + " keystore",
		Algorithm: "Unknown",
		Purpose:   "Certificate/key container",
	}
	crypto.ClassifyCryptoAsset(asset)

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 5,
		Source: model.FindingSource{
			Type: "file",
			Path: path,
		},
		CryptoAsset: asset,
		Confidence:  0.70,
		Module:      "certificates",
		Timestamp:   time.Now(),
	}
}

// buildCertAlgorithmName builds an algorithm name consistent with the PQC registry.
// Produces: RSA-2048, ECDSA-P256, Ed25519, ML-DSA-65, etc.
// For unknown algorithms, falls back to OID extraction from raw DER.
func (m *CertificateModule) buildCertAlgorithmName(cert *x509.Certificate, keySize int) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return fmt.Sprintf("RSA-%d", keySize)
	case x509.ECDSA:
		return fmt.Sprintf("ECDSA-P%d", keySize)
	case x509.Ed25519:
		return "Ed25519"
	default:
		return m.buildPQCAlgorithmName(cert)
	}
}

// buildPQCAlgorithmName extracts algorithm name from DER-encoded certificate OIDs.
// Used when Go's x509 parser returns UnknownPublicKeyAlgorithm (e.g., PQC certs).
func (m *CertificateModule) buildPQCAlgorithmName(cert *x509.Certificate) string {
	// Try public key OID first
	oid := crypto.ExtractPublicKeyOID(cert.Raw)
	if oid != "" {
		if entry, ok := crypto.LookupOID(oid); ok {
			return entry.Algorithm
		}
	}

	// Try signature algorithm OID
	oid = crypto.ExtractSignatureOID(cert.Raw)
	if oid != "" {
		if entry, ok := crypto.LookupOID(oid); ok {
			return entry.Algorithm
		}
	}

	return "Unknown"
}

// detectHybridCert checks if a certificate uses a composite/hybrid algorithm.
// Returns true and the component algorithms if it's a hybrid cert.
func (m *CertificateModule) detectHybridCert(cert *x509.Certificate) (isHybrid bool, components []string) {
	// Check signature algorithm OID
	sigOID := crypto.ExtractSignatureOID(cert.Raw)
	if sigOID != "" && crypto.IsCompositeOID(sigOID) {
		entry, _ := crypto.LookupOID(sigOID)
		components := crypto.CompositeComponents(entry.Algorithm)
		return true, components
	}

	// Check public key algorithm OID
	pkOID := crypto.ExtractPublicKeyOID(cert.Raw)
	if pkOID != "" && crypto.IsCompositeOID(pkOID) {
		entry, _ := crypto.LookupOID(pkOID)
		components := crypto.CompositeComponents(entry.Algorithm)
		return true, components
	}

	return false, nil
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
