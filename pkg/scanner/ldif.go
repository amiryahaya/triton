package scanner

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
)

// certAttributeNames lists LDIF attribute names that carry base64-encoded
// DER X.509 certificates (double-colon suffix = base64 in RFC 2849).
var certAttributeNames = []string{
	"userCertificate",
	"cACertificate",
	"userSMIMECertificate",
	"crossCertificatePair",
}

// LDIFModule parses .ldif files and extracts X.509 certificates embedded
// as base64-encoded DER values in LDAP directory entries.
type LDIFModule struct {
	config      *scannerconfig.Config
	reader      fsadapter.FileReader
	lastScanned int64
	lastMatched int64
}

// NewLDIFModule creates an LDIFModule with the given scanner configuration.
func NewLDIFModule(cfg *scannerconfig.Config) *LDIFModule {
	return &LDIFModule{config: cfg}
}

func (m *LDIFModule) Name() string                         { return "ldif" }
func (m *LDIFModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *LDIFModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *LDIFModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

// FileStats returns atomic counters tracking files visited and matched.
func (m *LDIFModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target filesystem looking for .ldif files and extracts
// certificates from all recognised certificate attributes.
func (m *LDIFModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isLDIFFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		reader:       m.reader,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			return m.processLDIF(ctx, reader, path, findings)
		},
	})
}

// isLDIFFile returns true for files with the .ldif extension.
func isLDIFFile(path string) bool {
	return strings.ToLower(filepath.Ext(path)) == ".ldif"
}

// processLDIF reads a single .ldif file and emits a finding for every
// parseable X.509 certificate it contains.
func (m *LDIFModule) processLDIF(ctx context.Context, reader fsadapter.FileReader, path string, findings chan<- *model.Finding) error {
	data, err := reader.ReadFile(ctx, path)
	if err != nil {
		return nil // skip unreadable files
	}

	certs := parseLDIFCerts(data)
	for _, ec := range certs {
		finding := m.buildFinding(path, ec.dn, ec.cert)
		select {
		case findings <- finding:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// entryCert associates a parsed certificate with its LDAP entry DN.
type entryCert struct {
	dn   string
	cert *x509.Certificate
}

// parseLDIFCerts implements a line-by-line RFC 2849 parser.
// It handles:
//   - dn: lines to track the current entry
//   - double-colon attributes (base64-encoded values)
//   - folded lines (continuation lines that begin with a single space)
//   - multiple certificate attributes per entry
//
// Bad base64 or unparseable certificates are silently skipped (fail-open).
func parseLDIFCerts(data []byte) []entryCert {
	var results []entryCert

	currentDN := ""
	// currentAttr is the name of the active cert attribute ("" = none).
	currentAttr := ""
	// currentValue accumulates the folded base64 value lines.
	var currentValue strings.Builder

	flushAttr := func() {
		if currentAttr == "" {
			return
		}
		b64 := strings.TrimSpace(currentValue.String())
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			// Try RawStdEncoding (no padding)
			der, err = base64.RawStdEncoding.DecodeString(b64)
			if err != nil {
				currentAttr = ""
				currentValue.Reset()
				return
			}
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			currentAttr = ""
			currentValue.Reset()
			return
		}
		results = append(results, entryCert{dn: currentDN, cert: cert})
		currentAttr = ""
		currentValue.Reset()
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()

		// Continuation line (RFC 2849 §3 "folding")
		if line != "" && line[0] == ' ' {
			if currentAttr != "" {
				currentValue.WriteString(strings.TrimPrefix(line, " "))
			}
			continue
		}

		// Any non-continuation line ends the current attribute.
		flushAttr()

		// Blank line separates entries; reset DN tracking.
		if strings.TrimSpace(line) == "" {
			currentDN = ""
			continue
		}

		// dn: <value>  — track entry DN.
		if strings.HasPrefix(line, "dn: ") {
			currentDN = strings.TrimPrefix(line, "dn: ")
			continue
		}

		// Check for a recognised certificate attribute with double-colon.
		if attr, value, ok := extractCertAttribute(line); ok {
			currentAttr = attr
			currentValue.Reset()
			currentValue.WriteString(value)
		}
	}

	// Flush any trailing attribute.
	flushAttr()

	return results
}

// extractCertAttribute checks whether line is a base64-encoded certificate
// attribute (double-colon syntax). Returns (attrName, base64Value, true) on
// match; otherwise ("", "", false).
func extractCertAttribute(line string) (attr, value string, ok bool) {
	// Double-colon separator required for base64 (RFC 2849 §2).
	idx := strings.Index(line, ":: ")
	if idx < 0 {
		return "", "", false
	}
	name := line[:idx]
	// Strip optional attribute options (e.g. "userCertificate;binary").
	if semi := strings.IndexByte(name, ';'); semi >= 0 {
		name = name[:semi]
	}
	for _, certAttr := range certAttributeNames {
		if strings.EqualFold(name, certAttr) {
			return certAttr, line[idx+3:], true
		}
	}
	return "", "", false
}

// buildFinding constructs a model.Finding for an X.509 certificate found
// inside an LDIF file.
func (m *LDIFModule) buildFinding(path, dn string, cert *x509.Certificate) *model.Finding {
	algoName, keySize := certPublicKeyInfo(cert)

	notBefore := cert.NotBefore
	notAfter := cert.NotAfter

	asset := &model.CryptoAsset{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Function:     "Certificate (LDIF)",
		Algorithm:    algoName,
		KeySize:      keySize,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    &notBefore,
		NotAfter:     &notAfter,
		IsCA:         cert.IsCA,
		Purpose:      fmt.Sprintf("Certificate from LDAP entry %s", dn),
	}
	crypto.ClassifyCryptoAsset(asset)

	return &model.Finding{
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 5,
		Source: model.FindingSource{
			Type:     "file",
			Path:     path,
			Evidence: fmt.Sprintf("ldif:%s", dn),
		},
		CryptoAsset: asset,
		Confidence:  0.95,
		Module:      "ldif",
		Timestamp:   time.Now(),
	}
}
