package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
	"github.com/amiryahaya/triton/pkg/store"
)

const (
	archiveMaxEntrySize    = 50 * 1024 * 1024  // 50MB per entry
	archiveMaxTotalExtract = 256 * 1024 * 1024 // 256MB total per archive
	archiveMaxEntries      = 10_000            // zip bomb protection
	archiveMaxNestDepth    = 2                 // WAR→JAR→cert
)

// ArchiveModule scans inside JAR/WAR/EAR/ZIP/TAR archives for certificates
// and keys, with 2-level nesting support and zip bomb protection.
type ArchiveModule struct {
	config      *scannerconfig.Config
	lastScanned int64
	lastMatched int64
	store       store.Store
	reader      fsadapter.FileReader
}

// NewArchiveModule creates a new ArchiveModule.
func NewArchiveModule(cfg *scannerconfig.Config) *ArchiveModule {
	return &ArchiveModule{config: cfg}
}

func (m *ArchiveModule) Name() string                         { return "archive" }
func (m *ArchiveModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *ArchiveModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *ArchiveModule) SetStore(s store.Store)               { m.store = s }
func (m *ArchiveModule) SetFileReader(r fsadapter.FileReader) { m.reader = r }

// FileStats returns the number of files scanned and matched.
func (m *ArchiveModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

// Scan walks the target filesystem and scans all archive files for crypto assets.
func (m *ArchiveModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isArchiveFile,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		reader:       m.reader,
		processFile: func(ctx context.Context, reader fsadapter.FileReader, path string) error {
			data, err := reader.ReadFile(ctx, path)
			if err != nil {
				return nil
			}
			return m.scanArchive(ctx, data, path, 1, findings)
		},
	})
}

// isArchiveFile reports whether the path looks like a supported archive.
func isArchiveFile(path string) bool {
	lower := strings.ToLower(path)
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".jar" || ext == ".war" || ext == ".ear" ||
		ext == ".zip" || ext == ".tar" ||
		strings.HasSuffix(lower, ".tar.gz") || ext == ".tgz" ||
		strings.HasSuffix(lower, ".tar.bz2")
}

// isCryptoFile reports whether the file extension indicates a crypto artifact.
func isCryptoFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".pem", ".crt", ".cer", ".der", ".p7b", ".p7c",
		".p12", ".pfx", ".jks", ".jceks", ".bks", ".uber",
		".keystore", ".truststore",
		".key", ".priv", ".pub":
		return true
	}
	return false
}

// scanArchive dispatches to the appropriate format handler based on the archive path.
func (m *ArchiveModule) scanArchive(ctx context.Context, data []byte, archivePath string, depth int, findings chan<- *model.Finding) error {
	lower := strings.ToLower(archivePath)
	ext := strings.ToLower(filepath.Ext(archivePath))

	if ext == ".jar" || ext == ".war" || ext == ".ear" || ext == ".zip" {
		return m.scanZip(ctx, data, archivePath, depth, findings)
	}
	if strings.HasSuffix(lower, ".tar.gz") || ext == ".tgz" {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil
		}
		defer gr.Close()
		tarData, err := io.ReadAll(io.LimitReader(gr, archiveMaxTotalExtract))
		if err != nil {
			return nil
		}
		return m.scanTar(ctx, tarData, archivePath, depth, findings)
	}
	if strings.HasSuffix(lower, ".tar.bz2") {
		br := bzip2.NewReader(bytes.NewReader(data))
		tarData, err := io.ReadAll(io.LimitReader(br, archiveMaxTotalExtract))
		if err != nil {
			return nil
		}
		return m.scanTar(ctx, tarData, archivePath, depth, findings)
	}
	if ext == ".tar" {
		return m.scanTar(ctx, data, archivePath, depth, findings)
	}
	return nil
}

// scanZip scans a ZIP-format archive (JAR/WAR/EAR/ZIP).
func (m *ArchiveModule) scanZip(ctx context.Context, data []byte, archivePath string, depth int, findings chan<- *model.Finding) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var totalExtracted int64
	for i, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return err
		}
		if i >= archiveMaxEntries {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if int64(f.UncompressedSize64) > archiveMaxEntrySize {
			continue
		}
		if totalExtracted+int64(f.UncompressedSize64) > archiveMaxTotalExtract {
			break
		}
		entryPath := archivePath + "!/" + f.Name

		if depth < archiveMaxNestDepth && isArchiveFile(f.Name) {
			entryData, err := readZipEntry(f, archiveMaxEntrySize)
			if err != nil {
				continue
			}
			totalExtracted += int64(len(entryData))
			_ = m.scanArchive(ctx, entryData, entryPath, depth+1, findings)
			continue
		}
		if !isCryptoFile(f.Name) {
			continue
		}
		entryData, err := readZipEntry(f, archiveMaxEntrySize)
		if err != nil {
			continue
		}
		totalExtracted += int64(len(entryData))
		m.processExtractedFile(ctx, entryData, entryPath, findings)
	}
	return nil
}

// scanTar scans a TAR archive (plain, gzip, or bzip2 already decompressed).
func (m *ArchiveModule) scanTar(ctx context.Context, data []byte, archivePath string, depth int, findings chan<- *model.Finding) error {
	tr := tar.NewReader(bytes.NewReader(data))
	var totalExtracted int64
	var entryCount int
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		entryCount++
		if entryCount > archiveMaxEntries {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size > archiveMaxEntrySize {
			continue
		}
		if totalExtracted+hdr.Size > archiveMaxTotalExtract {
			break
		}
		entryPath := archivePath + "!/" + hdr.Name
		entryData, err := io.ReadAll(io.LimitReader(tr, archiveMaxEntrySize))
		if err != nil {
			continue
		}
		totalExtracted += int64(len(entryData))
		if depth < archiveMaxNestDepth && isArchiveFile(hdr.Name) {
			_ = m.scanArchive(ctx, entryData, entryPath, depth+1, findings)
			continue
		}
		if !isCryptoFile(hdr.Name) {
			continue
		}
		m.processExtractedFile(ctx, entryData, entryPath, findings)
	}
	return nil
}

// processExtractedFile attempts to parse certs or keys from the extracted bytes.
func (m *ArchiveModule) processExtractedFile(ctx context.Context, data []byte, entryPath string, findings chan<- *model.Finding) {
	certs := m.parseCertsFromBytes(data)
	for _, cert := range certs {
		finding := m.createCertFinding(entryPath, cert)
		select {
		case findings <- finding:
		case <-ctx.Done():
			return
		}
	}
	if len(certs) == 0 {
		if finding := m.parseKeyFromBytes(data, entryPath); finding != nil {
			select {
			case findings <- finding:
			case <-ctx.Done():
				return
			}
		}
	}
}

// parseCertsFromBytes attempts PEM and DER certificate parsing.
func (m *ArchiveModule) parseCertsFromBytes(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	if bytes.Contains(data, []byte("BEGIN CERTIFICATE")) {
		rest := data
		for len(rest) > 0 {
			block, r := pem.Decode(rest)
			rest = r
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					certs = append(certs, cert)
				}
			}
		}
	}
	if len(certs) == 0 {
		cert, err := x509.ParseCertificate(data)
		if err == nil {
			certs = append(certs, cert)
		}
	}
	return certs
}

// parseKeyFromBytes checks for PEM key headers and returns a Finding if found.
func (m *ArchiveModule) parseKeyFromBytes(data []byte, path string) *model.Finding {
	content := string(data)
	for _, h := range keyPEMHeaders {
		if strings.Contains(content, h.header) {
			asset := &model.CryptoAsset{
				ID:        uuid.Must(uuid.NewV7()).String(),
				Function:  h.keyType,
				Algorithm: h.algorithm,
			}
			crypto.ClassifyCryptoAsset(asset)
			return &model.Finding{
				ID:       uuid.Must(uuid.NewV7()).String(),
				Category: 5,
				Source:   model.FindingSource{Type: "file", Path: path},
				CryptoAsset: asset,
				Confidence:  0.85,
				Module:      "archive",
				Timestamp:   time.Now(),
			}
		}
	}
	return nil
}

// createCertFinding creates a Finding for an X.509 certificate.
func (m *ArchiveModule) createCertFinding(path string, cert *x509.Certificate) *model.Finding {
	algoName, keySize := certPublicKeyInfo(cert)
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	asset := &model.CryptoAsset{
		ID:           uuid.Must(uuid.NewV7()).String(),
		Function:     "Certificate authentication",
		Algorithm:    algoName,
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
		ID:       uuid.Must(uuid.NewV7()).String(),
		Category: 5,
		Source:   model.FindingSource{Type: "file", Path: path},
		CryptoAsset: asset,
		Confidence:  0.90,
		Module:      "archive",
		Timestamp:   time.Now(),
	}
}

// readZipEntry reads a single ZIP entry, bounded by maxSize.
func readZipEntry(f *zip.File, maxSize int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, maxSize))
}
