package scanner

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/store"
)

// XMLDSigModule scans XML files for XML Digital Signature
// (xmldsig-core) elements and extracts the signing + digest
// algorithms. Primary use case: SAML IdP/SP metadata exchange
// files used by enterprise SSO, where signature algorithm choice
// is a direct PQC migration concern.
//
// This module is intentionally a pattern-matcher, not a full DOM
// parser — xmldsig-core uses fixed algorithm URIs that are
// trivially regex-able, and avoiding an XML parser keeps the
// binary small and the scanner fast on large metadata blobs.
type XMLDSigModule struct {
	config      *scannerconfig.Config
	store       store.Store
	lastScanned int64
	lastMatched int64
}

func NewXMLDSigModule(cfg *scannerconfig.Config) *XMLDSigModule {
	return &XMLDSigModule{config: cfg}
}

func (m *XMLDSigModule) Name() string                         { return "xml_dsig" }
func (m *XMLDSigModule) Category() model.ModuleCategory       { return model.CategoryPassiveFile }
func (m *XMLDSigModule) ScanTargetType() model.ScanTargetType { return model.TargetFilesystem }
func (m *XMLDSigModule) SetStore(s store.Store)               { m.store = s }

func (m *XMLDSigModule) FileStats() (scanned, matched int64) {
	return atomic.LoadInt64(&m.lastScanned), atomic.LoadInt64(&m.lastMatched)
}

func (m *XMLDSigModule) Scan(ctx context.Context, target model.ScanTarget, findings chan<- *model.Finding) error {
	if ctx == nil {
		ctx = context.Background()
	}
	atomic.StoreInt64(&m.lastScanned, 0)
	atomic.StoreInt64(&m.lastMatched, 0)
	return walkTarget(walkerConfig{
		ctx:          ctx,
		target:       target,
		config:       m.config,
		matchFile:    isXMLDSigCandidate,
		filesScanned: &m.lastScanned,
		filesMatched: &m.lastMatched,
		store:        m.store,
		processFile: func(path string) error {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, f := range m.parseXMLDSig(path, data) {
				if f == nil {
					continue
				}
				select {
				case findings <- f:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		},
	})
}

// isXMLDSigCandidate is path-based. We look in directories where
// SAML metadata and other signed XML commonly live. A purely
// extension-based match (any .xml) would be too noisy — most
// .xml files on a Linux host are unrelated to digital signatures.
func isXMLDSigCandidate(path string) bool {
	lower := strings.ToLower(path)
	base := strings.ToLower(filepath.Base(path))
	if !strings.HasSuffix(base, ".xml") {
		return false
	}
	// SAML / Shibboleth / IdP metadata layout.
	for _, marker := range []string{"/shibboleth/", "/saml/", "/idp/", "/sp/", "/metadata"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// Generic "signed-config" or "signed-" prefix inside any
	// config dir. Low-volume, high-value.
	if strings.Contains(base, "signed") {
		return true
	}
	return false
}

// xmlSigMethodRE captures xmldsig <SignatureMethod Algorithm="…"/>
// URIs. The attribute value is an IANA URI like
// http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 — we use the
// final path segment after `#` as the algorithm key.
var xmlSigMethodRE = regexp.MustCompile(`<\s*(?:[a-zA-Z][a-zA-Z0-9]*:)?SignatureMethod\s+Algorithm\s*=\s*"([^"]+)"`)

// xmlDigestMethodRE does the same for DigestMethod.
var xmlDigestMethodRE = regexp.MustCompile(`<\s*(?:[a-zA-Z][a-zA-Z0-9]*:)?DigestMethod\s+Algorithm\s*=\s*"([^"]+)"`)

// xmlDSigAlgoMap normalizes the URI path suffix to a canonical
// algorithm display name. Includes the weak legacy ones so they
// surface as findings.
var xmlDSigAlgoMap = map[string]string{
	"rsa-sha1":     "RSA-SHA1",
	"rsa-sha256":   "RSA-SHA256",
	"rsa-sha384":   "RSA-SHA384",
	"rsa-sha512":   "RSA-SHA512",
	"dsa-sha1":     "DSA-SHA1",
	"dsa-sha256":   "DSA-SHA256",
	"ecdsa-sha1":   "ECDSA-SHA1",
	"ecdsa-sha256": "ECDSA-SHA256",
	"ecdsa-sha384": "ECDSA-SHA384",
	"ecdsa-sha512": "ECDSA-SHA512",
	"hmac-sha1":    "HMAC-SHA1",
	"hmac-sha256":  "HMAC-SHA256",
	"hmac-sha384":  "HMAC-SHA384",
	"hmac-sha512":  "HMAC-SHA512",
	"sha1":         "SHA-1",
	"sha256":       "SHA-256",
	"sha384":       "SHA-384",
	"sha512":       "SHA-512",
	"md5":          "MD5",
	"rsa-md5":      "RSA-MD5",
}

// parseXMLDSig walks the file for signature and digest method
// URIs and emits one finding per unique algorithm found. Files
// that contain no signature element at all produce zero findings
// (we don't want to alarm on vanilla XML config files).
func (m *XMLDSigModule) parseXMLDSig(path string, data []byte) []*model.Finding {
	var out []*model.Finding
	seen := make(map[string]bool)

	extract := func(re *regexp.Regexp, function string) {
		matches := re.FindAllSubmatch(data, -1)
		for _, match := range matches {
			uri := string(match[1])
			// Take the trailing token after `#` or `/`.
			key := uri
			if i := strings.LastIndexByte(uri, '#'); i >= 0 {
				key = uri[i+1:]
			} else if i := strings.LastIndexByte(uri, '/'); i >= 0 {
				key = uri[i+1:]
			}
			key = strings.ToLower(key)
			display, ok := xmlDSigAlgoMap[key]
			if !ok {
				display = "xmldsig-" + key
			}
			dedup := function + ":" + display
			if seen[dedup] {
				continue
			}
			seen[dedup] = true
			asset := &model.CryptoAsset{
				ID:        uuid.Must(uuid.NewV7()).String(),
				Function:  function,
				Algorithm: display,
				Purpose:   "XML signature in " + filepath.Base(path) + " (" + uri + ")",
			}
			crypto.ClassifyCryptoAsset(asset)
			asset.Algorithm = display
			out = append(out, &model.Finding{
				ID:       uuid.Must(uuid.NewV7()).String(),
				Category: CategoryConfig,
				Source: model.FindingSource{
					Type:            "file",
					Path:            path,
					DetectionMethod: "configuration",
				},
				CryptoAsset: asset,
				Confidence:  ConfidenceHigh,
				Module:      "xml_dsig",
				Timestamp:   time.Now(),
			})
		}
	}

	extract(xmlSigMethodRE, "XML signature algorithm")
	extract(xmlDigestMethodRE, "XML signature digest")
	return out
}
