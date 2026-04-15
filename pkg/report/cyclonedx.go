package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/crypto"
	"github.com/amiryahaya/triton/pkg/model"
)

// CycloneDX 1.7 CBOM types

// CDXBom is the top-level CycloneDX BOM.
type CDXBom struct {
	BomFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     CDXMetadata    `json:"metadata"`
	Components   []CDXComponent `json:"components"`
}

// CDXMetadata holds BOM metadata.
type CDXMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []CDXTool `json:"tools"`
}

// CDXTool identifies the tool that generated the BOM.
type CDXTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CDXComponent is a CycloneDX component with optional crypto properties.
type CDXComponent struct {
	Type             string               `json:"type"`
	Name             string               `json:"name"`
	BomRef           string               `json:"bom-ref,omitempty"`
	CryptoProperties *CDXCryptoProperties `json:"cryptoProperties,omitempty"`
	Properties       []CDXProperty        `json:"properties,omitempty"`
}

// CDXProperty is a generic name/value property attached to a component.
type CDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CDXCryptoProperties holds cryptographic asset details per CycloneDX 1.7.
type CDXCryptoProperties struct {
	AssetType             string                    `json:"assetType"`
	AlgorithmProperties   *CDXAlgorithmProperties   `json:"algorithmProperties,omitempty"`
	CertificateProperties *CDXCertificateProperties `json:"certificateProperties,omitempty"`
	RelatedCryptoMaterial *CDXRelatedCryptoMaterial `json:"relatedCryptoMaterialProperties,omitempty"`
	ProtocolProperties    *CDXProtocolProperties    `json:"protocolProperties,omitempty"`
	OID                   string                    `json:"oid,omitempty"`
}

// CDXAlgorithmProperties describes an algorithm component.
type CDXAlgorithmProperties struct {
	Primitive                string   `json:"primitive,omitempty"`
	ParameterSetIdentifier   string   `json:"parameterSetIdentifier,omitempty"`
	Mode                     string   `json:"mode,omitempty"`
	ClassicalSecurityLevel   int      `json:"classicalSecurityLevel,omitempty"`
	NISTQuantumSecurityLevel int      `json:"nistQuantumSecurityLevel,omitempty"`
	IsHybrid                 bool     `json:"isHybrid,omitempty"`
	ComponentAlgorithms      []string `json:"componentAlgorithms,omitempty"`
}

// CDXCertificateProperties describes a certificate component.
type CDXCertificateProperties struct {
	SubjectName        string `json:"subjectName,omitempty"`
	IssuerName         string `json:"issuerName,omitempty"`
	NotValidBefore     string `json:"notValidBefore,omitempty"`
	NotValidAfter      string `json:"notValidAfter,omitempty"`
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
}

// CDXRelatedCryptoMaterial describes key material.
type CDXRelatedCryptoMaterial struct {
	Type string `json:"type,omitempty"`
	Size int    `json:"size,omitempty"`
}

// CDXProtocolProperties describes a protocol.
type CDXProtocolProperties struct {
	Type    string `json:"type,omitempty"`
	Version string `json:"version,omitempty"`
}

// GenerateCycloneDXBOM creates a proper CycloneDX 1.7 CBOM JSON file.
func (g *Generator) GenerateCycloneDXBOM(result *model.ScanResult, filename string) error {
	bom := CDXBom{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: "urn:uuid:" + uuid.Must(uuid.NewV7()).String(),
		Version:      1,
		Metadata: CDXMetadata{
			Timestamp: time.Now().Format(time.RFC3339),
			Tools:     []CDXTool{{Name: "triton", Version: version.Version}},
		},
	}

	// Convert findings to CycloneDX components
	bom.Components = make([]CDXComponent, 0, len(result.Findings))
	for i := range result.Findings {
		finding := &result.Findings[i]
		if finding.CryptoAsset == nil {
			continue
		}

		component := findingToComponent(finding)
		bom.Components = append(bom.Components, component)
	}

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling CycloneDX: %w", err)
	}

	return os.WriteFile(filename, data, 0o600)
}

// findingToComponent converts a Triton finding into a CycloneDX component.
func findingToComponent(f *model.Finding) CDXComponent {
	asset := f.CryptoAsset

	comp := CDXComponent{
		Type:   "cryptographic-asset",
		Name:   asset.Algorithm,
		BomRef: asset.ID,
	}

	// Determine asset type and populate properties
	switch categorizeAssetType(f) {
	case "certificate":
		comp.CryptoProperties = &CDXCryptoProperties{
			AssetType: "certificate",
			CertificateProperties: &CDXCertificateProperties{
				SubjectName:        asset.Subject,
				IssuerName:         asset.Issuer,
				NotValidBefore:     formatTimePtr(asset.NotBefore),
				NotValidAfter:      formatTimePtr(asset.NotAfter),
				SignatureAlgorithm: asset.Algorithm,
			},
		}

	case "key":
		comp.CryptoProperties = &CDXCryptoProperties{
			AssetType: "related-crypto-material",
			RelatedCryptoMaterial: &CDXRelatedCryptoMaterial{
				Type: "private-key",
				Size: asset.KeySize,
			},
		}

	case "protocol":
		comp.CryptoProperties = &CDXCryptoProperties{
			AssetType: "protocol",
			ProtocolProperties: &CDXProtocolProperties{
				Type:    deriveProtocolType(asset.Algorithm),
				Version: deriveProtocolVersion(asset.Algorithm),
			},
		}

	default: // algorithm
		paramSet := deriveParameterSet(asset.Algorithm, asset.KeySize)
		if asset.IsHybrid {
			// For hybrid composite assets, use the composite name as the parameter
			// set identifier (per CycloneDX 1.6/1.7 CBOM guidance for hybrids).
			paramSet = asset.Algorithm
		}
		comp.CryptoProperties = &CDXCryptoProperties{
			AssetType: "algorithm",
			AlgorithmProperties: &CDXAlgorithmProperties{
				Primitive:                derivePrimitive(asset.Algorithm, asset.Function),
				ParameterSetIdentifier:   paramSet,
				Mode:                     deriveMode(asset.Algorithm),
				ClassicalSecurityLevel:   asset.KeySize,
				NISTQuantumSecurityLevel: deriveNISTQuantumLevel(asset.Algorithm),
				IsHybrid:                 asset.IsHybrid,
				ComponentAlgorithms:      asset.ComponentAlgorithms,
			},
		}
	}

	// Populate OID: prefer the finding's authoritative OID (e.g. from asn1_oid
	// byte scanner). Fall back to reverse-lookup by algorithm name.
	if comp.CryptoProperties != nil {
		if asset.OID != "" {
			comp.CryptoProperties.OID = asset.OID
		} else if oid := crypto.OIDForAlgorithm(asset.Algorithm); oid != "" {
			comp.CryptoProperties.OID = oid
		}
	}

	// Emit key-material quality warnings as CycloneDX properties. The CycloneDX
	// 1.7 schema in this package does not yet include a vulnerabilities
	// section, so any embedded CVE identifiers are surfaced via a dedicated
	// `triton:quality-warning-cve` property alongside the full warning text.
	// A follow-up PR can graduate these to proper vulnerability refs.
	for _, qw := range asset.QualityWarnings {
		formatted := fmt.Sprintf("[%s] %s: %s", qw.Severity, qw.Code, qw.Message)
		if qw.CVE != "" {
			formatted += " [" + qw.CVE + "]"
		}
		comp.Properties = append(comp.Properties, CDXProperty{
			Name:  "triton:quality-warning",
			Value: formatted,
		})
		if qw.CVE != "" {
			comp.Properties = append(comp.Properties, CDXProperty{
				Name:  "triton:quality-warning-cve",
				Value: qw.CVE,
			})
		}
	}

	return comp
}

// categorizeAssetType determines the CycloneDX asset type from a finding.
func categorizeAssetType(f *model.Finding) string {
	asset := f.CryptoAsset

	// Certificate findings
	if f.Module == "certificates" && asset.Subject != "" {
		return "certificate"
	}

	// Key findings
	if f.Module == "keys" {
		return "key"
	}

	// Protocol findings
	if f.Module == "protocol" || f.Module == "network" {
		alg := strings.ToUpper(asset.Algorithm)
		if strings.Contains(alg, "TLS") || strings.Contains(alg, "SSL") ||
			strings.Contains(alg, "SSH") || strings.Contains(alg, "QUIC") {
			return "protocol"
		}
	}

	return "algorithm"
}

// derivePrimitive maps algorithm name to CycloneDX primitive type.
func derivePrimitive(algorithm, _ string) string {
	alg := strings.ToUpper(algorithm)

	switch {
	// HMAC/MAC must be checked before hash (HMAC-SHA256 contains "SHA")
	case strings.Contains(alg, "HMAC") || strings.Contains(alg, "CMAC"):
		return "mac"

	// Authenticated encryption (check before block-cipher)
	case strings.Contains(alg, "CHACHA20") || strings.Contains(alg, "POLY1305"):
		return "ae"

	case strings.Contains(alg, "AES") || strings.Contains(alg, "CAMELLIA") ||
		strings.Contains(alg, "3DES") || strings.Contains(alg, "DES"):
		if strings.Contains(alg, "GCM") || strings.Contains(alg, "CCM") {
			return "ae"
		}
		return "block-cipher"

	case strings.Contains(alg, "SHA") || strings.Contains(alg, "BLAKE") ||
		strings.Contains(alg, "MD5") || strings.Contains(alg, "MD4"):
		return "hash"

	case strings.Contains(alg, "RSA") || strings.Contains(alg, "ECDSA") ||
		strings.Contains(alg, "ED25519") || strings.Contains(alg, "ED448") ||
		strings.Contains(alg, "ML-DSA") || strings.Contains(alg, "SLH-DSA") ||
		strings.Contains(alg, "FN-DSA") || strings.Contains(alg, "DSA"):
		return "signature"

	case strings.Contains(alg, "ML-KEM") || strings.Contains(alg, "ECDH") ||
		strings.Contains(alg, "X25519") || strings.Contains(alg, "X448") ||
		strings.Contains(alg, "DH"):
		return "kem"

	case strings.Contains(alg, "ARGON") || strings.Contains(alg, "SCRYPT") ||
		strings.Contains(alg, "BCRYPT") || strings.Contains(alg, "PBKDF") ||
		strings.Contains(alg, "HKDF"):
		return "kdf"

	default:
		return "unknown"
	}
}

// deriveParameterSet returns the parameter set identifier.
func deriveParameterSet(algorithm string, keySize int) string {
	if keySize > 0 {
		return fmt.Sprintf("%d", keySize)
	}
	// Try to extract from algorithm name (e.g., ML-DSA-44 → "44")
	parts := strings.Split(algorithm, "-")
	if len(parts) >= 3 {
		return parts[len(parts)-1]
	}
	return ""
}

// deriveMode extracts the cipher mode from algorithm name.
func deriveMode(algorithm string) string {
	alg := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(alg, "GCM"):
		return "gcm"
	case strings.Contains(alg, "CBC"):
		return "cbc"
	case strings.Contains(alg, "CTR"):
		return "ctr"
	case strings.Contains(alg, "CCM"):
		return "ccm"
	default:
		return ""
	}
}

// deriveNISTQuantumLevel maps algorithms to NIST quantum security levels (1-5).
func deriveNISTQuantumLevel(algorithm string) int {
	alg := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(alg, "ML-KEM-512") || strings.Contains(alg, "ML-DSA-44") || strings.Contains(alg, "FN-DSA-512"):
		return 1
	case strings.Contains(alg, "ML-KEM-768") || strings.Contains(alg, "ML-DSA-65"):
		return 3
	case strings.Contains(alg, "ML-KEM-1024") || strings.Contains(alg, "ML-DSA-87") || strings.Contains(alg, "FN-DSA-1024"):
		return 5
	case strings.Contains(alg, "SLH-DSA-128") || strings.Contains(alg, "SLH-DSA-SHA2-128") || strings.Contains(alg, "SLH-DSA-SHAKE-128"):
		return 1
	case strings.Contains(alg, "SLH-DSA-192") || strings.Contains(alg, "SLH-DSA-SHA2-192") || strings.Contains(alg, "SLH-DSA-SHAKE-192"):
		return 3
	case strings.Contains(alg, "SLH-DSA-256") || strings.Contains(alg, "SLH-DSA-SHA2-256") || strings.Contains(alg, "SLH-DSA-SHAKE-256"):
		return 5
	case strings.Contains(alg, "AES-256"):
		return 5 // 256-bit symmetric → NIST Level 5 equivalent post-quantum security
	case strings.Contains(alg, "AES-192"):
		return 3 // 192-bit symmetric → NIST Level 3 equivalent
	case strings.Contains(alg, "AES-128"):
		return 1 // 128-bit symmetric → NIST Level 1 equivalent
	default:
		return 0
	}
}

// deriveProtocolType maps protocol names to CycloneDX protocol types.
func deriveProtocolType(algorithm string) string {
	alg := strings.ToUpper(algorithm)
	switch {
	case strings.Contains(alg, "TLS"):
		return "tls"
	case strings.Contains(alg, "SSL"):
		return "ssl"
	case strings.Contains(alg, "SSH"):
		return "ssh"
	case strings.Contains(alg, "QUIC"):
		return "quic"
	case strings.Contains(alg, "IPSEC"):
		return "ipsec"
	default:
		return "unknown"
	}
}

// deriveProtocolVersion extracts version from protocol name.
func deriveProtocolVersion(algorithm string) string {
	alg := algorithm
	switch {
	case strings.Contains(alg, "1.3"):
		return "1.3"
	case strings.Contains(alg, "1.2"):
		return "1.2"
	case strings.Contains(alg, "1.1"):
		return "1.1"
	case strings.Contains(alg, "1.0"):
		return "1.0"
	case strings.Contains(alg, "2.0"):
		return "2.0"
	case strings.Contains(alg, "3.0"):
		return "3.0"
	default:
		return ""
	}
}

// formatTimePtr formats a time pointer to RFC3339, returns empty string for nil.
func formatTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}
