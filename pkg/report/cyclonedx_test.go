package report

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func TestGenerateCycloneDXBOM_ValidJSON(t *testing.T) {
	tmpFile := t.TempDir() + "/test.cdx.json"
	g := New("")

	now := time.Now()
	result := &model.ScanResult{
		ID: "test-scan",
		Findings: []model.Finding{
			{
				ID:       "f1",
				Category: 5,
				Module:   "certificates",
				Source:   model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
				CryptoAsset: &model.CryptoAsset{
					ID:        "a1",
					Algorithm: "RSA-2048",
					KeySize:   2048,
					Function:  "Certificate authentication",
					Subject:   "CN=test",
					Issuer:    "CN=test-ca",
					NotBefore: &now,
					NotAfter:  &now,
				},
			},
			{
				ID:       "f2",
				Category: 3,
				Module:   "keys",
				Source:   model.FindingSource{Type: "file", Path: "/etc/ssl/key.pem"},
				CryptoAsset: &model.CryptoAsset{
					ID:        "a2",
					Algorithm: "RSA-2048",
					KeySize:   2048,
					Function:  "Private key",
				},
			},
			{
				ID:       "f3",
				Category: 1,
				Module:   "protocol",
				Source:   model.FindingSource{Type: "network", Endpoint: "localhost:443"},
				CryptoAsset: &model.CryptoAsset{
					ID:        "a3",
					Algorithm: "TLS 1.3",
					Function:  "TLS connection",
				},
			},
			{
				ID:       "f4",
				Category: 8,
				Module:   "configs",
				Source:   model.FindingSource{Type: "file", Path: "/etc/ssh/sshd_config"},
				CryptoAsset: &model.CryptoAsset{
					ID:        "a4",
					Algorithm: "AES-256-GCM",
					KeySize:   256,
					Function:  "Symmetric encryption",
				},
			},
		},
	}

	err := g.GenerateCycloneDXBOM(result, tmpFile)
	require.NoError(t, err)

	// Read and parse the output
	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	var bom CDXBom
	err = json.Unmarshal(data, &bom)
	require.NoError(t, err)

	// Verify top-level fields
	assert.Equal(t, "CycloneDX", bom.BomFormat)
	assert.Equal(t, "1.7", bom.SpecVersion)
	assert.Contains(t, bom.SerialNumber, "urn:uuid:")
	assert.Equal(t, 1, bom.Version)
	assert.Equal(t, "triton", bom.Metadata.Tools[0].Name)

	// Verify components
	assert.Len(t, bom.Components, 4)

	// Certificate component
	certComp := bom.Components[0]
	assert.Equal(t, "cryptographic-asset", certComp.Type)
	assert.Equal(t, "RSA-2048", certComp.Name)
	require.NotNil(t, certComp.CryptoProperties)
	assert.Equal(t, "certificate", certComp.CryptoProperties.AssetType)
	require.NotNil(t, certComp.CryptoProperties.CertificateProperties)
	assert.Equal(t, "CN=test", certComp.CryptoProperties.CertificateProperties.SubjectName)

	// Key component
	keyComp := bom.Components[1]
	assert.Equal(t, "related-crypto-material", keyComp.CryptoProperties.AssetType)
	require.NotNil(t, keyComp.CryptoProperties.RelatedCryptoMaterial)
	assert.Equal(t, 2048, keyComp.CryptoProperties.RelatedCryptoMaterial.Size)

	// Protocol component
	protoComp := bom.Components[2]
	assert.Equal(t, "protocol", protoComp.CryptoProperties.AssetType)
	require.NotNil(t, protoComp.CryptoProperties.ProtocolProperties)
	assert.Equal(t, "tls", protoComp.CryptoProperties.ProtocolProperties.Type)
	assert.Equal(t, "1.3", protoComp.CryptoProperties.ProtocolProperties.Version)

	// Algorithm component
	algoComp := bom.Components[3]
	assert.Equal(t, "algorithm", algoComp.CryptoProperties.AssetType)
	require.NotNil(t, algoComp.CryptoProperties.AlgorithmProperties)
	assert.Equal(t, "ae", algoComp.CryptoProperties.AlgorithmProperties.Primitive)
	assert.Equal(t, "gcm", algoComp.CryptoProperties.AlgorithmProperties.Mode)
	assert.Equal(t, 256, algoComp.CryptoProperties.AlgorithmProperties.ClassicalSecurityLevel)
}

func TestGenerateCycloneDXBOM_EmptyResult(t *testing.T) {
	tmpFile := t.TempDir() + "/empty.cdx.json"
	g := New("")
	result := &model.ScanResult{}

	err := g.GenerateCycloneDXBOM(result, tmpFile)
	require.NoError(t, err)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	var bom CDXBom
	err = json.Unmarshal(data, &bom)
	require.NoError(t, err)

	assert.Equal(t, "CycloneDX", bom.BomFormat)
	assert.NotNil(t, bom.Components)
	assert.Empty(t, bom.Components)
}

func TestGenerateCycloneDXBOM_NilCryptoAsset(t *testing.T) {
	tmpFile := t.TempDir() + "/nil-asset.cdx.json"
	g := New("")
	result := &model.ScanResult{
		Findings: []model.Finding{
			{
				ID:          "f1",
				Module:      "configs",
				CryptoAsset: nil, // nil CryptoAsset should be skipped
			},
			{
				ID:     "f2",
				Module: "configs",
				CryptoAsset: &model.CryptoAsset{
					ID:        "a1",
					Algorithm: "AES-256-GCM",
					KeySize:   256,
					Function:  "Symmetric encryption",
				},
			},
		},
	}

	err := g.GenerateCycloneDXBOM(result, tmpFile)
	require.NoError(t, err)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	var bom CDXBom
	err = json.Unmarshal(data, &bom)
	require.NoError(t, err)

	assert.Len(t, bom.Components, 1)
	assert.Equal(t, "AES-256-GCM", bom.Components[0].Name)
}

func TestGenerateCycloneDXBOM_PQCAlgorithms(t *testing.T) {
	tmpFile := t.TempDir() + "/pqc.cdx.json"
	g := New("")
	result := &model.ScanResult{
		Findings: []model.Finding{
			{
				ID:     "f1",
				Module: "certificates",
				CryptoAsset: &model.CryptoAsset{
					ID:        "a1",
					Algorithm: "ML-KEM-1024",
					Function:  "Key encapsulation",
				},
			},
			{
				ID:     "f2",
				Module: "certificates",
				CryptoAsset: &model.CryptoAsset{
					ID:        "a2",
					Algorithm: "ML-DSA-87",
					Function:  "Digital signature",
				},
			},
		},
	}

	err := g.GenerateCycloneDXBOM(result, tmpFile)
	require.NoError(t, err)

	data, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	var bom CDXBom
	err = json.Unmarshal(data, &bom)
	require.NoError(t, err)

	assert.Len(t, bom.Components, 2)
	assert.Equal(t, "ML-KEM-1024", bom.Components[0].Name)
	assert.Equal(t, "ML-DSA-87", bom.Components[1].Name)
}

func TestDeriveNISTQuantumLevel_AES(t *testing.T) {
	assert.Equal(t, 5, deriveNISTQuantumLevel("AES-256-GCM"))
	assert.Equal(t, 3, deriveNISTQuantumLevel("AES-192-CBC"))
	assert.Equal(t, 1, deriveNISTQuantumLevel("AES-128-GCM"))
}

func TestDerivePrimitive(t *testing.T) {
	tests := []struct {
		algo     string
		function string
		want     string
	}{
		{"AES-256-GCM", "", "ae"},
		{"AES-256-CBC", "", "block-cipher"},
		{"SHA-256", "", "hash"},
		{"HMAC-SHA256", "", "mac"},
		{"RSA-2048", "", "signature"},
		{"ML-KEM-768", "", "kem"},
		{"ECDSA-P256", "", "signature"},
		{"X25519", "", "kem"},
		{"Argon2", "", "kdf"},
		{"ChaCha20-Poly1305", "", "ae"},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			assert.Equal(t, tt.want, derivePrimitive(tt.algo, tt.function))
		})
	}
}

func TestDeriveMode(t *testing.T) {
	assert.Equal(t, "gcm", deriveMode("AES-256-GCM"))
	assert.Equal(t, "cbc", deriveMode("AES-128-CBC"))
	assert.Equal(t, "ctr", deriveMode("AES-256-CTR"))
	assert.Equal(t, "", deriveMode("RSA-2048"))
}

func TestFindingToComponent_OIDPopulation(t *testing.T) {
	// ML-KEM-768 has an OID in the registry — should be populated
	f := &model.Finding{
		Module: "configs",
		CryptoAsset: &model.CryptoAsset{
			ID:        "a1",
			Algorithm: "ML-KEM-768",
			Function:  "Key encapsulation",
		},
	}
	comp := findingToComponent(f)
	require.NotNil(t, comp.CryptoProperties)
	assert.Equal(t, "2.16.840.1.101.3.4.4.2", comp.CryptoProperties.OID, "ML-KEM-768 should have OID populated")

	// AES-256-GCM has no OID — should be empty
	f2 := &model.Finding{
		Module: "configs",
		CryptoAsset: &model.CryptoAsset{
			ID:        "a2",
			Algorithm: "AES-256-GCM",
			KeySize:   256,
			Function:  "Symmetric encryption",
		},
	}
	comp2 := findingToComponent(f2)
	require.NotNil(t, comp2.CryptoProperties)
	assert.Equal(t, "", comp2.CryptoProperties.OID, "AES-256-GCM has no OID")
}

func TestFindingToComponent_AES256NISTLevel(t *testing.T) {
	f := &model.Finding{
		Module: "configs",
		CryptoAsset: &model.CryptoAsset{
			ID:        "a1",
			Algorithm: "AES-256-GCM",
			KeySize:   256,
			Function:  "Symmetric encryption",
		},
	}
	comp := findingToComponent(f)
	require.NotNil(t, comp.CryptoProperties)
	require.NotNil(t, comp.CryptoProperties.AlgorithmProperties)
	assert.Equal(t, 5, comp.CryptoProperties.AlgorithmProperties.NISTQuantumSecurityLevel, "AES-256 should be NIST Level 5")
}

func TestDeriveNISTQuantumLevel(t *testing.T) {
	assert.Equal(t, 1, deriveNISTQuantumLevel("ML-KEM-512"))
	assert.Equal(t, 3, deriveNISTQuantumLevel("ML-KEM-768"))
	assert.Equal(t, 5, deriveNISTQuantumLevel("ML-KEM-1024"))
	assert.Equal(t, 5, deriveNISTQuantumLevel("ML-DSA-87"))
	assert.Equal(t, 0, deriveNISTQuantumLevel("RSA-2048"))
}

func TestDeriveProtocolVersion(t *testing.T) {
	assert.Equal(t, "1.3", deriveProtocolVersion("TLS 1.3"))
	assert.Equal(t, "1.2", deriveProtocolVersion("TLS 1.2"))
	assert.Equal(t, "3.0", deriveProtocolVersion("SSL 3.0"))
	assert.Equal(t, "", deriveProtocolVersion("SSH"))
}

func TestCategorizeAssetType(t *testing.T) {
	tests := []struct {
		module    string
		subject   string
		algorithm string
		want      string
	}{
		{"certificates", "CN=test", "RSA-2048", "certificate"},
		{"keys", "", "RSA-2048", "key"},
		{"protocol", "", "TLS 1.3", "protocol"},
		{"configs", "", "AES-256-GCM", "algorithm"},
	}

	for _, tt := range tests {
		t.Run(tt.module+"_"+tt.algorithm, func(t *testing.T) {
			f := &model.Finding{
				Module: tt.module,
				CryptoAsset: &model.CryptoAsset{
					Algorithm: tt.algorithm,
					Subject:   tt.subject,
				},
			}
			assert.Equal(t, tt.want, categorizeAssetType(f))
		})
	}
}
