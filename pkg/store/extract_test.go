package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// scanWith builds a minimal model.ScanResult with the given ID, orgID,
// hostname (via Metadata), and findings. Keeps test bodies short.
func scanWith(id, orgID, hostname string, findings ...model.Finding) *model.ScanResult {
	return &model.ScanResult{
		ID:       id,
		OrgID:    orgID,
		Metadata: model.ScanMetadata{Hostname: hostname},
		Findings: findings,
	}
}

// cryptoFinding is a test helper that builds a file-sourced finding
// carrying the given module name and CryptoAsset.
func cryptoFinding(module, path string, ca *model.CryptoAsset) model.Finding {
	return model.Finding{
		Module:      module,
		Source:      model.FindingSource{Type: "file", Path: path},
		CryptoAsset: ca,
	}
}

// plainFinding is a non-crypto finding (CryptoAsset == nil) used to
// verify index preservation and dropping semantics.
func plainFinding(path string) model.Finding {
	return model.Finding{
		Module: "file",
		Source: model.FindingSource{Type: "file", Path: path},
	}
}

func TestExtractFindings_NilScan(t *testing.T) {
	assert.Nil(t, ExtractFindings(nil))
}

func TestExtractFindings_EmptyScan(t *testing.T) {
	assert.Empty(t, ExtractFindings(scanWith("s1", "o1", "h1")))
}

func TestExtractFindings_NoCryptoFindings(t *testing.T) {
	scan := scanWith("s1", "o1", "h1",
		plainFinding("/x"),
		plainFinding("/y"),
	)
	assert.Empty(t, ExtractFindings(scan))
}

func TestExtractFindings_AllCryptoFindings(t *testing.T) {
	scan := scanWith("s1", "o1", "h1",
		cryptoFinding("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048, PQCStatus: "DEPRECATED", MigrationPriority: 80}),
		cryptoFinding("key", "/b", &model.CryptoAsset{Algorithm: "ECDSA", KeySize: 256, PQCStatus: "TRANSITIONAL", MigrationPriority: 55}),
	)
	got := ExtractFindings(scan)
	require.Len(t, got, 2)
	assert.Equal(t, "RSA", got[0].Algorithm)
	assert.Equal(t, 2048, got[0].KeySize)
	assert.Equal(t, "DEPRECATED", got[0].PQCStatus)
	assert.Equal(t, 80, got[0].MigrationPriority)
	assert.Equal(t, 0, got[0].FindingIndex)
	assert.Equal(t, "/a", got[0].FilePath)
	assert.Equal(t, "ECDSA", got[1].Algorithm)
	assert.Equal(t, 1, got[1].FindingIndex)
}

func TestExtractFindings_MixedFindingsPreservesIndex(t *testing.T) {
	// Index 0: plain (dropped). Index 1: RSA (kept, index=1).
	// Index 2: plain (dropped). Index 3: AES (kept, index=3).
	scan := scanWith("s1", "o1", "h1",
		plainFinding("/z"),
		cryptoFinding("key", "/a", &model.CryptoAsset{Algorithm: "RSA", KeySize: 2048}),
		plainFinding("/w"),
		cryptoFinding("key", "/b", &model.CryptoAsset{Algorithm: "AES", KeySize: 256}),
	)
	got := ExtractFindings(scan)
	require.Len(t, got, 2)
	assert.Equal(t, 1, got[0].FindingIndex, "RSA finding keeps its original index")
	assert.Equal(t, 3, got[1].FindingIndex, "AES finding keeps its original index")
}

func TestExtractFindings_CertificateFields(t *testing.T) {
	notAfter := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	scan := scanWith("s1", "o1", "h1",
		cryptoFinding("certificate", "/etc/pki/test.crt", &model.CryptoAsset{
			Algorithm: "RSA",
			KeySize:   2048,
			NotAfter:  &notAfter,
			Subject:   "CN=api.test",
			Issuer:    "CN=Test CA",
		}),
	)
	got := ExtractFindings(scan)
	require.Len(t, got, 1)
	require.NotNil(t, got[0].NotAfter)
	assert.Equal(t, notAfter, *got[0].NotAfter)
	assert.Equal(t, "CN=api.test", got[0].Subject)
	assert.Equal(t, "CN=Test CA", got[0].Issuer)
}

func TestExtractFindings_DepsReachability(t *testing.T) {
	scan := scanWith("s1", "o1", "h1",
		cryptoFinding("deps", "go.mod", &model.CryptoAsset{
			Algorithm:    "RSA",
			KeySize:      2048,
			Reachability: "transitive",
		}),
	)
	got := ExtractFindings(scan)
	require.Len(t, got, 1)
	assert.Equal(t, "transitive", got[0].Reachability)
}

func TestExtractFindings_NilNotAfterStaysNil(t *testing.T) {
	scan := scanWith("s1", "o1", "h1",
		cryptoFinding("key", "/a", &model.CryptoAsset{Algorithm: "AES", KeySize: 256, NotAfter: nil}),
	)
	got := ExtractFindings(scan)
	require.Len(t, got, 1)
	assert.Nil(t, got[0].NotAfter, "nil NotAfter must stay nil, not silently become a zero value")
}

func TestExtractFindings_ScanFieldsPropagate(t *testing.T) {
	scan := scanWith("scan-abc", "org-xyz", "host-123",
		cryptoFinding("key", "/key", &model.CryptoAsset{Algorithm: "AES"}),
	)
	got := ExtractFindings(scan)
	require.Len(t, got, 1)
	assert.Equal(t, "scan-abc", got[0].ScanID)
	assert.Equal(t, "org-xyz", got[0].OrgID)
	assert.Equal(t, "host-123", got[0].Hostname, "hostname must come from ScanResult.Metadata.Hostname")
}

func TestExtractFindings_ModuleNamePreserved(t *testing.T) {
	// Module (scanner name) is the primary drill-down field for Phase 1
	// views; model.Finding.Category (coarse enum) is deliberately NOT
	// stored. This test guards that design decision.
	scan := scanWith("s1", "o1", "h1",
		cryptoFinding("certificate", "/crt", &model.CryptoAsset{Algorithm: "RSA"}),
	)
	got := ExtractFindings(scan)
	require.Len(t, got, 1)
	assert.Equal(t, "certificate", got[0].Module)
}
