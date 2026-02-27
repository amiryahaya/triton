package diff

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/pkg/model"
)

func baseScan() *model.ScanResult {
	return &model.ScanResult{
		ID: "base-scan",
		Metadata: model.ScanMetadata{
			Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Hostname:  "host-a",
		},
		Findings: []model.Finding{
			{ID: "f1", Source: model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048", PQCStatus: "TRANSITIONAL"}, Module: "certificates"},
			{ID: "f2", Source: model.FindingSource{Type: "file", Path: "/usr/lib/libssl.so"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "AES-256-GCM", PQCStatus: "SAFE"}, Module: "libraries"},
			{ID: "f3", Source: model.FindingSource{Type: "network", Endpoint: "10.0.0.1:443"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "TLS 1.2", PQCStatus: "DEPRECATED"}, Module: "protocol"},
		},
		Summary: model.Summary{Safe: 1, Transitional: 1, Deprecated: 1, Unsafe: 0, NACSAReadinessPercent: 33.3},
	}
}

func compareScan() *model.ScanResult {
	return &model.ScanResult{
		ID: "compare-scan",
		Metadata: model.ScanMetadata{
			Timestamp: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			Hostname:  "host-a",
		},
		Findings: []model.Finding{
			// Same as base — unchanged
			{ID: "f1", Source: model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048", PQCStatus: "TRANSITIONAL"}, Module: "certificates"},
			// Same key, but status changed: SAFE -> still SAFE
			{ID: "f2", Source: model.FindingSource{Type: "file", Path: "/usr/lib/libssl.so"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "AES-256-GCM", PQCStatus: "SAFE"}, Module: "libraries"},
			// Removed: TLS 1.2 (no longer in compare)
			// Added: new finding
			{ID: "f4", Source: model.FindingSource{Type: "file", Path: "/etc/ssl/new-cert.pem"},
				CryptoAsset: &model.CryptoAsset{Algorithm: "ML-KEM-768", PQCStatus: "SAFE"}, Module: "certificates"},
		},
		Summary: model.Summary{Safe: 2, Transitional: 1, Deprecated: 0, Unsafe: 0, NACSAReadinessPercent: 66.7},
	}
}

func TestComputeDiff_AddedRemovedUnchanged(t *testing.T) {
	d := ComputeDiff(baseScan(), compareScan())

	assert.Equal(t, "base-scan", d.BaseID)
	assert.Equal(t, "compare-scan", d.CompareID)

	assert.Equal(t, 1, d.Summary.AddedCount)   // ML-KEM-768
	assert.Equal(t, 1, d.Summary.RemovedCount) // TLS 1.2
	assert.Equal(t, 0, d.Summary.ChangedCount)

	// Verify added is ML-KEM-768
	assert.Len(t, d.Added, 1)
	assert.Equal(t, "ML-KEM-768", d.Added[0].CryptoAsset.Algorithm)

	// Verify removed is TLS 1.2
	assert.Len(t, d.Removed, 1)
	assert.Equal(t, "TLS 1.2", d.Removed[0].CryptoAsset.Algorithm)
}

func TestComputeDiff_StatusChange(t *testing.T) {
	base := baseScan()
	compare := compareScan()

	// Modify compare to have RSA-2048 upgraded to SAFE
	compare.Findings[0].CryptoAsset.PQCStatus = "SAFE"

	d := ComputeDiff(base, compare)
	assert.Equal(t, 1, d.Summary.ChangedCount)
	assert.Len(t, d.Changed, 1)
	assert.Equal(t, "TRANSITIONAL", d.Changed[0].OldStatus)
	assert.Equal(t, "SAFE", d.Changed[0].NewStatus)
}

func TestComputeDiff_SummaryDeltas(t *testing.T) {
	d := ComputeDiff(baseScan(), compareScan())

	assert.Equal(t, 1, d.Summary.SafeDelta) // 2 - 1
	assert.Equal(t, 0, d.Summary.UnsafeDelta)
	assert.InDelta(t, 33.4, d.Summary.NACSADelta, 0.1)
}

func TestComputeDiff_IdenticalScans(t *testing.T) {
	base := baseScan()
	d := ComputeDiff(base, base)

	assert.Equal(t, 0, d.Summary.AddedCount)
	assert.Equal(t, 0, d.Summary.RemovedCount)
	assert.Equal(t, 0, d.Summary.ChangedCount)
}

func TestComputeDiff_EmptyScans(t *testing.T) {
	empty := &model.ScanResult{ID: "empty"}
	d := ComputeDiff(empty, empty)
	assert.Equal(t, 0, d.Summary.AddedCount)
}

func TestFindingKey_FileSource(t *testing.T) {
	f := &model.Finding{
		Source:      model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
		CryptoAsset: &model.CryptoAsset{Algorithm: "RSA-2048"},
	}
	assert.Equal(t, "file:/etc/ssl/cert.pem:RSA-2048", findingKey(f))
}

func TestFindingKey_NetworkSource(t *testing.T) {
	f := &model.Finding{
		Source:      model.FindingSource{Type: "network", Endpoint: "10.0.0.1:443"},
		CryptoAsset: &model.CryptoAsset{Algorithm: "TLS 1.3"},
	}
	assert.Equal(t, "net:10.0.0.1:443:TLS 1.3", findingKey(f))
}

func TestFindingKey_NilCryptoAsset(t *testing.T) {
	f := &model.Finding{
		Source: model.FindingSource{Type: "file", Path: "/test"},
	}
	assert.Equal(t, "file:/test:", findingKey(f))
}
