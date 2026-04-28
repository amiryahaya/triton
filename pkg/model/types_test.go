package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanResultJSON(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	result := ScanResult{
		ID: "scan-001",
		Metadata: ScanMetadata{
			Timestamp:   now,
			Hostname:    "testhost",
			OS:          "darwin",
			ScanProfile: "quick",
			Targets: []ScanTarget{
				{Type: TargetFilesystem, Value: "/etc", Depth: 3},
			},
			Duration:    5 * time.Second,
			ToolVersion: "0.1.0",
		},
		Systems: []System{
			{ID: "sys-1", Name: "TestApp", InUse: true},
		},
		Findings: []Finding{
			{
				ID:       "f-1",
				Category: 5,
				Source:   FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
				CryptoAsset: &CryptoAsset{
					ID:        "cbom-1",
					Algorithm: "RSA-2048",
					KeySize:   2048,
				},
				Confidence: 0.95,
				Module:     "certificates",
				Timestamp:  now,
			},
		},
		Summary: Summary{TotalFindings: 1, Transitional: 1},
	}

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded ScanResult
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, result.ID, decoded.ID)
	assert.Equal(t, result.Metadata.Hostname, decoded.Metadata.Hostname)
	assert.Equal(t, result.Metadata.OS, decoded.Metadata.OS)
	assert.Equal(t, result.Metadata.ScanProfile, decoded.Metadata.ScanProfile)
	assert.Len(t, decoded.Metadata.Targets, 1)
	assert.Equal(t, result.Metadata.Duration, decoded.Metadata.Duration)
	assert.Len(t, decoded.Systems, 1)
	assert.Len(t, decoded.Findings, 1)
	assert.Equal(t, result.Summary.TotalFindings, decoded.Summary.TotalFindings)
}

func TestSystemJSONRoundTrip(t *testing.T) {
	sys := System{
		ID:                "sys-1",
		Name:              "Portal Kerajaan",
		Purpose:           "Portal perkhidmatan awam",
		URL:               "https://portal.gov.my",
		ServiceMode:       "Online",
		TargetCustomer:    "Rakyat Malaysia",
		Components:        []string{"Apache", "OpenSSL"},
		ThirdPartyModules: []string{"mod_ssl"},
		ExternalAPIs:      []string{"MyKAD API"},
		CriticalityLevel:  "Tinggi",
		DataCategory:      "Sulit",
		InUse:             true,
		Developer:         "MAMPU",
		Vendor:            "Internal",
		CBOMRefs:          []string{"CBOM #1", "CBOM #2"},
		CryptoAssets: []CryptoAsset{
			{ID: "cbom-1", Algorithm: "RSA-2048"},
		},
	}

	data, err := json.Marshal(sys)
	require.NoError(t, err)

	var decoded System
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, sys.ID, decoded.ID)
	assert.Equal(t, sys.Name, decoded.Name)
	assert.Equal(t, sys.Purpose, decoded.Purpose)
	assert.Equal(t, sys.URL, decoded.URL)
	assert.Equal(t, sys.ServiceMode, decoded.ServiceMode)
	assert.Equal(t, sys.TargetCustomer, decoded.TargetCustomer)
	assert.Equal(t, sys.Components, decoded.Components)
	assert.Equal(t, sys.ThirdPartyModules, decoded.ThirdPartyModules)
	assert.Equal(t, sys.ExternalAPIs, decoded.ExternalAPIs)
	assert.Equal(t, sys.CriticalityLevel, decoded.CriticalityLevel)
	assert.Equal(t, sys.DataCategory, decoded.DataCategory)
	assert.Equal(t, sys.InUse, decoded.InUse)
	assert.Equal(t, sys.Developer, decoded.Developer)
	assert.Equal(t, sys.Vendor, decoded.Vendor)
	assert.Equal(t, sys.CBOMRefs, decoded.CBOMRefs)
	assert.Len(t, decoded.CryptoAssets, 1)

	// InUse=false is preserved (no omitempty)
	sys.InUse = false
	data, err = json.Marshal(sys)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"inUse":false`)
}

func TestFindingJSONRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	finding := Finding{
		ID:       "f-1",
		Category: 5,
		Source: FindingSource{
			Type: "file",
			Path: "/etc/ssl/cert.pem",
		},
		CryptoAsset: &CryptoAsset{
			ID:        "cbom-1",
			Algorithm: "RSA-2048",
			KeySize:   2048,
			PQCStatus: "TRANSITIONAL",
		},
		Confidence: 0.95,
		Module:     "certificates",
		Timestamp:  now,
	}

	data, err := json.Marshal(finding)
	require.NoError(t, err)

	var decoded Finding
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, finding.ID, decoded.ID)
	assert.Equal(t, finding.Category, decoded.Category)
	assert.Equal(t, finding.Source.Type, decoded.Source.Type)
	assert.Equal(t, finding.Source.Path, decoded.Source.Path)
	require.NotNil(t, decoded.CryptoAsset)
	assert.Equal(t, finding.CryptoAsset.Algorithm, decoded.CryptoAsset.Algorithm)
	assert.Equal(t, finding.Confidence, decoded.Confidence)
	assert.Equal(t, finding.Module, decoded.Module)
}

func TestCryptoAssetJSONRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	notAfter := now.Add(365 * 24 * time.Hour)
	asset := CryptoAsset{
		ID:                "cbom-1",
		SystemName:        "Portal",
		Function:          "Certificate authentication",
		Algorithm:         "RSA-2048",
		Library:           "OpenSSL 3.0",
		KeySize:           2048,
		Purpose:           "TLS",
		CryptoAgility:     "Supported",
		PQCStatus:         "TRANSITIONAL",
		MigrationPriority: 50,
		BreakYear:         2035,
		Subject:           "CN=portal.gov.my",
		Issuer:            "CN=DigiCert",
		SerialNumber:      "1234",
		NotBefore:         &now,
		NotAfter:          &notAfter,
		IsCA:              false,
	}

	data, err := json.Marshal(asset)
	require.NoError(t, err)

	var decoded CryptoAsset
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, asset.ID, decoded.ID)
	assert.Equal(t, asset.SystemName, decoded.SystemName)
	assert.Equal(t, asset.Function, decoded.Function)
	assert.Equal(t, asset.Algorithm, decoded.Algorithm)
	assert.Equal(t, asset.Library, decoded.Library)
	assert.Equal(t, asset.KeySize, decoded.KeySize)
	assert.Equal(t, asset.Purpose, decoded.Purpose)
	assert.Equal(t, asset.CryptoAgility, decoded.CryptoAgility)
	assert.Equal(t, asset.PQCStatus, decoded.PQCStatus)
	assert.Equal(t, asset.MigrationPriority, decoded.MigrationPriority)
	assert.Equal(t, asset.BreakYear, decoded.BreakYear)
	assert.Equal(t, asset.Subject, decoded.Subject)
	require.NotNil(t, decoded.NotBefore)
	require.NotNil(t, decoded.NotAfter)
	assert.Equal(t, asset.NotBefore.Unix(), decoded.NotBefore.Unix())
	assert.Equal(t, asset.NotAfter.Unix(), decoded.NotAfter.Unix())

	// Certificate-specific fields use omitempty
	minimal := CryptoAsset{ID: "cbom-2", Algorithm: "AES-256"}
	data, err = json.Marshal(minimal)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "subject")
	assert.NotContains(t, string(data), "issuer")
	assert.NotContains(t, string(data), "notBefore")
}

func TestFindingSourceTypes(t *testing.T) {
	tests := []struct {
		name   string
		source FindingSource
	}{
		{
			name:   "file source",
			source: FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
		},
		{
			name:   "process source",
			source: FindingSource{Type: "process", PID: 1234},
		},
		{
			name:   "network source",
			source: FindingSource{Type: "network", Endpoint: "192.168.1.1:443"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.source)
			require.NoError(t, err)

			var decoded FindingSource
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.source.Type, decoded.Type)
		})
	}
}

func TestComputeSummary(t *testing.T) {
	findings := []Finding{
		{Category: 5, CryptoAsset: &CryptoAsset{PQCStatus: "SAFE"}},
		{Category: 5, CryptoAsset: &CryptoAsset{PQCStatus: "SAFE"}},
		{Category: 3, CryptoAsset: &CryptoAsset{PQCStatus: "TRANSITIONAL"}},
		{Category: 2, CryptoAsset: &CryptoAsset{PQCStatus: "DEPRECATED"}},
		{Category: 9, CryptoAsset: &CryptoAsset{PQCStatus: "UNSAFE"}},
		{Category: 5, CryptoAsset: nil}, // no crypto asset
	}

	summary := ComputeSummary(findings)

	assert.Equal(t, 6, summary.TotalFindings)
	assert.Equal(t, 5, summary.TotalCryptoAssets)
	assert.Equal(t, 2, summary.Safe)
	assert.Equal(t, 1, summary.Transitional)
	assert.Equal(t, 1, summary.Deprecated)
	assert.Equal(t, 1, summary.Unsafe)

	// Categories scanned: 2, 3, 5, 9
	assert.Contains(t, summary.CategoriesScanned, 2)
	assert.Contains(t, summary.CategoriesScanned, 3)
	assert.Contains(t, summary.CategoriesScanned, 5)
	assert.Contains(t, summary.CategoriesScanned, 9)
	assert.Len(t, summary.CategoriesScanned, 4)

	// Categories skipped: 1, 4, 6, 7, 8
	assert.Contains(t, summary.CategoriesSkipped, 1)
	assert.Contains(t, summary.CategoriesSkipped, 4)
	assert.Len(t, summary.CategoriesSkipped, 5)
}

func TestComputeSummaryEmpty(t *testing.T) {
	summary := ComputeSummary([]Finding{})

	assert.Equal(t, 0, summary.TotalFindings)
	assert.Equal(t, 0, summary.TotalCryptoAssets)
	assert.Equal(t, 0, summary.Safe)
	assert.Equal(t, 0, summary.Transitional)
	assert.Equal(t, 0, summary.Deprecated)
	assert.Equal(t, 0, summary.Unsafe)
	assert.Len(t, summary.CategoriesScanned, 0)
	assert.Len(t, summary.CategoriesSkipped, 9)
}

func TestScanTargetTypes(t *testing.T) {
	assert.Equal(t, ScanTargetType(0), TargetFilesystem)
	assert.Equal(t, ScanTargetType(1), TargetNetwork)
	assert.Equal(t, ScanTargetType(2), TargetProcess)
	assert.Equal(t, ScanTargetType(3), TargetDatabase)
	assert.Equal(t, ScanTargetType(4), TargetHSM)
	assert.Equal(t, ScanTargetType(5), TargetLDAP)
	assert.Equal(t, ScanTargetType(6), TargetOCIImage)
	assert.Equal(t, ScanTargetType(7), TargetKubernetesCluster)
}

func TestModuleCategoryConstants(t *testing.T) {
	assert.Equal(t, ModuleCategory(0), CategoryPassiveFile)
	assert.Equal(t, ModuleCategory(1), CategoryPassiveCode)
	assert.Equal(t, ModuleCategory(2), CategoryActiveRuntime)
	assert.Equal(t, ModuleCategory(3), CategoryActiveNetwork)
}

func TestCryptoAssetNewFieldsJSON(t *testing.T) {
	asset := CryptoAsset{
		ID:              "cbom-1",
		Algorithm:       "AES-256-GCM",
		Language:        "Go",
		State:           "IN_TRANSIT",
		CryptoLibraries: []string{"crypto/tls", "crypto/aes"},
	}

	data, err := json.Marshal(asset)
	require.NoError(t, err)

	var decoded CryptoAsset
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "Go", decoded.Language)
	assert.Equal(t, "IN_TRANSIT", decoded.State)
	assert.Equal(t, []string{"crypto/tls", "crypto/aes"}, decoded.CryptoLibraries)
}

func TestCryptoAssetNewFieldsOmitEmpty(t *testing.T) {
	asset := CryptoAsset{ID: "cbom-2", Algorithm: "RSA-2048"}
	data, err := json.Marshal(asset)
	require.NoError(t, err)
	jsonStr := string(data)

	assert.NotContains(t, jsonStr, "language")
	assert.NotContains(t, jsonStr, "state")
	assert.NotContains(t, jsonStr, "cryptoLibraries")
}

func TestFindingSourceDetectionMethod(t *testing.T) {
	source := FindingSource{
		Type:            "file",
		Path:            "/usr/bin/test",
		DetectionMethod: "symbol",
	}

	data, err := json.Marshal(source)
	require.NoError(t, err)

	var decoded FindingSource
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "symbol", decoded.DetectionMethod)
}

func TestFindingSourceDetectionMethodOmitEmpty(t *testing.T) {
	source := FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"}
	data, err := json.Marshal(source)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "detectionMethod")
}

func TestModuleMetricJSON(t *testing.T) {
	metric := ModuleMetric{
		Module:        "binaries",
		Target:        "/Applications",
		Duration:      45200 * time.Millisecond,
		FilesScanned:  3420,
		FilesMatched:  284,
		Findings:      198,
		MemoryDeltaMB: 12.3,
	}

	data, err := json.Marshal(metric)
	require.NoError(t, err)

	var decoded ModuleMetric
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, metric.Module, decoded.Module)
	assert.Equal(t, metric.Target, decoded.Target)
	assert.Equal(t, metric.Duration, decoded.Duration)
	assert.Equal(t, metric.FilesScanned, decoded.FilesScanned)
	assert.Equal(t, metric.FilesMatched, decoded.FilesMatched)
	assert.Equal(t, metric.Findings, decoded.Findings)
	assert.Equal(t, metric.MemoryDeltaMB, decoded.MemoryDeltaMB)
	assert.Empty(t, decoded.Error)

	// Error field omits when empty
	assert.NotContains(t, string(data), "error")
}

func TestModuleMetricErrorJSON(t *testing.T) {
	metric := ModuleMetric{
		Module: "failing",
		Target: "/tmp",
		Error:  "disk read error",
	}

	data, err := json.Marshal(metric)
	require.NoError(t, err)

	assert.Contains(t, string(data), `"error":"disk read error"`)

	var decoded ModuleMetric
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, "disk read error", decoded.Error)
}

func TestScanMetadataMetricsField(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	metadata := ScanMetadata{
		Timestamp:   now,
		Hostname:    "testhost",
		OS:          "darwin",
		ScanProfile: "quick",
		Duration:    10 * time.Second,
		ToolVersion: "0.1.0",
		ModuleMetrics: []ModuleMetric{
			{Module: "certs", Target: "/etc", Duration: 2 * time.Second, Findings: 5},
			{Module: "keys", Target: "/etc", Duration: 1 * time.Second, Findings: 3},
		},
		PeakMemoryMB: 142.3,
	}

	data, err := json.Marshal(metadata)
	require.NoError(t, err)

	var decoded ScanMetadata
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	require.Len(t, decoded.ModuleMetrics, 2)
	assert.Equal(t, "certs", decoded.ModuleMetrics[0].Module)
	assert.Equal(t, 5, decoded.ModuleMetrics[0].Findings)
	assert.Equal(t, "keys", decoded.ModuleMetrics[1].Module)
	assert.Equal(t, 142.3, decoded.PeakMemoryMB)
}

func TestScanMetadataMetricsOmitEmpty(t *testing.T) {
	metadata := ScanMetadata{
		Hostname:    "testhost",
		ScanProfile: "quick",
	}

	data, err := json.Marshal(metadata)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "moduleMetrics")
	assert.NotContains(t, string(data), "peakMemoryMB")
}

func TestPQCStatusConstants(t *testing.T) {
	// Verify constant values match expected strings.
	// ComputeSummary uses these constants in its switch statement.
	assert.Equal(t, "SAFE", PQCStatusSafe)
	assert.Equal(t, "TRANSITIONAL", PQCStatusTransitional)
	assert.Equal(t, "DEPRECATED", PQCStatusDeprecated)
	assert.Equal(t, "UNSAFE", PQCStatusUnsafe)
}

func TestCryptoAssetImageFieldsOmitEmpty(t *testing.T) {
	a := CryptoAsset{Algorithm: "RSA"}
	b, err := json.Marshal(a)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "imageRef")
	assert.NotContains(t, string(b), "imageDigest")

	a.ImageRef = "nginx:1.25"
	a.ImageDigest = "sha256:abc"
	b, err = json.Marshal(a)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"imageRef":"nginx:1.25"`)
	assert.Contains(t, string(b), `"imageDigest":"sha256:abc"`)
}

func TestScanMetadata_SourceField(t *testing.T) {
	m := ScanMetadata{Source: ScanSourceAgent}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"source":"triton-agent"`)

	var m2 ScanMetadata
	err = json.Unmarshal(b, &m2)
	require.NoError(t, err)
	assert.Equal(t, ScanSourceAgent, m2.Source)
}

func TestScanMetadata_SourceFieldOmitEmpty(t *testing.T) {
	m := ScanMetadata{}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	if strings.Contains(string(b), `"source"`) {
		t.Errorf("expected source to be omitted for zero value, got: %s", b)
	}
}
