package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func testScanResult() *model.ScanResult {
	now := time.Now()
	return &model.ScanResult{
		ID: "sarif-test",
		Metadata: model.ScanMetadata{
			Timestamp:   now,
			Hostname:    "test-host",
			ToolVersion: "2.0.0-test",
		},
		Findings: []model.Finding{
			{
				ID:       "f1",
				Category: 2,
				Source:   model.FindingSource{Type: "file", Path: "/etc/ssl/cert.pem"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "RSA-2048",
					PQCStatus: "TRANSITIONAL",
					KeySize:   2048,
				},
				Module: "certificates",
			},
			{
				ID:       "f2",
				Category: 3,
				Source:   model.FindingSource{Type: "file", Path: "/usr/lib/libssl.so"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "AES-256-GCM",
					PQCStatus: "SAFE",
					KeySize:   256,
				},
				Module: "libraries",
			},
			{
				ID:       "f3",
				Category: 2,
				Source:   model.FindingSource{Type: "file", Path: "/etc/ssh/host_key"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "DES",
					PQCStatus: "UNSAFE",
					KeySize:   56,
				},
				Module: "keys",
			},
			{
				ID:       "f4",
				Category: 8,
				Source:   model.FindingSource{Type: "network", Endpoint: "10.0.0.1:443"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "TLS 1.2",
					PQCStatus: "DEPRECATED",
				},
				Module: "protocol",
			},
			{
				ID:       "f5",
				Category: 1,
				Source:   model.FindingSource{Type: "process", Path: "sshd"},
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "Ed25519",
					PQCStatus: "TRANSITIONAL",
				},
				Module: "processes",
			},
			{
				ID:          "f6",
				Category:    5,
				Source:      model.FindingSource{Type: "file", Path: "/app/test.py"},
				CryptoAsset: nil, // No crypto asset — should be skipped
				Module:      "scripts",
			},
		},
	}
}

func TestGenerateSARIF_WritesValidJSON(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.sarif")

	gen := New(dir)
	err := gen.GenerateSARIF(testScanResult(), out)
	require.NoError(t, err)

	data, err := os.ReadFile(out)
	require.NoError(t, err)

	var log sarifLog
	err = json.Unmarshal(data, &log)
	require.NoError(t, err)

	assert.Equal(t, "2.1.0", log.Version)
	assert.Len(t, log.Runs, 1)
	assert.Equal(t, "Triton", log.Runs[0].Tool.Driver.Name)
}

func TestGenerateSARIF_CorrectResultCount(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.sarif")

	gen := New(dir)
	require.NoError(t, gen.GenerateSARIF(testScanResult(), out))

	data, err := os.ReadFile(out)
	require.NoError(t, err)

	var log sarifLog
	require.NoError(t, json.Unmarshal(data, &log))

	// 5 findings with CryptoAsset, 1 without (should be skipped)
	assert.Len(t, log.Runs[0].Results, 5)
}

func TestGenerateSARIF_CorrectLevels(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.sarif")

	gen := New(dir)
	require.NoError(t, gen.GenerateSARIF(testScanResult(), out))

	data, err := os.ReadFile(out)
	require.NoError(t, err)

	var log sarifLog
	require.NoError(t, json.Unmarshal(data, &log))

	results := log.Runs[0].Results

	// Check rule IDs and levels
	levelCount := map[string]int{}
	for _, r := range results {
		levelCount[r.Level]++
	}

	assert.Equal(t, 1, levelCount["error"])   // DES (UNSAFE)
	assert.Equal(t, 1, levelCount["warning"]) // TLS 1.2 (DEPRECATED)
	assert.Equal(t, 3, levelCount["note"])    // RSA-2048 (TRANSITIONAL) + AES-256 (SAFE) + Ed25519 (TRANSITIONAL)
}

func TestGenerateSARIF_FileLocations(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.sarif")

	gen := New(dir)
	require.NoError(t, gen.GenerateSARIF(testScanResult(), out))

	data, err := os.ReadFile(out)
	require.NoError(t, err)

	var log sarifLog
	require.NoError(t, json.Unmarshal(data, &log))

	// First result should be a file location
	r0 := log.Runs[0].Results[0]
	require.Len(t, r0.Locations, 1)
	assert.NotNil(t, r0.Locations[0].PhysicalLocation)
}

func TestGenerateSARIF_NetworkLocations(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.sarif")

	gen := New(dir)
	require.NoError(t, gen.GenerateSARIF(testScanResult(), out))

	data, err := os.ReadFile(out)
	require.NoError(t, err)

	var log sarifLog
	require.NoError(t, json.Unmarshal(data, &log))

	// Find the network result (TLS 1.2)
	var networkResult *sarifResult
	for i, r := range log.Runs[0].Results {
		if r.RuleID == "triton/pqc-deprecated" {
			networkResult = &log.Runs[0].Results[i]
			break
		}
	}
	require.NotNil(t, networkResult)
	require.Len(t, networkResult.Locations, 1)
	assert.Len(t, networkResult.Locations[0].LogicalLocations, 1)
	assert.Equal(t, "10.0.0.1:443", networkResult.Locations[0].LogicalLocations[0].Name)
}

func TestGenerateSARIF_EmptyFindings(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.sarif")

	gen := New(dir)
	result := &model.ScanResult{Metadata: model.ScanMetadata{ToolVersion: "2.0"}}
	require.NoError(t, gen.GenerateSARIF(result, out))

	data, err := os.ReadFile(out)
	require.NoError(t, err)

	var log sarifLog
	require.NoError(t, json.Unmarshal(data, &log))
	assert.Empty(t, log.Runs[0].Results)
}
