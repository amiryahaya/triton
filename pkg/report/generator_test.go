package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

func sampleScanResult() *model.ScanResult {
	return &model.ScanResult{
		ID: "test-scan-001",
		Metadata: model.ScanMetadata{
			Timestamp:   time.Date(2026, 2, 26, 10, 0, 0, 0, time.UTC),
			Hostname:    "test-host",
			ScanProfile: "standard",
			ToolVersion: "0.1.0",
		},
		Systems: []model.System{
			{
				ID:               "sys-1",
				Name:             "TLS Service (10.0.0.1:443)",
				Purpose:          "Encryption for TLS channel",
				URL:              "10.0.0.1:443",
				CriticalityLevel: "Sangat Tinggi",
				InUse:            true,
				CryptoAssets: []model.CryptoAsset{
					{Algorithm: "AES-256-GCM", Function: "TLS cipher suite", KeySize: 256, PQCStatus: "SAFE"},
					{Algorithm: "RSA-4096", Function: "TLS server certificate", KeySize: 4096, PQCStatus: "TRANSITIONAL"},
				},
				CBOMRefs: []string{"CBOM #1 - CBOM #2"},
			},
			{
				ID:               "sys-2",
				Name:             "sshd (process)",
				CriticalityLevel: "Tinggi",
				InUse:            true,
				CryptoAssets: []model.CryptoAsset{
					{Algorithm: "Ed25519", Function: "SSH host key", KeySize: 256, PQCStatus: "SAFE"},
				},
				CBOMRefs: []string{"CBOM #3"},
			},
		},
		Summary: model.Summary{
			TotalSystems:      2,
			TotalFindings:     3,
			TotalCryptoAssets: 3,
			Safe:              2,
			Transitional:      1,
			CategoriesScanned: []int{5, 9},
			CategoriesSkipped: []int{1, 2, 3, 4, 6, 7, 8},
		},
	}
}

func TestGenerateHTMLContainsPQCSummary(t *testing.T) {
	tmpFile := t.TempDir() + "/report.html"
	g := New("")
	result := sampleScanResult()

	err := g.GenerateHTML(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	html := string(content)

	// Should contain PQC status breakdown
	assert.Contains(t, html, "Safe")
	assert.Contains(t, html, "Transitional")
	assert.Contains(t, html, "CBOM Report")

	// Should contain system names
	assert.Contains(t, html, "TLS Service")
	assert.Contains(t, html, "sshd")

	// Should contain algorithm names
	assert.Contains(t, html, "AES-256-GCM")
	assert.Contains(t, html, "RSA-4096")
	assert.Contains(t, html, "Ed25519")
}

func TestGenerateHTMLSystemsTable(t *testing.T) {
	tmpFile := t.TempDir() + "/report.html"
	g := New("")
	result := sampleScanResult()

	err := g.GenerateHTML(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	html := string(content)

	// Should contain system table headers
	assert.Contains(t, html, "System / Application")
	assert.Contains(t, html, "Critical Level")
	assert.Contains(t, html, "Link to CBOM")
}

func TestGenerateHTMLEmpty(t *testing.T) {
	tmpFile := t.TempDir() + "/report.html"
	g := New("")
	result := &model.ScanResult{}

	err := g.GenerateHTML(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "<!DOCTYPE html>")
}

func TestGenerateCycloneDXIncludesSystems(t *testing.T) {
	tmpFile := t.TempDir() + "/report.json"
	g := New("")
	result := sampleScanResult()

	err := g.GenerateCycloneDX(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)

	var parsed struct {
		GeneratedAt string           `json:"generatedAt"`
		Result      model.ScanResult `json:"result"`
	}
	err = json.Unmarshal(content, &parsed)
	require.NoError(t, err)

	assert.NotEmpty(t, parsed.GeneratedAt)
	assert.Len(t, parsed.Result.Systems, 2)
	assert.Equal(t, "TLS Service (10.0.0.1:443)", parsed.Result.Systems[0].Name)
	assert.Equal(t, 2, parsed.Result.Summary.Safe)
	assert.Equal(t, 1, parsed.Result.Summary.Transitional)
}

func TestGenerateAllReports(t *testing.T) {
	dir := t.TempDir()
	g := New(dir)
	result := sampleScanResult()

	files, err := g.GenerateAllReports(result, "20260227-120000")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	// Should produce JSON, HTML, Excel
	require.Len(t, files, 3, "expected 3 report files, got %d", len(files))

	for _, f := range files {
		assert.True(t, strings.HasPrefix(f, dir), "file should be in output dir")
		assert.Contains(t, f, "20260227-120000", "filename should contain timestamp")
		info, err := os.Stat(f)
		require.NoError(t, err)
		assert.True(t, info.Size() > 0, "file should not be empty: %s", f)
	}
}
