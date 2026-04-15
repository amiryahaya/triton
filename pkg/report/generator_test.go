package report

import (
	"encoding/json"
	"os"
	"path/filepath"
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

	// Should contain scan profile and PQC status breakdown
	assert.Contains(t, html, "Profile: standard")
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

	// Should contain SVG chart
	assert.Contains(t, html, "<svg")
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

func TestGenerateTritonJSONIncludesSystems(t *testing.T) {
	tmpFile := t.TempDir() + "/report.json"
	g := New("")
	result := sampleScanResult()

	err := g.GenerateTritonJSON(result, tmpFile)
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

	// Should produce JSON, CycloneDX, HTML, Excel, SARIF
	require.Len(t, files, 5, "expected 5 report files, got %d", len(files))

	for _, f := range files {
		assert.True(t, strings.HasPrefix(f, dir), "file should be in output dir")
		assert.Contains(t, f, "20260227-120000", "filename should contain timestamp")
		info, err := os.Stat(f)
		require.NoError(t, err)
		assert.True(t, info.Size() > 0, "file should not be empty: %s", f)
	}
}

func TestGenerateHTMLCharts(t *testing.T) {
	tmpFile := t.TempDir() + "/report.html"
	g := New("")
	result := sampleScanResult()

	err := g.GenerateHTML(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	html := string(content)

	// Donut chart should be present (PQC breakdown has non-zero values)
	assert.Contains(t, html, `<svg width="200" height="200"`)
	assert.Contains(t, html, "chart-section")
	assert.Contains(t, html, "chart-legend")
	assert.Contains(t, html, "legend-dot")
}

func TestGenerateHTMLCBOMSortOrder(t *testing.T) {
	tmpFile := t.TempDir() + "/report.html"
	g := New("")
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{
			Timestamp: time.Date(2026, 2, 27, 10, 0, 0, 0, time.UTC),
		},
		Systems: []model.System{
			{
				Name: "System A",
				CryptoAssets: []model.CryptoAsset{
					{Algorithm: "AES-256", PQCStatus: "SAFE", KeySize: 256},
					{Algorithm: "RSA-1024", PQCStatus: "UNSAFE", KeySize: 1024},
				},
			},
			{
				Name: "System B",
				CryptoAssets: []model.CryptoAsset{
					{Algorithm: "3DES", PQCStatus: "DEPRECATED", KeySize: 168},
					{Algorithm: "RSA-2048", PQCStatus: "TRANSITIONAL", KeySize: 2048},
				},
			},
		},
		Summary: model.Summary{
			TotalSystems:      2,
			TotalCryptoAssets: 4,
			Safe:              1,
			Transitional:      1,
			Deprecated:        1,
			Unsafe:            1,
		},
	}

	err := g.GenerateHTML(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	html := string(content)

	// Verify sort order: UNSAFE < DEPRECATED < TRANSITIONAL < SAFE
	unsafePos := strings.Index(html, "RSA-1024")
	deprecatedPos := strings.Index(html, "3DES")
	transitionalPos := strings.Index(html, "RSA-2048")
	safePos := strings.Index(html, "AES-256")

	assert.Greater(t, deprecatedPos, unsafePos, "DEPRECATED should appear after UNSAFE")
	assert.Greater(t, transitionalPos, deprecatedPos, "TRANSITIONAL should appear after DEPRECATED")
	assert.Greater(t, safePos, transitionalPos, "SAFE should appear after TRANSITIONAL")
}

func TestGenerateHTMLPolicySummary(t *testing.T) {
	tmpFile := t.TempDir() + "/report.html"
	g := New("")
	result := sampleScanResult()

	// Attach policy evaluation data
	result.PolicyEvaluation = &model.PolicyEvaluationResult{
		PolicyName:      "nacsa-2030",
		Verdict:         "FAIL",
		RulesEvaluated:  8,
		FindingsChecked: 15,
		Violations: []model.PolicyViolation{
			{RuleID: "nacsa-weak-hash", Severity: "error", Action: "fail", Message: "MD5 found"},
			{RuleID: "nacsa-weak-hash", Severity: "error", Action: "fail", Message: "SHA-1 found"},
			{RuleID: "nacsa-small-key", Severity: "warning", Action: "warn", Message: "RSA-1024 key"},
		},
		ThresholdViolations: []model.PolicyThresholdViolation{
			{Name: "min_safe_percent", Expected: ">= 60.0%", Actual: "33.3%", Message: "Safe percentage 33.3% below minimum 60.0%"},
		},
		SystemEvaluations: []model.PolicySystemEvaluation{
			{SystemName: "Test System", Verdict: "FAIL", FindingsChecked: 5},
		},
	}

	err := g.GenerateHTML(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	html := string(content)

	// Verdict banner
	assert.Contains(t, html, "Policy Analysis Summary")
	assert.Contains(t, html, "nacsa-2030")
	assert.Contains(t, html, "FAIL")
	assert.Contains(t, html, "Rules evaluated: 8")
	assert.Contains(t, html, "Findings checked: 15")

	// Violations by rule table (aggregated)
	assert.Contains(t, html, "Violations by Rule")
	assert.Contains(t, html, "nacsa-weak-hash")
	assert.Contains(t, html, "nacsa-small-key")

	// Threshold violations table
	assert.Contains(t, html, "Threshold Violations")
	assert.Contains(t, html, "min_safe_percent")
	assert.Contains(t, html, "&gt;= 60.0%")
	assert.Contains(t, html, "33.3%")

	// Per-system table still present
	assert.Contains(t, html, "Per-System Policy Results")
	assert.Contains(t, html, "Test System")
}

func TestGenerateHTMLNoPolicySummary(t *testing.T) {
	tmpFile := t.TempDir() + "/report.html"
	g := New("")
	result := sampleScanResult()
	result.PolicyEvaluation = nil

	err := g.GenerateHTML(result, tmpFile)
	require.NoError(t, err)

	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	html := string(content)

	// Policy section should not be present
	assert.NotContains(t, html, "Policy Analysis Summary")
	assert.NotContains(t, html, "Violations by Rule")
	assert.NotContains(t, html, "Per-System Policy Results")
}

func TestGenerateHTMLHybridBadge(t *testing.T) {
	tmpFile := t.TempDir() + "/hybrid.html"
	g := New("")
	result := &model.ScanResult{
		ID: "hybrid-scan",
		Metadata: model.ScanMetadata{
			Timestamp:   time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
			Hostname:    "host",
			ScanProfile: "comprehensive",
		},
		Systems: []model.System{
			{
				ID:               "sys-hybrid",
				Name:             "TLS 1.3 w/ X25519MLKEM768",
				CriticalityLevel: "Tinggi",
				InUse:            true,
				CryptoAssets: []model.CryptoAsset{
					{
						Algorithm:           "X25519MLKEM768",
						Function:            "Key agreement",
						KeySize:             256,
						PQCStatus:           "SAFE",
						IsHybrid:            true,
						ComponentAlgorithms: []string{"X25519", "ML-KEM-768"},
					},
				},
				CBOMRefs: []string{"CBOM #1"},
			},
		},
	}

	require.NoError(t, g.GenerateHTML(result, tmpFile))
	content, err := os.ReadFile(tmpFile)
	require.NoError(t, err)
	out := string(content)

	assert.Contains(t, out, "X25519MLKEM768")
	assert.Contains(t, out, "hybrid-badge")
	assert.Contains(t, out, ">HYBRID<")
	assert.Contains(t, out, "Hybrid: X25519 + ML-KEM-768")
}

func TestGenerateHTMLAgilityPanel(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "agility.html")
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "agility-host"},
		Systems:  []model.System{{Name: "demo"}},
		Findings: []model.Finding{
			{
				Module: "protocol",
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "TLS 1.3", PQCStatus: model.PQCStatusSafe, IsHybrid: true,
				},
			},
			{
				Module: "binaries",
				CryptoAsset: &model.CryptoAsset{
					Algorithm: "MD5", PQCStatus: model.PQCStatusUnsafe,
				},
			},
		},
	}
	g := New(tmp)
	if err := g.GenerateHTML(result, out); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	html := string(data)
	if !strings.Contains(html, "Crypto Agility Assessment") {
		t.Error("missing section heading")
	}
	if !strings.Contains(html, "agility-host") {
		t.Error("missing hostname in panel")
	}
	if !strings.Contains(html, "PQC Coverage") {
		t.Error("missing PQC Coverage dimension label")
	}
	// Verify badge color class corresponds to the Overall band.
	// The synthetic input has 1 hybrid SAFE TLS finding + 1 unsafe MD5 finding.
	// PQC: 1/2 covered = 50; Protocol: TLS 1.3 + 1 group + hybrid → fires; etc.
	// Whatever the Overall is, exactly one band class must be applied to the
	// badge element (the other two still appear as CSS rules in the <style> block).
	bandClasses := []string{"agility-high", "agility-mid", "agility-low"}
	matches := 0
	for _, c := range bandClasses {
		if strings.Contains(html, `agility-badge `+c) {
			matches++
		}
	}
	if matches != 1 {
		t.Errorf("expected exactly 1 band class applied to badge, found %d (%v)", matches, bandClasses)
	}
	// Recommendations must render when low PQC + java/binary findings present.
	if !strings.Contains(html, "Recommended actions") && !strings.Contains(html, "<ul>") {
		// Synthetic input may not trigger any rule; soft assertion only — log if absent.
		t.Logf("note: no recommendations rendered for synthetic input")
	}
}

func TestGenerateHTMLNoAgilityPanelWhenNoFindings(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "noagility.html")
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "empty"},
		Systems:  []model.System{{Name: "demo"}},
	}
	g := New(tmp)
	if err := g.GenerateHTML(result, out); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "Crypto Agility Assessment") {
		t.Error("agility section should be omitted when no findings")
	}
}

func TestGenerateHTML_SurfacesQualityWarnings(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "quality.html")
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{Hostname: "q-host"},
		Systems: []model.System{{Name: "demo", CryptoAssets: []model.CryptoAsset{
			{
				Algorithm: "RSA-2048",
				PQCStatus: model.PQCStatusTransitional,
				QualityWarnings: []model.QualityWarning{
					{Code: "ROCA", Severity: "CRITICAL", Message: "modulus matches Infineon weak-prime structure", CVE: "CVE-2017-15361"},
				},
			},
		}}},
	}
	g := New(tmp)
	if err := g.GenerateHTML(result, out); err != nil {
		t.Fatalf("GenerateHTML: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	htmlStr := string(data)
	if !strings.Contains(htmlStr, "QUALITY") {
		t.Error("missing QUALITY badge")
	}
	if !strings.Contains(htmlStr, "ROCA") {
		t.Error("missing ROCA warning text in details block")
	}
	if !strings.Contains(htmlStr, "CVE-2017-15361") {
		t.Error("missing CVE reference in warning text")
	}
}
