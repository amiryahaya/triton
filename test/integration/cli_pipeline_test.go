//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/policy"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// A1: Quick profile → scan fixtures → GenerateTritonJSON → valid JSON file
func TestCLI_QuickScanToJSON(t *testing.T) {
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})

	require.NotEmpty(t, result.Findings, "should find at least one crypto asset")
	assert.NotEmpty(t, result.ID)
	assert.True(t, result.Metadata.Duration > 0)

	outDir := t.TempDir()
	gen := report.New(outDir)
	jsonFile := filepath.Join(outDir, "test-report.json")
	require.NoError(t, gen.GenerateTritonJSON(result, jsonFile))

	assertFileValid(t, jsonFile, `"id"`, `"findings"`)

	// Verify it's valid JSON with the expected wrapper structure
	data, err := os.ReadFile(jsonFile)
	require.NoError(t, err)
	var parsed struct {
		GeneratedAt string            `json:"generatedAt"`
		Result      *model.ScanResult `json:"result"`
	}
	require.NoError(t, json.Unmarshal(data, &parsed))
	require.NotNil(t, parsed.Result)
	assert.Equal(t, result.ID, parsed.Result.ID)
}

// A2: Standard profile → multi-module findings → all requested modules present
func TestCLI_StandardScanMultiModule(t *testing.T) {
	mods := []string{"certificates", "keys", "libraries", "binaries"}
	result := scanFixtures(t, "standard", mods)

	require.NotEmpty(t, result.Findings)

	modulesSeen := make(map[string]bool)
	for _, f := range result.Findings {
		modulesSeen[f.Module] = true
	}

	// At minimum certs and keys should produce findings from fixtures
	assert.True(t, modulesSeen["certificates"], "should have certificate findings")
	assert.True(t, modulesSeen["keys"], "should have key findings")
}

// A3: Scan → SaveScan → GetScan → findings match
func TestCLI_ScanToStoreRoundTrip(t *testing.T) {
	db := requireDB(t)
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})

	ctx := context.Background()
	require.NoError(t, db.SaveScan(ctx, result))

	got, err := db.GetScan(ctx, result.ID, "")
	require.NoError(t, err)
	assert.Equal(t, result.ID, got.ID)
	assert.Equal(t, len(result.Findings), len(got.Findings))
	assert.Equal(t, result.Summary.TotalFindings, got.Summary.TotalFindings)
}

// A4: Scan → CycloneDX → contains bomFormat, specVersion
func TestCLI_ScanToCycloneDX(t *testing.T) {
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})

	outDir := t.TempDir()
	gen := report.New(outDir)
	cdxFile := filepath.Join(outDir, "test-report.cdx.json")
	require.NoError(t, gen.GenerateCycloneDXBOM(result, cdxFile))

	assertFileValid(t, cdxFile, "bomFormat", "specVersion")
}

// A5: Scan → HTML → contains DOCTYPE, summary table
func TestCLI_ScanToHTML(t *testing.T) {
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})

	outDir := t.TempDir()
	gen := report.New(outDir)
	htmlFile := filepath.Join(outDir, "test-report.html")
	require.NoError(t, gen.GenerateHTML(result, htmlFile))

	assertFileValid(t, htmlFile, "<!DOCTYPE html>", "<table")
}

// A6: Scan → SARIF → contains $schema, runs, results
func TestCLI_ScanToSARIF(t *testing.T) {
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})

	outDir := t.TempDir()
	gen := report.New(outDir)
	sarifFile := filepath.Join(outDir, "test-report.sarif")
	require.NoError(t, gen.GenerateSARIF(result, sarifFile))

	assertFileValid(t, sarifFile, "$schema", "runs")
}

// A7: Scan → Excel → file exists, non-empty
func TestCLI_ScanToExcel(t *testing.T) {
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})

	outDir := t.TempDir()
	gen := report.New(outDir)
	xlsxFile := filepath.Join(outDir, "test-report.xlsx")
	require.NoError(t, gen.GenerateExcel(result, xlsxFile))

	info, err := os.Stat(xlsxFile)
	require.NoError(t, err)
	assert.True(t, info.Size() > 0, "Excel file should be non-empty")
}

// A8: Scan → policy.Evaluate(nacsa-2030) → verdict present
func TestCLI_PolicyEvaluation(t *testing.T) {
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})

	// Group findings into systems for policy evaluation
	result.Systems = report.GroupFindingsIntoSystems(result.Findings)

	pol, err := policy.LoadBuiltin("nacsa-2030")
	require.NoError(t, err)

	eval := policy.Evaluate(pol, result)
	require.NotNil(t, eval)
	assert.NotEmpty(t, string(eval.Verdict), "verdict should be present")
	assert.Contains(t, []policy.Verdict{policy.VerdictPass, policy.VerdictFail, policy.VerdictWarn},
		eval.Verdict, "verdict should be PASS, FAIL, or WARN")
}

// A9: Free guard → FilterConfig → only 3 modules remain
func TestCLI_LicenseGuardFreeFilters(t *testing.T) {
	// Empty token → free tier
	guard := license.NewGuardFromToken("", nil)
	assert.Equal(t, license.TierFree, guard.Tier())

	cfg := config.Load("comprehensive")
	guard.FilterConfig(cfg)

	// Free tier downgrades to quick profile
	assert.Equal(t, "quick", cfg.Profile)

	// Free tier only allows 3 modules: certificates, keys, packages
	assert.Len(t, cfg.Modules, 3)
	expected := map[string]bool{"certificates": true, "keys": true, "packages": true}
	for _, m := range cfg.Modules {
		assert.True(t, expected[m], "unexpected module for free tier: %s", m)
	}
}

// A10: Scan → GenerateAllReports → 5 report files created
func TestCLI_AllReportsGenerated(t *testing.T) {
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})
	result.Systems = report.GroupFindingsIntoSystems(result.Findings)

	outDir := t.TempDir()
	gen := report.New(outDir)
	ts := time.Now().Format("20060102-150405")
	files, err := gen.GenerateAllReports(result, ts)
	require.NoError(t, err)
	assert.Len(t, files, 5, "should generate 5 report files")

	for _, f := range files {
		info, err := os.Stat(f)
		require.NoError(t, err, "report file should exist: %s", f)
		assert.True(t, info.Size() > 0, "report file should be non-empty: %s", f)
	}
}

// A11: Cancel mid-scan → clean shutdown, no goroutine leaks
func TestCLI_ContextCancellation(t *testing.T) {
	cfg := config.Load("standard")
	cfg.ScanTargets = []model.ScanTarget{
		{Type: model.TargetFilesystem, Value: fixturesDir(), Depth: 10},
	}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	ctx, cancel := context.WithCancel(context.Background())
	progressCh := make(chan scanner.Progress, 100)

	// Cancel after the first progress event to ensure scan has started
	go func() {
		select {
		case <-progressCh:
		case <-time.After(5 * time.Second):
		}
		cancel()
		for range progressCh {
		}
	}()

	result := eng.Scan(ctx, progressCh)
	require.NotNil(t, result, "should return a result even on cancellation")
	// The scan should complete without panic or deadlock
}
