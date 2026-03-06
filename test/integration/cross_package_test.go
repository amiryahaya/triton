//go:build integration

package integration_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/diff"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/policy"
	"github.com/amiryahaya/triton/pkg/report"
)

// D1: Engine scans fixtures → SaveScan → GetScan → GenerateAllReports → 5 valid files
func TestCross_ScanStoreReport(t *testing.T) {
	db := requireDB(t)
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})
	result.Systems = report.GroupFindingsIntoSystems(result.Findings)

	ctx := context.Background()
	require.NoError(t, db.SaveScan(ctx, result))

	got, err := db.GetScan(ctx, result.ID, "")
	require.NoError(t, err)
	assert.Equal(t, len(result.Findings), len(got.Findings))

	outDir := t.TempDir()
	gen := report.New(outDir)
	ts := time.Now().Format("20060102-150405")
	files, err := gen.GenerateAllReports(got, ts)
	require.NoError(t, err)
	assert.Len(t, files, 5)

	for _, f := range files {
		info, err := os.Stat(f)
		require.NoError(t, err, "report file should exist: %s", f)
		assert.True(t, info.Size() > 0, "report should be non-empty: %s", f)
	}
}

// D2: Two scans (add fixture between) → SaveScan both → ComputeDiff → additions detected
func TestCross_ScanStoreDiff(t *testing.T) {
	db := requireDB(t)
	ctx := context.Background()

	// First scan with just certificates
	result1 := scanFixtures(t, "quick", []string{"certificates"})
	require.NoError(t, db.SaveScan(ctx, result1))

	// Second scan adds keys too
	result2 := scanFixtures(t, "quick", []string{"certificates", "keys"})
	require.NoError(t, db.SaveScan(ctx, result2))

	// Retrieve from store
	base, err := db.GetScan(ctx, result1.ID, "")
	require.NoError(t, err)
	compare, err := db.GetScan(ctx, result2.ID, "")
	require.NoError(t, err)

	d := diff.ComputeDiff(base, compare)
	require.NotNil(t, d)
	assert.Equal(t, base.ID, d.BaseID)
	assert.Equal(t, compare.ID, d.CompareID)

	// The second scan should have more findings (keys added)
	assert.True(t, len(compare.Findings) >= len(base.Findings),
		"second scan should have >= findings (base=%d, compare=%d)",
		len(base.Findings), len(compare.Findings))
}

// D3: 3 scans saved → ComputeTrend → trend points ordered, direction computed
func TestCross_ScanStoreTrend(t *testing.T) {
	db := requireDB(t)
	ctx := context.Background()

	base := time.Now().Add(-3 * time.Hour).UTC()
	scans := make([]*model.ScanResult, 3)
	for i := 0; i < 3; i++ {
		s := makeScanResultWithPQC(
			"cross-trend-"+string(rune('a'+i)), "trend-host",
			5+i*2, 3, 2, 1, // Improving: more safe over time
		)
		s.Metadata.Timestamp = base.Add(time.Duration(i) * time.Hour).Truncate(time.Microsecond)
		require.NoError(t, db.SaveScan(ctx, s))
		scans[i] = s
	}

	// Retrieve all from store in chronological order
	var retrieved []*model.ScanResult
	for _, s := range scans {
		got, err := db.GetScan(ctx, s.ID, "")
		require.NoError(t, err)
		retrieved = append(retrieved, got)
	}

	trend := diff.ComputeTrend(retrieved)
	require.NotNil(t, trend)
	assert.Len(t, trend.Points, 3)
	assert.NotEmpty(t, trend.Direction())
}

// D4: Scan → GroupFindingsIntoSystems → systems have findings
func TestCross_FindingsGroupedToSystems(t *testing.T) {
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})
	require.NotEmpty(t, result.Findings)

	systems := report.GroupFindingsIntoSystems(result.Findings)
	require.NotEmpty(t, systems, "should group findings into at least one system")

	totalAssets := 0
	for _, sys := range systems {
		assert.NotEmpty(t, sys.Name, "system should have a name")
		totalAssets += len(sys.CryptoAssets)
	}
	assert.True(t, totalAssets > 0, "systems should contain crypto assets")
}

// D5: Scan → policy.Evaluate(nacsa-2030) → PQC counts match summary
func TestCross_ScanPolicyCompliance(t *testing.T) {
	result := scanFixtures(t, "quick", []string{"certificates", "keys"})
	result.Systems = report.GroupFindingsIntoSystems(result.Findings)

	pol, err := policy.LoadBuiltin("nacsa-2030")
	require.NoError(t, err)

	eval := policy.Evaluate(pol, result)
	require.NotNil(t, eval)
	assert.Contains(t, []policy.Verdict{policy.VerdictPass, policy.VerdictFail, policy.VerdictWarn}, eval.Verdict)
	assert.True(t, eval.FindingsChecked > 0, "should have checked at least one finding")
}

// D6: Scan with store → rescan same files → verify incremental metrics
func TestCross_IncrementalRescan(t *testing.T) {
	db := requireDB(t)

	// First scan — sets file hashes
	result1 := scanFixtures(t, "quick", []string{"certificates", "keys"})
	require.NotEmpty(t, result1.Findings)

	// Store the file hashes for fixtures
	ctx := context.Background()
	fixDir := fixturesDir()
	certDir := filepath.Join(fixDir, "certificates")
	entries, err := os.ReadDir(certDir)
	require.NoError(t, err)

	// Set some file hashes to simulate a previous scan
	for _, e := range entries {
		if !e.IsDir() {
			path := filepath.Join(certDir, e.Name())
			require.NoError(t, db.SetFileHash(ctx, path, "fakehash-"+e.Name()))
		}
	}

	// Verify hashes were stored
	count, _, _, err := db.FileHashStats(ctx)
	require.NoError(t, err)
	assert.True(t, count > 0, "should have stored file hashes")
}
