package analytics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

func TestComputeOrgTrend_EmptyInput(t *testing.T) {
	got := ComputeOrgTrend(nil)
	assert.Equal(t, "insufficient-history", got.Direction)
	assert.Equal(t, 0.0, got.DeltaPercent)
	assert.Empty(t, got.MonthlyPoints)
}

func TestComputeOrgTrend_SingleScanReturnsInsufficientHistory(t *testing.T) {
	scans := []store.ScanSummary{
		scanSummaryAt("host-1", mustParseMonth("2026-02-15"), 50, 20, 20, 10),
	}
	got := ComputeOrgTrend(scans)
	assert.Equal(t, "insufficient-history", got.Direction)
	// Single-scan case still emits the one monthly point for the
	// UI to render a solitary dot if it chooses to.
	assert.Len(t, got.MonthlyPoints, 1)
	assert.Equal(t, "2026-02", got.MonthlyPoints[0].Month)
}

func TestComputeOrgTrend_TwoScansSameMonthReturnsInsufficientHistory(t *testing.T) {
	scans := []store.ScanSummary{
		scanSummaryAt("host-1", mustParseMonth("2026-02-10"), 40, 20, 20, 20),
		scanSummaryAt("host-2", mustParseMonth("2026-02-20"), 60, 20, 15, 5),
	}
	got := ComputeOrgTrend(scans)
	assert.Equal(t, "insufficient-history", got.Direction)
	assert.Len(t, got.MonthlyPoints, 1)
}

func TestComputeOrgTrend_TwoMonthsImprovingReturnsImproving(t *testing.T) {
	// Month 1: 40 safe / 100 total = 40%
	// Month 2: 60 safe / 100 total = 60%
	// Delta = +20% > 1% threshold → improving
	scans := []store.ScanSummary{
		scanSummaryAt("host-1", mustParseMonth("2026-01-15"), 40, 30, 20, 10),
		scanSummaryAt("host-1", mustParseMonth("2026-02-15"), 60, 20, 15, 5),
	}
	got := ComputeOrgTrend(scans)
	assert.Equal(t, "improving", got.Direction)
	assert.Equal(t, 20.0, got.DeltaPercent)
	require.Len(t, got.MonthlyPoints, 2)
	assert.Equal(t, "2026-01", got.MonthlyPoints[0].Month)
	assert.Equal(t, 40.0, got.MonthlyPoints[0].Readiness)
	assert.Equal(t, "2026-02", got.MonthlyPoints[1].Month)
	assert.Equal(t, 60.0, got.MonthlyPoints[1].Readiness)
}

func TestComputeOrgTrend_TwoMonthsDecliningReturnsDeclining(t *testing.T) {
	// Month 1: 60 safe / 100 = 60%
	// Month 2: 40 safe / 100 = 40%
	// Delta = -20% < -1% → declining
	scans := []store.ScanSummary{
		scanSummaryAt("host-1", mustParseMonth("2026-01-15"), 60, 20, 15, 5),
		scanSummaryAt("host-1", mustParseMonth("2026-02-15"), 40, 30, 20, 10),
	}
	got := ComputeOrgTrend(scans)
	assert.Equal(t, "declining", got.Direction)
	assert.Equal(t, -20.0, got.DeltaPercent)
}

func TestComputeOrgTrend_WithinNoiseThresholdReturnsStable(t *testing.T) {
	// Month 1: 50.0%
	// Month 2: 50.5%
	// Delta = +0.5% ≤ 1% → stable
	scans := []store.ScanSummary{
		scanSummaryAt("host-1", mustParseMonth("2026-01-15"), 500, 200, 200, 100),
		scanSummaryAt("host-1", mustParseMonth("2026-02-15"), 505, 195, 200, 100),
	}
	got := ComputeOrgTrend(scans)
	assert.Equal(t, "stable", got.Direction)
}

func TestComputeOrgTrend_MultipleHostsInSameMonthBucketed(t *testing.T) {
	// Month 1: host A (50 safe/100) + host B (30 safe/100) = 80/200 = 40%
	// Month 2: host A (70 safe/100) + host B (50 safe/100) = 120/200 = 60%
	// Delta = +20% → improving
	scans := []store.ScanSummary{
		scanSummaryAt("host-A", mustParseMonth("2026-01-10"), 50, 20, 20, 10),
		scanSummaryAt("host-B", mustParseMonth("2026-01-10"), 30, 30, 20, 20),
		scanSummaryAt("host-A", mustParseMonth("2026-02-10"), 70, 15, 10, 5),
		scanSummaryAt("host-B", mustParseMonth("2026-02-10"), 50, 25, 15, 10),
	}
	got := ComputeOrgTrend(scans)
	assert.Equal(t, "improving", got.Direction)
	require.Len(t, got.MonthlyPoints, 2)
	assert.Equal(t, 40.0, got.MonthlyPoints[0].Readiness)
	assert.Equal(t, 60.0, got.MonthlyPoints[1].Readiness)
}

func TestComputeOrgTrend_HostReScansInSameMonthKeepsLatest(t *testing.T) {
	// Host A scans twice in January. Only the LATEST scan per host
	// per month counts for the bucket aggregate.
	// 1st scan: 30 safe/100 = 30%
	// 2nd scan: 70 safe/100 = 70%  ← this one counts
	scans := []store.ScanSummary{
		scanSummaryAt("host-A", mustParseMonth("2026-01-05"), 30, 30, 30, 10),
		scanSummaryAt("host-A", mustParseMonth("2026-01-25"), 70, 15, 10, 5),
		scanSummaryAt("host-A", mustParseMonth("2026-02-15"), 80, 10, 7, 3),
	}
	got := ComputeOrgTrend(scans)
	require.Len(t, got.MonthlyPoints, 2)
	// January bucket should reflect the 2nd (later) scan — 70%, not 30%
	assert.Equal(t, 70.0, got.MonthlyPoints[0].Readiness, "latest scan per host per month wins")
}

func TestComputeOrgTrend_HostMissingFromLaterMonthStillComputes(t *testing.T) {
	// Host A is in both months, Host B only in Jan.
	// January: A (50/100) + B (30/100) = 80/200 = 40%
	// February: A only (70/100) = 70/100 = 70%
	// Delta = +30% → improving
	scans := []store.ScanSummary{
		scanSummaryAt("host-A", mustParseMonth("2026-01-15"), 50, 20, 20, 10),
		scanSummaryAt("host-B", mustParseMonth("2026-01-15"), 30, 30, 20, 20),
		scanSummaryAt("host-A", mustParseMonth("2026-02-15"), 70, 15, 10, 5),
	}
	got := ComputeOrgTrend(scans)
	assert.Equal(t, "improving", got.Direction)
	require.Len(t, got.MonthlyPoints, 2)
	assert.Equal(t, 40.0, got.MonthlyPoints[0].Readiness)
	assert.Equal(t, 70.0, got.MonthlyPoints[1].Readiness)
}

func TestComputeOrgTrend_MonthlyPointsSortedChronologically(t *testing.T) {
	// Provide scans in REVERSE chronological order to verify sorting.
	scans := []store.ScanSummary{
		scanSummaryAt("host-1", mustParseMonth("2026-03-15"), 80, 10, 5, 5),
		scanSummaryAt("host-1", mustParseMonth("2026-01-15"), 40, 30, 20, 10),
		scanSummaryAt("host-1", mustParseMonth("2026-02-15"), 60, 20, 15, 5),
	}
	got := ComputeOrgTrend(scans)
	require.Len(t, got.MonthlyPoints, 3)
	assert.Equal(t, "2026-01", got.MonthlyPoints[0].Month)
	assert.Equal(t, "2026-02", got.MonthlyPoints[1].Month)
	assert.Equal(t, "2026-03", got.MonthlyPoints[2].Month)
}

func TestComputeOrgTrend_ExactlyAtThresholdIsStable(t *testing.T) {
	// Delta of exactly +1.0% should be "stable" because the
	// threshold is strict (delta > 1.0, not >=).
	// 50 safe / 100 total = 50%, then 51 safe / 100 = 51%.
	// Delta = 1.0% — at the threshold, not past it.
	scans := []store.ScanSummary{
		scanSummaryAt("host-1", mustParseMonth("2026-01-15"), 50, 20, 20, 10),
		scanSummaryAt("host-1", mustParseMonth("2026-02-15"), 51, 19, 20, 10),
	}
	got := ComputeOrgTrend(scans)
	assert.Equal(t, "stable", got.Direction, "delta of exactly 1.0 should be stable, not improving")
	assert.Equal(t, 1.0, got.DeltaPercent)
}

// --- LatestByHostname tests ---

func TestLatestByHostname_Nil(t *testing.T) {
	got := LatestByHostname(nil)
	assert.Nil(t, got)
}

func TestLatestByHostname_SingleHost(t *testing.T) {
	scans := []store.ScanSummary{
		scanSummaryAt("host-1", mustParseMonth("2026-01-15"), 50, 20, 20, 10),
	}
	got := LatestByHostname(scans)
	require.Len(t, got, 1)
	assert.Equal(t, "host-1", got[0].Hostname)
}

func TestLatestByHostname_KeepsLatestPerHost(t *testing.T) {
	scans := []store.ScanSummary{
		scanSummaryAt("host-1", mustParseMonth("2026-01-05"), 30, 30, 30, 10),
		scanSummaryAt("host-1", mustParseMonth("2026-03-15"), 80, 10, 5, 5),
		scanSummaryAt("host-1", mustParseMonth("2026-02-10"), 50, 20, 20, 10),
	}
	got := LatestByHostname(scans)
	require.Len(t, got, 1)
	assert.Equal(t, "2026-03-15", got[0].Timestamp.Format("2006-01-02"),
		"should keep the latest scan by timestamp")
	assert.Equal(t, 80, got[0].Safe)
}

func TestLatestByHostname_MultiHost(t *testing.T) {
	scans := []store.ScanSummary{
		scanSummaryAt("host-A", mustParseMonth("2026-01-15"), 40, 20, 20, 20),
		scanSummaryAt("host-B", mustParseMonth("2026-02-15"), 60, 20, 15, 5),
		scanSummaryAt("host-A", mustParseMonth("2026-03-15"), 70, 15, 10, 5),
	}
	got := LatestByHostname(scans)
	require.Len(t, got, 2)
	byHost := map[string]store.ScanSummary{}
	for _, s := range got {
		byHost[s.Hostname] = s
	}
	assert.Equal(t, 70, byHost["host-A"].Safe, "host-A should have the March scan")
	assert.Equal(t, 60, byHost["host-B"].Safe, "host-B has only one scan")
}
