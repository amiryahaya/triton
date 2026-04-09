package analytics

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/store"
)

// tpa is a short helper to build a TrendSummary fixture for
// projection tests. Direction is computed by the real
// ComputeOrgTrend elsewhere; here we hand-craft the monthly series
// the projection consumes.
func tpa(points ...store.TrendMonthPoint) store.TrendSummary {
	if len(points) < 2 {
		return store.TrendSummary{Direction: "insufficient-history", MonthlyPoints: points}
	}
	delta := points[len(points)-1].Readiness - points[0].Readiness
	dir := "stable"
	if delta > 1.0 {
		dir = "improving"
	} else if delta < -1.0 {
		dir = "declining"
	}
	return store.TrendSummary{
		Direction:     dir,
		DeltaPercent:  delta,
		MonthlyPoints: points,
	}
}

func TestComputeProjection_InsufficientHistoryZeroPoints(t *testing.T) {
	trend := store.TrendSummary{
		Direction:     "insufficient-history",
		MonthlyPoints: []store.TrendMonthPoint{},
	}
	got := ComputeProjection(trend, 80.0, 2030)
	assert.Equal(t, "insufficient-history", got.Status)
	assert.Equal(t, 80.0, got.TargetPercent)
	assert.Equal(t, 2030, got.DeadlineYear)
	assert.Equal(t, 0, got.ProjectedYear)
	assert.Contains(t, got.ExplanationText, "Insufficient history")
}

func TestComputeProjection_InsufficientHistoryOnePoint(t *testing.T) {
	trend := store.TrendSummary{
		Direction: "insufficient-history",
		MonthlyPoints: []store.TrendMonthPoint{
			{Month: "2026-02", Readiness: 45.0, TotalFindings: 100},
		},
	}
	got := ComputeProjection(trend, 80.0, 2030)
	assert.Equal(t, "insufficient-history", got.Status)
}

func TestComputeProjection_AlreadyCompleteAtOrAboveTarget(t *testing.T) {
	// Last reading 85%, target 80 — already past.
	trend := tpa(
		store.TrendMonthPoint{Month: "2026-01", Readiness: 80.0, TotalFindings: 100},
		store.TrendMonthPoint{Month: "2026-02", Readiness: 85.0, TotalFindings: 100},
	)
	got := ComputeProjection(trend, 80.0, 2030)
	assert.Equal(t, "already-complete", got.Status)
	assert.Contains(t, got.ExplanationText, "85")
	assert.Contains(t, got.ExplanationText, "80")
}

func TestComputeProjection_NegativePaceRegressing(t *testing.T) {
	// Declining from 60% to 55% over 2 months = -2.5%/mo
	trend := tpa(
		store.TrendMonthPoint{Month: "2026-01", Readiness: 60.0, TotalFindings: 100},
		store.TrendMonthPoint{Month: "2026-03", Readiness: 55.0, TotalFindings: 100},
	)
	got := ComputeProjection(trend, 80.0, 2030)
	assert.Equal(t, "regressing", got.Status)
	assert.Equal(t, -2.5, got.PacePerMonth)
	assert.Equal(t, 0, got.ProjectedYear, "regressing has no projection")
	assert.Contains(t, got.ExplanationText, "Regressing")
	assert.Contains(t, got.ExplanationText, "2.5")
}

func TestComputeProjection_BelowFlatThresholdInsufficientMovement(t *testing.T) {
	// +0.1% over 4 months = 0.025%/mo — below 0.1 flat floor.
	trend := tpa(
		store.TrendMonthPoint{Month: "2026-01", Readiness: 50.0, TotalFindings: 100},
		store.TrendMonthPoint{Month: "2026-05", Readiness: 50.1, TotalFindings: 100},
	)
	got := ComputeProjection(trend, 80.0, 2030)
	assert.Equal(t, "insufficient-movement", got.Status)
	assert.Contains(t, got.ExplanationText, "Insufficient movement")
}

func TestComputeProjection_PositivePaceOnTrack(t *testing.T) {
	// +15% over 6 months = 2.5%/mo, remaining 15% → 6 months → within year
	trend := tpa(
		store.TrendMonthPoint{Month: "2026-01", Readiness: 50.0, TotalFindings: 100},
		store.TrendMonthPoint{Month: "2026-07", Readiness: 65.0, TotalFindings: 100},
	)
	got := ComputeProjection(trend, 80.0, 2030)
	assert.Equal(t, "on-track", got.Status)
	assert.Equal(t, 2.5, got.PacePerMonth)
	assert.True(t, got.ProjectedYear >= 2026 && got.ProjectedYear <= 2027,
		"projected year should be within current year + 1, got %d", got.ProjectedYear)
	assert.Contains(t, got.ExplanationText, "On track")
}

func TestComputeProjection_PositivePaceBehindSchedule(t *testing.T) {
	// +3% over 6 months = 0.5%/mo
	// Remaining 77% → 154 months → ~13 years → year >= 2039
	trend := tpa(
		store.TrendMonthPoint{Month: "2026-01", Readiness: 0.0, TotalFindings: 1000},
		store.TrendMonthPoint{Month: "2026-07", Readiness: 3.0, TotalFindings: 1000},
	)
	got := ComputeProjection(trend, 80.0, 2030)
	assert.Equal(t, "behind-schedule", got.Status)
	assert.Equal(t, 0.5, got.PacePerMonth)
	assert.True(t, got.ProjectedYear > 2030, "projected year must be past deadline, got %d", got.ProjectedYear)
	assert.Contains(t, got.ExplanationText, "Behind schedule")
}

func TestComputeProjection_SanityCapOver70Years(t *testing.T) {
	// target=100, start 0.9%, +0.11%/mo → 99/0.11 = 900 months = 75 years → CAPPED
	trend := tpa(
		store.TrendMonthPoint{Month: "2026-01", Readiness: 0.9, TotalFindings: 1000},
		store.TrendMonthPoint{Month: "2026-11", Readiness: 2.0, TotalFindings: 1000},
	)
	got := ComputeProjection(trend, 100.0, 2030)
	assert.Equal(t, "capped", got.Status)
	assert.Contains(t, got.ExplanationText, "70 years")
}

func TestComputeProjection_CustomTargetPercentFromOrg(t *testing.T) {
	// +6% over 6 months = 1%/mo — steady improvement
	// Target 60 (not default 80), remaining 40 → 40 months → ~3.5 years
	trend := tpa(
		store.TrendMonthPoint{Month: "2026-01", Readiness: 14.0, TotalFindings: 100},
		store.TrendMonthPoint{Month: "2026-07", Readiness: 20.0, TotalFindings: 100},
	)
	got := ComputeProjection(trend, 60.0, 2030)
	assert.Equal(t, 60.0, got.TargetPercent, "custom target must propagate into the response")
	assert.True(t, got.Status == "on-track" || got.Status == "behind-schedule",
		"expected on-track or behind-schedule, got %q", got.Status)
}

func TestComputeProjection_CustomDeadlineYearFromOrg(t *testing.T) {
	// Same pace, but custom deadline 2035 → more headroom → more
	// likely to be on-track.
	trend := tpa(
		store.TrendMonthPoint{Month: "2026-01", Readiness: 20.0, TotalFindings: 100},
		store.TrendMonthPoint{Month: "2026-07", Readiness: 26.0, TotalFindings: 100},
	)
	got := ComputeProjection(trend, 80.0, 2035)
	assert.Equal(t, 2035, got.DeadlineYear, "custom deadline must propagate into the response")
}

func TestComputeProjection_ExplanationTextFormatting(t *testing.T) {
	// Verify explanation text is a complete sentence ending with
	// punctuation. This catches accidental regressions in
	// fmt.Sprintf formatting.
	trend := tpa(
		store.TrendMonthPoint{Month: "2026-01", Readiness: 50.0, TotalFindings: 100},
		store.TrendMonthPoint{Month: "2026-07", Readiness: 65.0, TotalFindings: 100},
	)
	got := ComputeProjection(trend, 80.0, 2030)
	require.NotEmpty(t, got.ExplanationText)
	last := got.ExplanationText[len(got.ExplanationText)-1]
	assert.True(t, last == '.' || last == '!', "explanation should end with punctuation, got %q", got.ExplanationText)
	assert.False(t, strings.HasPrefix(got.ExplanationText, " "), "no leading whitespace")
}
