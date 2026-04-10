package analytics

import (
	"fmt"
	"math"
	"time"

	"github.com/amiryahaya/triton/pkg/store"
)

// flatThresholdPercent is the pace-per-month floor below which the
// projection is labeled "insufficient-movement" rather than
// extrapolated to an absurd year. Below this, any extrapolation
// produces projected years hundreds of years out. Operators should
// see "nothing is changing" instead. Hard-coded per spec §4.
const flatThresholdPercent = 0.1

// maxProjectionYears is the sanity cap for the projection — any
// projected year more than this far out is surfaced as "capped"
// rather than "on track for year 2400". Hard-coded per spec §4.
const maxProjectionYears = 70

// ComputeProjection takes an org-wide trend and projects when the
// org will reach targetPercent readiness at current pace.
// targetPercent and deadlineYear come from the org's
// executive_target_percent and executive_deadline_year columns
// (defaults 80/2030). Pure function — no DB, one clock read for
// "current year".
//
// Math spec:
//  1. No monthly points          → insufficient-history
//  2. lastReadiness >= target    → already-complete
//  3. Fewer than 2 points        → insufficient-history
//  4. pace < 0                   → regressing
//  5. pace < flatThresholdPercent → insufficient-movement
//  6. projectedYears > cap        → capped
//  7. projectedYear <= deadline   → on-track
//  8. otherwise                   → behind-schedule
//
// See docs/plans/2026-04-10-analytics-phase-2-design.md §5.2 for
// full rationale.
func ComputeProjection(trend store.TrendSummary, targetPercent float64, deadlineYear int) store.ProjectionSummary {
	out := store.ProjectionSummary{
		TargetPercent: targetPercent,
		DeadlineYear:  deadlineYear,
	}

	n := len(trend.MonthlyPoints)
	if n == 0 {
		out.Status = "insufficient-history"
		out.ExplanationText = "Insufficient history — run at least two scans across different months."
		return out
	}

	lastReadiness := trend.MonthlyPoints[n-1].Readiness

	// Already past the target — short-circuit.
	if lastReadiness >= targetPercent {
		out.Status = "already-complete"
		out.ExplanationText = fmt.Sprintf("Already at %.1f%% — past the %g%% target.", lastReadiness, targetPercent)
		return out
	}

	if n < 2 {
		out.Status = "insufficient-history"
		out.ExplanationText = "Insufficient history — need at least two months of scan data to compute pace."
		return out
	}

	// Compute pace. We use the MONTHS BETWEEN first and last bucket,
	// not (n-1), because gaps in monthly data (e.g., no scans in
	// March) mean adjacent buckets may span more than one month.
	first := trend.MonthlyPoints[0]
	last := trend.MonthlyPoints[n-1]
	firstMonth, errA := time.Parse("2006-01", first.Month)
	lastMonth, errB := time.Parse("2006-01", last.Month)
	if errA != nil || errB != nil {
		// Should never happen — trend.go formats months with this
		// exact layout — but guard anyway.
		out.Status = "insufficient-history"
		out.ExplanationText = "Insufficient history — monthly data could not be parsed."
		return out
	}
	monthsBetween := monthsDiff(firstMonth, lastMonth)
	if monthsBetween < 1 {
		monthsBetween = 1
	}

	rawPace := (lastReadiness - first.Readiness) / float64(monthsBetween)
	out.PacePerMonth = roundTo1Decimal(rawPace) // display value only

	// Regressing: any negative pace is worth flagging.
	if rawPace < 0 {
		out.Status = "regressing"
		out.ExplanationText = fmt.Sprintf(
			"Regressing — net readiness dropping %.1f%% per month over the last %d months.",
			-out.PacePerMonth, monthsBetween)
		return out
	}

	// Flat: below the noise floor we can reliably measure.
	if rawPace < flatThresholdPercent {
		out.Status = "insufficient-movement"
		out.ExplanationText = fmt.Sprintf(
			"Insufficient movement — readiness flat over the last %d months.",
			monthsBetween)
		return out
	}

	// Compute projection using raw (unrounded) pace to avoid
	// compounding rounding error into the projected year.
	remaining := targetPercent - lastReadiness
	monthsNeeded := remaining / rawPace
	yearsNeeded := monthsNeeded / 12
	currentYear := time.Now().UTC().Year()

	if yearsNeeded > float64(maxProjectionYears) {
		out.Status = "capped"
		out.ExplanationText = fmt.Sprintf(
			"Capped — at current pace of %.1f%%/month, reaching %g%% would take over %d years.",
			out.PacePerMonth, targetPercent, maxProjectionYears)
		return out // ProjectedYear stays 0 per documented contract
	}

	projectedYear := currentYear + int(math.Ceil(yearsNeeded))
	out.ProjectedYear = projectedYear

	if projectedYear <= deadlineYear {
		out.Status = "on-track"
		out.ExplanationText = fmt.Sprintf(
			"On track — %.1f%%/month pace projects %g%% readiness by %d.",
			out.PacePerMonth, targetPercent, projectedYear)
	} else {
		out.Status = "behind-schedule"
		out.ExplanationText = fmt.Sprintf(
			"Behind schedule — %.1f%%/month pace projects %g%% readiness by %d, past the %d deadline.",
			out.PacePerMonth, targetPercent, projectedYear, deadlineYear)
	}
	return out
}

// monthsDiff returns the number of full calendar months between two
// month-only timestamps. Both inputs are assumed to be first-of-month
// (which is what time.Parse("2006-01", ...) produces).
func monthsDiff(earlier, later time.Time) int {
	y := later.Year() - earlier.Year()
	m := int(later.Month()) - int(earlier.Month())
	return y*12 + m
}
