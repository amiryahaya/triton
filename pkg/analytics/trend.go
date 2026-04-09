package analytics

import (
	"math"
	"sort"

	"github.com/amiryahaya/triton/pkg/store"
)

// ComputeOrgTrend computes an org-wide monthly-bucketed trend from a
// chronologically-unsorted slice of scan summaries. For each (month,
// hostname) pair it keeps the LATEST scan by timestamp, then sums
// safe + total across hosts in each month to compute per-month
// readiness. The resulting monthly series classifies as improving
// (delta > +1%), declining (delta < -1%), or stable.
//
// Pure function — no DB, no clock reads. See
// docs/plans/2026-04-10-analytics-phase-2-design.md §5.1 for
// rationale on the latest-per-host-per-month choice.
func ComputeOrgTrend(scans []store.ScanSummary) store.TrendSummary {
	if len(scans) == 0 {
		return store.TrendSummary{
			Direction:     "insufficient-history",
			MonthlyPoints: []store.TrendMonthPoint{},
		}
	}

	// 1. Group by (month, hostname), keep the latest timestamp.
	type key struct{ month, hostname string }
	latest := make(map[key]store.ScanSummary)
	for _, s := range scans {
		k := key{
			month:    s.Timestamp.UTC().Format("2006-01"),
			hostname: s.Hostname,
		}
		prev, exists := latest[k]
		if !exists || s.Timestamp.After(prev.Timestamp) {
			latest[k] = s
		}
	}

	// 2. Aggregate by month: sum safe + total across hosts.
	type bucket struct {
		safe  int
		total int
	}
	byMonth := make(map[string]*bucket)
	for k, s := range latest {
		b, exists := byMonth[k.month]
		if !exists {
			b = &bucket{}
			byMonth[k.month] = b
		}
		b.safe += s.Safe
		b.total += s.Safe + s.Transitional + s.Deprecated + s.Unsafe
	}

	// 3. Sort months chronologically ("2026-01" < "2026-02"
	// lexicographically matches chronologically).
	months := make([]string, 0, len(byMonth))
	for m := range byMonth {
		months = append(months, m)
	}
	sort.Strings(months)

	// 4. Build the monthly series.
	points := make([]store.TrendMonthPoint, 0, len(months))
	for _, m := range months {
		b := byMonth[m]
		readiness := 0.0
		if b.total > 0 {
			readiness = float64(b.safe) / float64(b.total) * 100
		}
		points = append(points, store.TrendMonthPoint{
			Month:         m,
			Readiness:     roundTo1Decimal(readiness),
			TotalFindings: b.total,
		})
	}

	// 5. Classify direction. Need at least 2 buckets for a
	// meaningful direction; fewer → insufficient-history.
	if len(points) < 2 {
		return store.TrendSummary{
			Direction:     "insufficient-history",
			MonthlyPoints: points,
		}
	}
	delta := roundTo1Decimal(points[len(points)-1].Readiness - points[0].Readiness)
	direction := "stable"
	if delta > 1.0 {
		direction = "improving"
	} else if delta < -1.0 {
		direction = "declining"
	}

	return store.TrendSummary{
		Direction:     direction,
		DeltaPercent:  delta,
		MonthlyPoints: points,
	}
}

// LatestByHostname returns a slice containing only the latest scan
// per hostname from the input. Used by the executive handler to
// narrow a full historical slice down to "currently deployed" state
// for machine-health and policy computations.
//
// Input need not be sorted. Output order is not defined (it's a
// dedup by hostname, not a sort).
func LatestByHostname(scans []store.ScanSummary) []store.ScanSummary {
	if len(scans) == 0 {
		return nil
	}
	latest := make(map[string]store.ScanSummary, len(scans))
	for _, s := range scans {
		prev, exists := latest[s.Hostname]
		if !exists || s.Timestamp.After(prev.Timestamp) {
			latest[s.Hostname] = s
		}
	}
	out := make([]store.ScanSummary, 0, len(latest))
	for _, s := range latest {
		out = append(out, s)
	}
	return out
}

// roundTo1Decimal rounds a float64 to one decimal place. Used for
// every user-facing percentage in the analytics package so clients
// don't need to handle float render precision themselves.
func roundTo1Decimal(x float64) float64 {
	return math.Round(x*10) / 10
}
