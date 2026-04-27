package analytics

import (
	"github.com/amiryahaya/triton/pkg/store"
)

// ComputeMachineHealth classifies each scan summary into red/yellow/
// green tiers for the executive summary's Machine Health rollup.
//
// Rules (strict, no magnitude threshold):
//
//	red    — Unsafe > 0 (one unsafe finding is a legitimate crisis)
//	yellow — no Unsafe, Deprecated > 0
//	green  — everything else (including zero-finding machines)
//
// Input is typically the result of LatestByHostname (so each host
// is counted once). Pure function; no DB access. See
// docs/plans/2026-04-10-analytics-phase-2-design.md §5.3 for the
// rationale on "any unsafe = red" strictness.

// ComputeReadiness sums safe and total findings across the latest
// scan per host and returns a ReadinessSummary with the headline
// percentage. Pure function; no DB access.
func ComputeReadiness(latestPerHost []store.ScanSummary) store.ReadinessSummary {
	var safe, total int
	for i := range latestPerHost {
		s := &latestPerHost[i]
		safe += s.Safe
		total += s.Safe + s.Transitional + s.Deprecated + s.Unsafe
	}
	percent := 0.0
	if total > 0 {
		percent = roundTo1Decimal(float64(safe) / float64(total) * 100)
	}
	return store.ReadinessSummary{
		Percent:       percent,
		TotalFindings: total,
		SafeFindings:  safe,
	}
}

func ComputeMachineHealth(machines []store.ScanSummary) store.MachineHealthTiers {
	var out store.MachineHealthTiers
	for i := range machines {
		m := &machines[i]
		switch {
		case m.Unsafe > 0:
			out.Red++
		case m.Deprecated > 0:
			out.Yellow++
		default:
			out.Green++
		}
	}
	out.Total = out.Red + out.Yellow + out.Green
	return out
}
