// Package analytics provides pure functions that turn raw scan data
// into executive-summary insights for Analytics Phase 2.
//
// All functions in this package are pure: given the same input, they
// produce the same output, with no database access, no network calls,
// and no clock reads beyond what's strictly necessary for math. This
// makes them trivially unit-testable — see the _test.go files.
//
// The package sits between pkg/store (raw data) and pkg/server
// (HTTP orchestration). Handler code calls pkg/store to fetch data,
// passes it to pkg/analytics for computation, and returns the result
// as JSON.
//
// Phase 2 adds three public functions:
//
//   - ComputeOrgTrend: monthly-bucketed trend direction + series
//   - ComputeProjection: pace-based "when will we reach X%" estimate
//   - ComputeMachineHealth: red/yellow/green tier rollup
//
// Design rationale and full algorithm specs live in
// docs/plans/2026-04-10-analytics-phase-2-design.md §5.
package analytics
