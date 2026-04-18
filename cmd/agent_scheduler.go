package cmd

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/amiryahaya/triton/internal/agentconfig"
)

// scheduler computes when the next agent scan should fire. It is
// deliberately minimal: one "how long until next" method and one
// "describe yourself for logs" method. Concrete implementations
// encapsulate interval and cron logic.
type scheduler interface {
	// Next returns the duration to sleep from `now` until the next
	// scheduled fire. Returns 0 when the schedule has no future
	// occurrence (shouldn't happen for either production impl but
	// the caller should treat it as "already due" and fire immediately).
	Next(now time.Time) time.Duration

	// Describe returns a human-readable form for startup logs.
	Describe() string
}

// intervalScheduler fires every `interval` with ±jitterPct random jitter.
// Jitter is computed per-call so a fleet of agents that all started at
// the same second drift apart over successive iterations.
type intervalScheduler struct {
	interval  time.Duration
	jitterPct float64 // 0.10 for ±10%, 0 for no jitter
}

// Next returns interval + jitter, clamped at 0 to avoid negative sleeps
// when interval is 0 or jitter math underflows.
func (s intervalScheduler) Next(_ time.Time) time.Duration {
	if s.interval <= 0 {
		return 0
	}
	if s.jitterPct <= 0 {
		return s.interval
	}
	// Range is 2*jitterPct of interval, centered on 0.
	spread := float64(s.interval) * s.jitterPct * 2
	if spread <= 0 {
		return s.interval
	}
	//nolint:gosec // G404: non-cryptographic jitter is intentional
	offset := time.Duration(rand.Int63n(int64(spread))) - time.Duration(spread/2)
	next := s.interval + offset
	if next < 0 {
		return s.interval
	}
	return next
}

// Describe renders the interval and jitter policy for the startup banner.
func (s intervalScheduler) Describe() string {
	if s.jitterPct > 0 {
		return fmt.Sprintf("interval %s (±%.0f%% jitter)", s.interval, s.jitterPct*100)
	}
	return fmt.Sprintf("interval %s", s.interval)
}

// cronScheduler wraps a robfig/cron/v3 Schedule and exposes the
// interface the agent loop needs. Unlike intervalScheduler, jitter is
// expressed as a maximum absolute offset (not a percentage) — the
// whole point of a cron expression is "fire at this wall-clock time",
// so percentage jitter on top of "0 2 * * *" would be surprising.
type cronScheduler struct {
	expr     string
	schedule cron.Schedule
	jitter   time.Duration // 0 = disabled; uniform in [0, jitter)
}

// newCronScheduler parses expr with robfig's standard parser (5-field
// minute/hour/dom/month/dow) and returns a ready-to-call scheduler.
// Returns an error on any parse failure — the agent should fail fast
// at startup rather than silently fall back to one-shot mode.
func newCronScheduler(expr string, jitter time.Duration) (cronScheduler, error) {
	if expr == "" {
		return cronScheduler{}, fmt.Errorf("cron expression is empty")
	}
	parsed, err := cron.ParseStandard(expr)
	if err != nil {
		return cronScheduler{}, fmt.Errorf("invalid cron expression %q: %w", expr, err)
	}
	return cronScheduler{expr: expr, schedule: parsed, jitter: jitter}, nil
}

// cronExhaustedBackoff is the sleep returned when the underlying cron
// library reports no future occurrence (zero-value time). That shouldn't
// happen with ParseStandard expressions in practice, but defending
// against it keeps the agent loop from busy-spinning if robfig ever
// changes semantics or an exotic expression exhausts its 5-year search.
const cronExhaustedBackoff = 24 * time.Hour

// Next returns the duration from `now` until the next cron fire time,
// optionally with positive uniform jitter in [0, jitter). The jitter
// is additive (never negative) to preserve the "fire at or after the
// scheduled time" contract that operators expect from cron.
func (s cronScheduler) Next(now time.Time) time.Duration {
	nextFire := s.schedule.Next(now)
	if nextFire.IsZero() {
		return cronExhaustedBackoff
	}
	delta := nextFire.Sub(now)
	if delta < 0 {
		delta = 0
	}
	if s.jitter <= 0 {
		return delta
	}
	//nolint:gosec // G404: non-cryptographic jitter is intentional
	extra := time.Duration(rand.Int63n(int64(s.jitter)))
	return delta + extra
}

// Describe returns the expression plus any jitter, so the startup
// banner reveals exactly what the operator asked for.
func (s cronScheduler) Describe() string {
	if s.jitter > 0 {
		return fmt.Sprintf("cron %q (+[0, %s) jitter, local time)", s.expr, s.jitter)
	}
	return fmt.Sprintf("cron %q (local time)", s.expr)
}

// Compile-time interface assertions.
var (
	_ scheduler = intervalScheduler{}
	_ scheduler = cronScheduler{}
)

// intervalJitterPct is the ±jitter fraction applied in interval mode.
// Extracted as a constant so the scheduler and startup banner can
// quote the same number.
const intervalJitterPct = 0.10

// newSchedulerFromSpec builds the runtime scheduler from a resolved
// ScheduleSpec. Returns (nil, nil) for one-shot mode so the agent
// loop can short-circuit. Returns an error only when the spec is
// syntactically unusable (currently: invalid cron expression).
func newSchedulerFromSpec(spec agentconfig.ScheduleSpec) (scheduler, error) {
	switch spec.Kind {
	case agentconfig.ScheduleKindCron:
		return newCronScheduler(spec.CronExpr, spec.Jitter)
	case agentconfig.ScheduleKindInterval:
		return intervalScheduler{
			interval:  spec.Interval,
			jitterPct: intervalJitterPct,
		}, nil
	case agentconfig.ScheduleKindOneShot:
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown schedule kind %q", spec.Kind)
	}
}
