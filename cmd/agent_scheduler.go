package cmd

import (
	"fmt"
	"math/rand"
	"time"
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
