package jobqueue

import (
	"context"
	"log"
	"time"
)

// Reclaimer is the single method StaleReaper needs from any queue-backed
// store. Both Queue itself and the per-bounded-context PostgresStore
// types satisfy this interface.
type Reclaimer interface {
	ReclaimStale(ctx context.Context, cutoff time.Time) error
}

// StaleReaper periodically flips jobs stuck in non-terminal states
// (claimed / running) back to queued so another engine can pick them up.
// It replaces the per-bounded-context StaleReaper implementations that
// were previously duplicated across discovery, credentials, and scanjobs.
//
// Zero-valued fields get safe defaults on Run:
//   - Interval: 5m  (how often we sweep)
//   - Timeout:  15m (claimed_at older than this is considered abandoned)
//   - Now:      time.Now (injectable so tests can pin the cutoff)
type StaleReaper struct {
	Reclaimer Reclaimer
	Label     string        // log prefix, e.g. "discovery"
	Interval  time.Duration // default 5min
	Timeout   time.Duration // default 15min
	Now       func() time.Time
}

// Run blocks until ctx is cancelled. Per-sweep errors are logged but
// never stop the loop — a transient DB blip shouldn't kill the reaper.
func (r *StaleReaper) Run(ctx context.Context) {
	if r.Interval == 0 {
		r.Interval = 5 * time.Minute
	}
	if r.Timeout == 0 {
		r.Timeout = 15 * time.Minute
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.Reclaimer.ReclaimStale(ctx, r.Now().Add(-r.Timeout)); err != nil {
				log.Printf("%s stale reaper: %v", r.Label, err)
			}
		}
	}
}
