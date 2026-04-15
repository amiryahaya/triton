package credentials

import (
	"context"
	"log"
	"time"
)

// StaleReaper periodically flips credential deliveries + test jobs stuck
// in non-terminal states (claimed / running) back to queued so another
// engine can pick them up. The delivery + test queries filter on
// status='queued', so abandoned rows are otherwise invisible to
// ClaimNextDelivery / ClaimNextTest forever. One ticker drives both
// reclaim calls — they share the same cutoff.
//
// Zero-valued fields get safe defaults on Run:
//   - Interval: 5m  (how often we sweep)
//   - Timeout:  15m (claimed_at older than this is considered abandoned)
//   - Now:      time.Now (injectable so tests can pin the cutoff)
type StaleReaper struct {
	Store    Store
	Interval time.Duration
	Timeout  time.Duration
	Now      func() time.Time
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
			cutoff := r.Now().Add(-r.Timeout)
			if err := r.Store.ReclaimStaleDeliveries(ctx, cutoff); err != nil {
				log.Printf("credentials stale delivery reaper: %v", err)
			}
			if err := r.Store.ReclaimStaleTests(ctx, cutoff); err != nil {
				log.Printf("credentials stale test reaper: %v", err)
			}
		}
	}
}
