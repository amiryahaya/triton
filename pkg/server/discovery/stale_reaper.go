package discovery

import (
	"context"
	"log"
	"time"
)

// StaleReaper periodically flips discovery jobs stuck in 'claimed' or
// 'running' back to 'queued' so another engine can pick them up. The
// partial index on status='queued' means abandoned jobs are otherwise
// invisible to ClaimNext forever; this sweeper is the only path to
// recovery after a portal crash between claim and finish.
//
// Zero-valued fields get safe defaults on Run:
//   - Interval: 5m (how often we sweep)
//   - Timeout:  15m (claimed_at older than this is considered abandoned)
//   - Now:      time.Now (injectable so tests can pin the cutoff)
type StaleReaper struct {
	Store    Store
	Interval time.Duration
	Timeout  time.Duration
	Now      func() time.Time
}

// Run blocks until ctx is cancelled. Sweep errors are logged but do not
// stop the loop — a transient DB blip shouldn't kill the reaper.
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
			if err := r.Store.ReclaimStale(ctx, r.Now().Add(-r.Timeout)); err != nil {
				log.Printf("discovery stale reaper: %v", err)
			}
		}
	}
}
