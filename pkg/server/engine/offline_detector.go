package engine

import (
	"context"
	"log"
	"time"
)

// OfflineDetector periodically finds engines whose last_poll_at is stale
// and flips them to status='offline'. Ticker-driven; cancel the context
// to stop it cleanly.
//
// Zero-valued fields get safe defaults on Run:
//   - Interval: 30s (how often we sweep)
//   - Stale:    60s (last_poll_at older than this is considered offline)
//   - Now:      time.Now (injectable so tests can pin the cutoff)
type OfflineDetector struct {
	Store    Store
	Interval time.Duration
	Stale    time.Duration
	Now      func() time.Time
}

// Run blocks until ctx is cancelled. Sweep errors are logged but do not
// stop the loop — a transient DB blip shouldn't kill offline detection.
func (d *OfflineDetector) Run(ctx context.Context) {
	if d.Interval == 0 {
		d.Interval = 30 * time.Second
	}
	if d.Stale == 0 {
		d.Stale = 60 * time.Second
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	t := time.NewTicker(d.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.sweep(ctx); err != nil {
				log.Printf("offline detector sweep: %v", err)
			}
		}
	}
}

func (d *OfflineDetector) sweep(ctx context.Context) error {
	return d.Store.MarkStaleOffline(ctx, d.Now().Add(-d.Stale))
}
