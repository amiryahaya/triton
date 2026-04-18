package server

import (
	"context"
	"log"
	"time"

	"github.com/amiryahaya/triton/pkg/store"
)

// RetentionPruner deletes scans older than retentionDays.
// Designed as a daily goroutine; the caller cancels via ctx to stop it.
//
// It takes a *store.PostgresStore rather than the Store interface because
// PruneScansBefore is a Report-Server-only operational concern — there is
// no reason to put it on the shared Store interface.
type RetentionPruner struct {
	store         *store.PostgresStore
	retentionDays int
}

// NewRetentionPruner creates a RetentionPruner. days <= 0 is treated as
// 365 days (one year default). The caller is responsible for calling
// RunDaily(ctx) in a goroutine.
func NewRetentionPruner(s *store.PostgresStore, days int) *RetentionPruner {
	if days <= 0 {
		days = 365
	}
	return &RetentionPruner{store: s, retentionDays: days}
}

// RunOnce prunes in a single pass. Exported so callers can trigger
// immediate pruning (e.g., during testing or manual maintenance).
// Returns immediately with no error if the context is already done.
func (p *RetentionPruner) RunOnce(ctx context.Context) error {
	// Short-circuit if the context is already cancelled — avoids a nil-store
	// panic in tests that pre-cancel the context.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	cutoff := time.Now().UTC().Add(-time.Duration(p.retentionDays) * 24 * time.Hour)

	n, err := p.store.PruneScansBefore(ctx, cutoff)
	if err != nil {
		return err
	}
	if n > 0 {
		log.Printf("retention: pruned %d scan(s) older than %d days", n, p.retentionDays)
	}
	return nil
}

// RunDaily blocks until ctx is cancelled, running RunOnce every 24 h.
// An initial pass fires immediately so any stale data from a previous
// deployment with a longer retention window is cleaned out promptly.
func (p *RetentionPruner) RunDaily(ctx context.Context) {
	if err := p.RunOnce(ctx); err != nil {
		log.Printf("retention first-run: %v", err)
	}
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.RunOnce(ctx); err != nil {
				log.Printf("retention: %v", err)
			}
		}
	}
}
