package server

import (
	"context"
	"testing"
	"time"
)

func TestNewRetentionPruner_DefaultDays(t *testing.T) {
	p := NewRetentionPruner(nil, 0)
	if p.retentionDays != 365 {
		t.Errorf("days<=0 should default to 365, got %d", p.retentionDays)
	}
}

func TestNewRetentionPruner_NegativeDays(t *testing.T) {
	p := NewRetentionPruner(nil, -1)
	if p.retentionDays != 365 {
		t.Errorf("negative days should default to 365, got %d", p.retentionDays)
	}
}

func TestNewRetentionPruner_PositiveDays(t *testing.T) {
	p := NewRetentionPruner(nil, 90)
	if p.retentionDays != 90 {
		t.Errorf("expected 90 days, got %d", p.retentionDays)
	}
}

func TestRetentionPruner_RunDaily_CancelsCleanly(t *testing.T) {
	// Verify RunDaily exits promptly when context is cancelled before it starts.
	// Pre-cancel the context so the first RunOnce call gets a cancelled context
	// and returns without accessing the (nil) store.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so RunOnce returns context.Canceled

	p := NewRetentionPruner(nil, 30)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.RunDaily(ctx)
	}()
	select {
	case <-done:
		// good — goroutine exited promptly
	case <-time.After(2 * time.Second):
		t.Error("RunDaily did not exit after context cancellation")
	}
}
