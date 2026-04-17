package limits

import (
	"context"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplyMemoryLimitSetsSoftLimit(t *testing.T) {
	orig := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(orig) })

	const want = int64(512 << 20) // 512MB
	ApplyMemoryLimit(want)

	got := debug.SetMemoryLimit(-1)
	if got != want {
		t.Errorf("SetMemoryLimit after ApplyMemoryLimit = %d, want %d", got, want)
	}
}

func TestApplyMemoryLimitZeroIsNoop(t *testing.T) {
	orig := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(orig) })

	ApplyMemoryLimit(0)

	got := debug.SetMemoryLimit(-1)
	if got != orig {
		t.Errorf("ApplyMemoryLimit(0) changed limit from %d to %d (want unchanged)", orig, got)
	}
}

// TestWatchdogTriggersOnBreach verifies the watchdog calls its kill hook when
// the sampler reports memory above the hard cap. We inject a fake sampler
// returning a value above the threshold and a fake kill hook that increments
// a counter. Runs with a short sample interval.
func TestWatchdogTriggersOnBreach(t *testing.T) {
	var killed atomic.Int32
	cfg := watchdogConfig{
		softLimit:    100 << 20, // 100MB soft
		hardMultiple: 1.5,       // → 150MB hard cap
		sampleEvery:  10 * time.Millisecond,
		sampleMemory: func() uint64 { return 200 << 20 }, // always report 200MB
		kill:         func() { killed.Add(1) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		watchdogLoop(ctx, cfg)
		close(done)
	}()

	// Give the watchdog a few ticks to notice the breach.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if killed.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if killed.Load() == 0 {
		t.Error("watchdog did not call kill hook after breach")
	}
}

// TestWatchdogDoesNotTriggerUnderLimit verifies no kill when memory is fine.
func TestWatchdogDoesNotTriggerUnderLimit(t *testing.T) {
	var killed atomic.Int32
	cfg := watchdogConfig{
		softLimit:    100 << 20,
		hardMultiple: 1.5,
		sampleEvery:  10 * time.Millisecond,
		sampleMemory: func() uint64 { return 50 << 20 }, // well under
		kill:         func() { killed.Add(1) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchdogLoop(ctx, cfg)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if killed.Load() != 0 {
		t.Errorf("watchdog fired %d time(s) under limit (want 0)", killed.Load())
	}
}

// TestWatchdogStopsOnCancel verifies the goroutine exits when context is cancelled.
func TestWatchdogStopsOnCancel(t *testing.T) {
	cfg := watchdogConfig{
		softLimit:    100 << 20,
		hardMultiple: 1.5,
		sampleEvery:  10 * time.Millisecond,
		sampleMemory: func() uint64 { return 0 },
		kill:         func() {},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchdogLoop(ctx, cfg)
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// ok
	case <-time.After(200 * time.Millisecond):
		t.Error("watchdog did not exit within 200ms of cancel")
	}
}
