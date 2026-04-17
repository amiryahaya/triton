//go:build integration

package integration

import (
	"context"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/limits"
)

// TestLimitsApply_EndToEnd applies a realistic bundle of limits and verifies
// each dimension took effect in the process.
func TestLimitsApply_EndToEnd(t *testing.T) {
	origProcs := runtime.GOMAXPROCS(0)
	origMem := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(origProcs)
		debug.SetMemoryLimit(origMem)
	})

	l := limits.Limits{
		MaxMemoryBytes: 1 << 30, // 1GB
		MaxCPUPercent:  50,
		MaxDuration:    1 * time.Second,
	}
	ctx, cleanup := l.Apply(context.Background())
	defer cleanup()

	// 1. Memory limit was set.
	if got := debug.SetMemoryLimit(-1); got != 1<<30 {
		t.Errorf("SetMemoryLimit: got %d, want %d", got, 1<<30)
	}
	// 2. GOMAXPROCS was capped.
	wantProcs := runtime.NumCPU() / 2
	if wantProcs < 1 {
		wantProcs = 1
	}
	if got := runtime.GOMAXPROCS(0); got != wantProcs {
		t.Errorf("GOMAXPROCS: got %d, want %d (NumCPU=%d)", got, wantProcs, runtime.NumCPU())
	}
	// 3. Context has deadline within ~1s.
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context missing deadline")
	}
	if until := time.Until(deadline); until > 1200*time.Millisecond || until <= 0 {
		t.Errorf("deadline %v is not ~1s from now", until)
	}
	// 4. Context actually cancels after timeout.
	select {
	case <-ctx.Done():
		// ok
	case <-time.After(1500 * time.Millisecond):
		t.Error("context did not cancel within 1.5s (deadline was 1s)")
	}
}
