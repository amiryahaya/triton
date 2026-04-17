package limits

import (
	"context"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func TestLimitsZeroValueIsDisabled(t *testing.T) {
	var l Limits
	if l.Enabled() {
		t.Errorf("zero-value Limits should report Enabled() == false")
	}
}

func TestLimitsEnabled(t *testing.T) {
	cases := []struct {
		name string
		l    Limits
		want bool
	}{
		{"empty", Limits{}, false},
		{"memory set", Limits{MaxMemoryBytes: 1 << 20}, true},
		{"cpu set", Limits{MaxCPUPercent: 50}, true},
		{"duration set", Limits{MaxDuration: time.Second}, true},
		{"stop-at set", Limits{StopAtOffset: time.Hour}, true},
		{"nice set", Limits{Nice: 10}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.l.Enabled(); got != tc.want {
				t.Errorf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLimitsString(t *testing.T) {
	l := Limits{
		MaxMemoryBytes: 2 * (1 << 30),
		MaxCPUPercent:  50,
		MaxDuration:    4 * time.Hour,
		Nice:           10,
	}
	got := l.String()
	for _, want := range []string{"memory=2147483648", "cpu=50%", "duration=4h0m0s", "nice=10"} {
		if !containsSubstr(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}

func containsSubstr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestApplyZeroIsNoop(t *testing.T) {
	origProcs := runtime.GOMAXPROCS(0)
	origMem := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(origProcs)
		debug.SetMemoryLimit(origMem)
	})

	var l Limits
	ctx := context.Background()
	newCtx, cleanup := l.Apply(ctx)
	defer cleanup()

	if newCtx != ctx {
		t.Error("Apply() with zero Limits must return input ctx unchanged")
	}
	if deadline, ok := newCtx.Deadline(); ok {
		t.Errorf("Apply() with zero Limits must not set a deadline, got %v", deadline)
	}
	if runtime.GOMAXPROCS(0) != origProcs {
		t.Errorf("Apply() with zero Limits changed GOMAXPROCS")
	}
	if debug.SetMemoryLimit(-1) != origMem {
		t.Errorf("Apply() with zero Limits changed memory limit")
	}
}

func TestApplySetsDeadline(t *testing.T) {
	l := Limits{MaxDuration: 100 * time.Millisecond}
	ctx := context.Background()
	newCtx, cleanup := l.Apply(ctx)
	defer cleanup()

	deadline, ok := newCtx.Deadline()
	if !ok {
		t.Fatal("Apply() with MaxDuration must set deadline")
	}
	until := time.Until(deadline)
	if until <= 0 || until > 200*time.Millisecond {
		t.Errorf("deadline %v is not ~100ms from now (got %v)", deadline, until)
	}
}

func TestApplyUsesTighterOfDurationAndStopAt(t *testing.T) {
	l := Limits{
		MaxDuration:  5 * time.Hour,
		StopAtOffset: 30 * time.Minute, // tighter
	}
	ctx := context.Background()
	newCtx, cleanup := l.Apply(ctx)
	defer cleanup()

	deadline, ok := newCtx.Deadline()
	if !ok {
		t.Fatal("Apply() must set deadline when either duration is set")
	}
	until := time.Until(deadline)
	if until > 35*time.Minute || until < 25*time.Minute {
		t.Errorf("deadline %v should be ~30min from now, got %v away", deadline, until)
	}
}

func TestApplyCleanupStopsWatchdog(t *testing.T) {
	// Can't directly observe the watchdog goroutine, but we can verify
	// cleanup() returns promptly and doesn't panic when called twice.
	l := Limits{MaxMemoryBytes: 1 << 30}
	newCtx, cleanup := l.Apply(context.Background())
	_ = newCtx
	cleanup()
	cleanup() // idempotent
}
