package cmd

import (
	"testing"
	"time"
)

func TestIntervalScheduler_Next(t *testing.T) {
	s := intervalScheduler{interval: 10 * time.Minute, jitterPct: 0}
	now := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	got := s.Next(now)
	if got != 10*time.Minute {
		t.Errorf("Next() = %v, want 10m (no jitter)", got)
	}
}

func TestIntervalScheduler_NextWithJitter(t *testing.T) {
	// With jitterPct=0.10 and interval=10m, the result must land in
	// [9m, 11m] — ±10%.
	s := intervalScheduler{interval: 10 * time.Minute, jitterPct: 0.10}
	now := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		got := s.Next(now)
		if got < 9*time.Minute || got > 11*time.Minute {
			t.Errorf("iter %d: Next() = %v, want in [9m, 11m]", i, got)
		}
	}
}

func TestIntervalScheduler_Describe(t *testing.T) {
	s := intervalScheduler{interval: 24 * time.Hour, jitterPct: 0.10}
	got := s.Describe()
	// Minimal contract: the string must reveal "24h" so an operator
	// reading startup logs can sanity-check.
	if !containsFold(got, "24h") {
		t.Errorf("Describe() = %q, want to mention 24h", got)
	}
}

// containsFold is a tiny helper so the test doesn't import strings.
func containsFold(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
