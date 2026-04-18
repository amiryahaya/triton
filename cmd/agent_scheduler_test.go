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

func TestCronScheduler_NextDeterministic(t *testing.T) {
	// "Every day at 02:00 local time". At 01:55 on 2026-04-19 the
	// next fire is 5 minutes away.
	s, err := newCronScheduler("0 2 * * *", 0)
	if err != nil {
		t.Fatalf("newCronScheduler: %v", err)
	}
	loc, _ := time.LoadLocation("Local")
	now := time.Date(2026, 4, 19, 1, 55, 0, 0, loc)
	got := s.Next(now)
	if got != 5*time.Minute {
		t.Errorf("Next() = %v, want 5m", got)
	}
}

func TestCronScheduler_NextSteppedRange(t *testing.T) {
	// "Every 15 minutes" — at 12:07, next is 12:15 (8 minutes away).
	s, err := newCronScheduler("*/15 * * * *", 0)
	if err != nil {
		t.Fatalf("newCronScheduler: %v", err)
	}
	loc, _ := time.LoadLocation("Local")
	now := time.Date(2026, 4, 19, 12, 7, 0, 0, loc)
	got := s.Next(now)
	if got != 8*time.Minute {
		t.Errorf("Next() = %v, want 8m", got)
	}
}

func TestCronScheduler_JitterWithinBound(t *testing.T) {
	// With 45s jitter, the result must land in [base, base+45s).
	s, err := newCronScheduler("0 2 * * *", 45*time.Second)
	if err != nil {
		t.Fatalf("newCronScheduler: %v", err)
	}
	loc, _ := time.LoadLocation("Local")
	now := time.Date(2026, 4, 19, 1, 55, 0, 0, loc)
	base := 5 * time.Minute
	for i := 0; i < 50; i++ {
		got := s.Next(now)
		if got < base || got >= base+45*time.Second {
			t.Errorf("iter %d: Next() = %v, want in [%v, %v)", i, got, base, base+45*time.Second)
		}
	}
}

func TestCronScheduler_InvalidExpr(t *testing.T) {
	cases := []string{
		"bogus",        // not a cron expression
		"0 2 * *",      // only 4 fields
		"99 * * * *",   // minute out of range
		"",             // empty (caller's job to guard, but verify we reject)
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			if _, err := newCronScheduler(expr, 0); err == nil {
				t.Errorf("newCronScheduler(%q) = nil error, want error", expr)
			}
		})
	}
}

func TestCronScheduler_Describe(t *testing.T) {
	s, err := newCronScheduler("0 2 * * 0", 0)
	if err != nil {
		t.Fatalf("newCronScheduler: %v", err)
	}
	got := s.Describe()
	if !containsFold(got, "0 2 * * 0") {
		t.Errorf("Describe() = %q, want to include the expression", got)
	}
}
