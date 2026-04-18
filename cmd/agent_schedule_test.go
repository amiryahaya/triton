package cmd

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/agentconfig"
)

// TestAgentScheduler_ConstructsFromYAML verifies the end-to-end wiring
// from Config → ResolveSchedule → newSchedulerFromSpec. It does NOT
// run the scan loop; the point is to catch plumbing breaks early.
func TestAgentScheduler_ConstructsFromYAML(t *testing.T) {
	cfg := &agentconfig.Config{Schedule: "0 2 * * *"}
	spec, err := cfg.ResolveSchedule(nil, nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	s, err := newSchedulerFromSpec(spec)
	if err != nil {
		t.Fatalf("newSchedulerFromSpec: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scheduler for cron spec")
	}
	// Sanity: calling Next doesn't panic and returns a positive value.
	got := s.Next(time.Date(2026, 4, 19, 1, 0, 0, 0, time.Local))
	if got <= 0 || got > 24*time.Hour {
		t.Errorf("Next() = %v, want positive and <= 24h", got)
	}
}

func TestAgentScheduler_InvalidCronFailsFast(t *testing.T) {
	cfg := &agentconfig.Config{Schedule: "bogus"}
	spec, err := cfg.ResolveSchedule(nil, nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if _, err := newSchedulerFromSpec(spec); err == nil {
		t.Fatal("expected invalid-cron error")
	}
}
