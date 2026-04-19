package cmd

import (
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/agentconfig"
	"github.com/amiryahaya/triton/internal/license"
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

// TestAgentScheduler_IntervalFlagFallback proves the CLI --interval
// flag still drives a non-nil interval scheduler when no yaml
// schedule/interval is set. This closes the semantic-equivalence gap
// between the old `agentInterval == 0` healthcheck heuristic and the
// new `sched == nil` one: if the flag resolves to an interval scheduler,
// the healthcheck will attempt retries; if it falls through to oneshot,
// it will not.
func TestAgentScheduler_IntervalFlagFallback(t *testing.T) {
	cmd := &cobra.Command{Use: "agent"}
	cmd.Flags().Duration("interval", 0, "")
	if err := cmd.Flags().Set("interval", "30m"); err != nil {
		t.Fatal(err)
	}
	cfg := &agentconfig.Config{}
	spec, err := cfg.ResolveSchedule(cmd, nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != agentconfig.ScheduleKindInterval {
		t.Errorf("Kind = %q, want interval", spec.Kind)
	}
	if spec.Interval != 30*time.Minute {
		t.Errorf("Interval = %v, want 30m", spec.Interval)
	}
	s, err := newSchedulerFromSpec(spec)
	if err != nil {
		t.Fatalf("newSchedulerFromSpec: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scheduler when --interval flag is set")
	}
}

// fakeServerClient lets tests drive heartbeat behaviour without HTTP.
// Implements the heartbeatClient interface in agent.go.
type fakeServerClient struct {
	resp *license.ValidateResponse
	err  error
}

func (f *fakeServerClient) Validate(_, _ string) (*license.ValidateResponse, error) {
	return f.resp, f.err
}

func (f *fakeServerClient) Deactivate(string) error { return nil }

func TestHeartbeat_ReturnsServerOverride(t *testing.T) {
	seat := &seatState{
		activated: true,
		client: &fakeServerClient{resp: &license.ValidateResponse{
			Valid:                 true,
			Tier:                  "pro",
			Schedule:              "0 2 * * *",
			ScheduleJitterSeconds: 30,
		}},
		licenseID: "lic-1",
		token:     "tok",
	}
	g := license.NewGuard("")
	_, override, err := heartbeat(seat, g)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if override == nil {
		t.Fatal("expected non-nil override when server pushes schedule")
	}
	if override.Kind != agentconfig.ScheduleKindCron {
		t.Errorf("Kind = %q", override.Kind)
	}
	if override.CronExpr != "0 2 * * *" {
		t.Errorf("CronExpr = %q", override.CronExpr)
	}
	if override.Jitter != 30*time.Second {
		t.Errorf("Jitter = %v", override.Jitter)
	}
}

func TestHeartbeat_EmptyScheduleReturnsNilOverride(t *testing.T) {
	seat := &seatState{
		activated: true,
		client: &fakeServerClient{resp: &license.ValidateResponse{
			Valid: true, Tier: "pro",
		}},
		licenseID: "lic-1", token: "tok",
	}
	g := license.NewGuard("")
	_, override, err := heartbeat(seat, g)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if override != nil {
		t.Errorf("expected nil override, got %+v", override)
	}
}

func TestHeartbeat_NotActivatedReturnsNilOverride(t *testing.T) {
	seat := &seatState{activated: false}
	_, override, err := heartbeat(seat, license.NewGuard(""))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if override != nil {
		t.Errorf("expected nil override, got %+v", override)
	}
}
