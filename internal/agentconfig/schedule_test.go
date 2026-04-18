package agentconfig

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestScheduleSpec_Kinds(t *testing.T) {
	// Sanity: the kind constants exist and are distinct.
	if ScheduleKindCron == ScheduleKindInterval {
		t.Error("ScheduleKindCron must differ from ScheduleKindInterval")
	}
	if ScheduleKindOneShot == ScheduleKindInterval {
		t.Error("ScheduleKindOneShot must differ from ScheduleKindInterval")
	}
}

func TestScheduleSpec_Zero(t *testing.T) {
	var s ScheduleSpec
	if s.Kind != "" {
		t.Errorf("zero ScheduleSpec.Kind = %q, want empty", s.Kind)
	}
	if s.CronExpr != "" {
		t.Errorf("zero ScheduleSpec.CronExpr = %q, want empty", s.CronExpr)
	}
	if s.Interval != 0 {
		t.Errorf("zero ScheduleSpec.Interval = %v, want 0", s.Interval)
	}
	if s.Jitter != 0 {
		t.Errorf("zero ScheduleSpec.Jitter = %v, want 0", s.Jitter)
	}
}

func TestScheduleSpec_Populated(t *testing.T) {
	s := ScheduleSpec{
		Kind:     ScheduleKindCron,
		CronExpr: "0 2 * * *",
		Jitter:   30 * time.Second,
	}
	if s.Kind != ScheduleKindCron {
		t.Errorf("Kind = %q, want %q", s.Kind, ScheduleKindCron)
	}
	if s.CronExpr != "0 2 * * *" {
		t.Errorf("CronExpr = %q", s.CronExpr)
	}
	if s.Jitter != 30*time.Second {
		t.Errorf("Jitter = %v", s.Jitter)
	}
}

// newScheduleTestCmd returns a *cobra.Command with the --interval flag
// registered (mirroring cmd/agent.go's real registration).
func newScheduleTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Duration("interval", 0, "")
	return cmd
}

func TestResolveSchedule_CronWinsOverInterval(t *testing.T) {
	cfg := &Config{
		Schedule: "0 2 * * 0",
		Interval: 24 * time.Hour,
	}
	var warn bytes.Buffer
	spec, err := cfg.ResolveSchedule(newScheduleTestCmd(), &warn)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindCron {
		t.Errorf("Kind = %q, want cron", spec.Kind)
	}
	if spec.CronExpr != "0 2 * * 0" {
		t.Errorf("CronExpr = %q", spec.CronExpr)
	}
	if !strings.Contains(warn.String(), "schedule") || !strings.Contains(warn.String(), "interval") {
		t.Errorf("expected both-set warning in warn output, got %q", warn.String())
	}
}

func TestResolveSchedule_YAMLIntervalOverFlag(t *testing.T) {
	cfg := &Config{Interval: 12 * time.Hour}
	cmd := newScheduleTestCmd()
	if err := cmd.Flags().Set("interval", "24h"); err != nil {
		t.Fatal(err)
	}
	spec, err := cfg.ResolveSchedule(cmd, nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindInterval {
		t.Errorf("Kind = %q, want interval", spec.Kind)
	}
	if spec.Interval != 12*time.Hour {
		t.Errorf("Interval = %v, want 12h (yaml wins over flag)", spec.Interval)
	}
}

func TestResolveSchedule_FlagOnly(t *testing.T) {
	cfg := &Config{}
	cmd := newScheduleTestCmd()
	if err := cmd.Flags().Set("interval", "6h"); err != nil {
		t.Fatal(err)
	}
	spec, err := cfg.ResolveSchedule(cmd, nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindInterval {
		t.Errorf("Kind = %q, want interval", spec.Kind)
	}
	if spec.Interval != 6*time.Hour {
		t.Errorf("Interval = %v, want 6h", spec.Interval)
	}
}

func TestResolveSchedule_Nothing(t *testing.T) {
	cfg := &Config{}
	spec, err := cfg.ResolveSchedule(newScheduleTestCmd(), nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindOneShot {
		t.Errorf("Kind = %q, want oneshot", spec.Kind)
	}
}

func TestResolveSchedule_JitterOnlyInCronMode(t *testing.T) {
	cfg := &Config{
		Schedule:       "*/15 * * * *",
		ScheduleJitter: 45 * time.Second,
	}
	spec, err := cfg.ResolveSchedule(newScheduleTestCmd(), nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindCron {
		t.Errorf("Kind = %q, want cron", spec.Kind)
	}
	if spec.Jitter != 45*time.Second {
		t.Errorf("Jitter = %v, want 45s", spec.Jitter)
	}
}

func TestResolveSchedule_JitterIgnoredInIntervalMode(t *testing.T) {
	// schedule_jitter only applies to cron mode. In interval mode it's
	// silently dropped — interval has its own ±10% jitter handled by
	// cmd/agent_scheduler.go, not by ScheduleSpec.
	cfg := &Config{
		Interval:       24 * time.Hour,
		ScheduleJitter: 45 * time.Second,
	}
	spec, err := cfg.ResolveSchedule(newScheduleTestCmd(), nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindInterval {
		t.Errorf("Kind = %q, want interval", spec.Kind)
	}
	if spec.Jitter != 0 {
		t.Errorf("Jitter = %v, want 0 in interval mode", spec.Jitter)
	}
}
