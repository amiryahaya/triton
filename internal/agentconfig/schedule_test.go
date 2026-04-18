package agentconfig

import (
	"testing"
	"time"
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
