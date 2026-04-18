package jobrunner

import (
	"testing"
	"time"
)

func TestInitialStatus(t *testing.T) {
	before := time.Now()
	s := InitialStatus("job-123", 4567, "quick", "v1.0.0", "limits=none")
	after := time.Now()

	if s.JobID != "job-123" {
		t.Errorf("JobID = %q, want job-123", s.JobID)
	}
	if s.PID != 4567 {
		t.Errorf("PID = %d, want 4567", s.PID)
	}
	if s.State != StateRunning {
		t.Errorf("State = %q, want %q", s.State, StateRunning)
	}
	if s.StartedAt.Before(before) || s.StartedAt.After(after) {
		t.Errorf("StartedAt %v not in [%v, %v]", s.StartedAt, before, after)
	}
	if s.TritonVersion != "v1.0.0" {
		t.Errorf("TritonVersion = %q, want v1.0.0", s.TritonVersion)
	}
	if s.Limits != "limits=none" {
		t.Errorf("Limits = %q, want limits=none", s.Limits)
	}
	if s.CompletedAt != nil {
		t.Errorf("CompletedAt should be nil on init, got %v", *s.CompletedAt)
	}
}

func TestStateIsTerminal(t *testing.T) {
	cases := []struct {
		s    State
		term bool
	}{
		{StatePending, false},
		{StateRunning, false},
		{StateDone, true},
		{StateFailed, true},
		{StateCancelled, true},
	}
	for _, tc := range cases {
		t.Run(string(tc.s), func(t *testing.T) {
			if got := tc.s.IsTerminal(); got != tc.term {
				t.Errorf("%q.IsTerminal() = %v, want %v", tc.s, got, tc.term)
			}
		})
	}
}

func TestStatusMarkTerminal(t *testing.T) {
	s := InitialStatus("j", 1, "q", "v", "")
	s.MarkTerminal(StateDone, nil)

	if s.State != StateDone {
		t.Errorf("State = %q, want done", s.State)
	}
	if s.CompletedAt == nil {
		t.Fatal("CompletedAt should be set after MarkTerminal")
	}
	if s.Error != "" {
		t.Errorf("Error = %q, want empty on done", s.Error)
	}
}

func TestStatusMarkTerminalWithError(t *testing.T) {
	s := InitialStatus("j", 1, "q", "v", "")
	s.MarkTerminal(StateFailed, errAtomicFailure)

	if s.State != StateFailed {
		t.Errorf("State = %q, want failed", s.State)
	}
	if s.Error == "" {
		t.Errorf("Error should be populated on failed state")
	}
}

// sentinel for the test above
var errAtomicFailure = &sentinelError{msg: "boom"}

type sentinelError struct{ msg string }

func (e *sentinelError) Error() string { return e.msg }
