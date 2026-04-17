package jobrunner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReconcile_NonTerminalPidGone_MarksFailed(t *testing.T) {
	dir := t.TempDir()
	s := InitialStatus("j", 999999, "quick", "v1.0.0", "")
	s.State = StateRunning
	if err := WriteStatusAtomic(dir, s); err != nil {
		t.Fatal(err)
	}

	rec := &reconciler{pidAlive: func(int) bool { return false }}
	out, changed, err := rec.Reconcile(dir)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !changed {
		t.Error("expected state to change (running → failed)")
	}
	if out.State != StateFailed {
		t.Errorf("State = %q, want failed", out.State)
	}
	if out.Error == "" {
		t.Error("Error should be populated with 'daemon vanished'")
	}
}

func TestReconcile_NonTerminalPidAlive_NoChange(t *testing.T) {
	dir := t.TempDir()
	s := InitialStatus("j", os.Getpid(), "quick", "v1.0.0", "")
	s.State = StateRunning
	if err := WriteStatusAtomic(dir, s); err != nil {
		t.Fatal(err)
	}

	rec := &reconciler{pidAlive: func(int) bool { return true }}
	out, changed, err := rec.Reconcile(dir)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if changed {
		t.Error("expected no change when daemon alive")
	}
	if out.State != StateRunning {
		t.Errorf("State = %q, want running", out.State)
	}
}

func TestReconcile_TerminalStateNeverChanges(t *testing.T) {
	dir := t.TempDir()
	s := InitialStatus("j", 1, "quick", "v1.0.0", "")
	s.State = StateDone
	ct := time.Now().UTC()
	s.CompletedAt = &ct
	if err := WriteStatusAtomic(dir, s); err != nil {
		t.Fatal(err)
	}

	rec := &reconciler{pidAlive: func(int) bool { return false }}
	out, changed, err := rec.Reconcile(dir)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if changed {
		t.Error("terminal state should not be reconciled")
	}
	if out.State != StateDone {
		t.Errorf("State = %q, want done (sticky)", out.State)
	}
}

func TestReconcile_MissingStatus(t *testing.T) {
	dir := t.TempDir()
	rec := &reconciler{pidAlive: func(int) bool { return false }}
	_, _, err := rec.Reconcile(dir)
	if err == nil {
		t.Error("expected error for missing status.json")
	}
}

// Ensure the public Reconcile uses real pidAlive (smoke test).
func TestReconcilePublic_DoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	s := InitialStatus("j", os.Getpid(), "quick", "v1.0.0", "")
	if err := WriteStatusAtomic(dir, s); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "state.lock"), nil, 0o600)
	_, _, err := Reconcile(dir)
	if err != nil {
		t.Errorf("Reconcile public: %v", err)
	}
}
