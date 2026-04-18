package jobrunner

import "testing"

func TestTouchCancelFlag(t *testing.T) {
	dir := t.TempDir()

	if IsCancelled(dir) {
		t.Error("fresh work-dir should not be cancelled")
	}

	if err := TouchCancelFlag(dir); err != nil {
		t.Fatalf("TouchCancelFlag: %v", err)
	}

	if !IsCancelled(dir) {
		t.Error("after TouchCancelFlag, IsCancelled should be true")
	}
}

func TestTouchCancelFlag_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if err := TouchCancelFlag(dir); err != nil {
		t.Fatalf("first touch: %v", err)
	}
	if err := TouchCancelFlag(dir); err != nil {
		t.Fatalf("second touch (idempotent): %v", err)
	}
	if !IsCancelled(dir) {
		t.Error("still cancelled after second touch")
	}
}
