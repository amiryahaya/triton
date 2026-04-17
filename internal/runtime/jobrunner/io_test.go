package jobrunner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteStatusAtomic_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	orig := InitialStatus("abc", 42, "quick", "v1.2.3", "limits=none")
	orig.ProgressPct = 33.3
	orig.FindingsCount = 7

	if err := WriteStatusAtomic(dir, orig); err != nil {
		t.Fatalf("WriteStatusAtomic: %v", err)
	}

	got, err := ReadStatus(dir)
	if err != nil {
		t.Fatalf("ReadStatus: %v", err)
	}

	if got.JobID != orig.JobID {
		t.Errorf("JobID: got %q want %q", got.JobID, orig.JobID)
	}
	if got.ProgressPct != orig.ProgressPct {
		t.Errorf("ProgressPct: got %v want %v", got.ProgressPct, orig.ProgressPct)
	}
	if !got.StartedAt.Equal(orig.StartedAt) {
		t.Errorf("StartedAt: got %v want %v", got.StartedAt, orig.StartedAt)
	}
}

func TestWriteStatusAtomic_NoPartialReads(t *testing.T) {
	dir := t.TempDir()
	s1 := InitialStatus("j", 1, "q", "v", "")
	s2 := InitialStatus("j", 1, "q", "v", "")
	s2.FindingsCount = 999

	if err := WriteStatusAtomic(dir, s1); err != nil {
		t.Fatal(err)
	}
	if err := WriteStatusAtomic(dir, s2); err != nil {
		t.Fatal(err)
	}
	got, err := ReadStatus(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.FindingsCount != 999 {
		t.Errorf("FindingsCount: got %d want 999 (expected second write to win)", got.FindingsCount)
	}
}

func TestReadStatus_Missing(t *testing.T) {
	dir := t.TempDir()
	_, err := ReadStatus(dir)
	if err == nil {
		t.Error("expected error for missing status.json, got nil")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.IsNotExist error, got %v", err)
	}
}

func TestReadStatus_CorruptJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "status.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadStatus(dir)
	if err == nil {
		t.Error("expected parse error for corrupt JSON, got nil")
	}
}

func TestWriteJSON_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	type cfg struct {
		Profile string    `json:"profile"`
		At      time.Time `json:"at"`
	}
	want := cfg{Profile: "standard", At: time.Now().UTC()}
	if err := WriteJSON(path, want); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}
