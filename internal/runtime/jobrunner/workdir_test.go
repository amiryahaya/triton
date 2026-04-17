package jobrunner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveWorkDir_Override(t *testing.T) {
	got := ResolveWorkDir("/custom/path")
	if got != "/custom/path" {
		t.Errorf("ResolveWorkDir override: got %q want /custom/path", got)
	}
}

func TestResolveWorkDir_Default(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	want := filepath.Join(home, ".triton", "jobs")
	got := ResolveWorkDir("")
	if got != want {
		t.Errorf("ResolveWorkDir default: got %q want %q", got, want)
	}
}

func TestJobDir(t *testing.T) {
	got := JobDir("/base", "abc-123")
	want := filepath.Join("/base", "abc-123")
	if got != want {
		t.Errorf("JobDir: got %q want %q", got, want)
	}
}

func TestEnsureJobDir(t *testing.T) {
	tmp := t.TempDir()
	jobDir, err := EnsureJobDir(tmp, "job-xyz")
	if err != nil {
		t.Fatalf("EnsureJobDir: %v", err)
	}
	expected := filepath.Join(tmp, "job-xyz")
	if jobDir != expected {
		t.Errorf("returned path: got %q want %q", jobDir, expected)
	}
	if _, err := os.Stat(filepath.Join(jobDir, "reports")); err != nil {
		t.Errorf("reports/ not created: %v", err)
	}
}

func TestEnsureJobDir_IdempotentOnExisting(t *testing.T) {
	tmp := t.TempDir()
	_, err := EnsureJobDir(tmp, "already")
	if err != nil {
		t.Fatal(err)
	}
	_, err = EnsureJobDir(tmp, "already")
	if err != nil {
		t.Errorf("second EnsureJobDir should be idempotent, got %v", err)
	}
}

func TestResolveWorkDir_ExpandsTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home: %v", err)
	}
	got := ResolveWorkDir("~/custom-jobs")
	want := filepath.Join(home, "custom-jobs")
	if got != want {
		t.Errorf("ResolveWorkDir(~/custom-jobs): got %q want %q", got, want)
	}
	if !strings.HasPrefix(ResolveWorkDir(""), "/") && !strings.Contains(ResolveWorkDir(""), ":\\") {
		t.Errorf("default workdir should be absolute")
	}
}
