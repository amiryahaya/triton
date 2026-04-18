package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
)

// fakeRunner is a test seam that records commands and returns scripted
// responses. One response per call index; extra calls return err.
type fakeRunner struct {
	responses []fakeResponse
	calls     atomic.Int32
	commands  []string
}

type fakeResponse struct {
	out string
	err error
}

func (f *fakeRunner) Run(ctx context.Context, cmd string) (string, error) {
	idx := int(f.calls.Add(1)) - 1
	f.commands = append(f.commands, cmd)
	if idx >= len(f.responses) {
		return "", errors.New("unexpected call")
	}
	return f.responses[idx].out, f.responses[idx].err
}

func (f *fakeRunner) Upload(ctx context.Context, local, remote string, mode os.FileMode) error {
	return nil
}
func (f *fakeRunner) Close() error { return nil }

func makeStatusJSON(t *testing.T, state jobrunner.State, findings int) string {
	s := jobrunner.Status{
		JobID:         "test",
		State:         state,
		FindingsCount: findings,
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPollStatus_TerminalOnFirstCall(t *testing.T) {
	f := &fakeRunner{responses: []fakeResponse{
		{out: makeStatusJSON(t, jobrunner.StateDone, 42)},
	}}
	got, err := PollStatus(context.Background(), f, "job", "cmd", 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != jobrunner.StateDone {
		t.Errorf("State = %q, want done", got.State)
	}
	if got.FindingsCount != 42 {
		t.Errorf("FindingsCount = %d, want 42", got.FindingsCount)
	}
}

func TestPollStatus_WaitsForTerminal(t *testing.T) {
	f := &fakeRunner{responses: []fakeResponse{
		{out: makeStatusJSON(t, jobrunner.StateRunning, 10)},
		{out: makeStatusJSON(t, jobrunner.StateRunning, 25)},
		{out: makeStatusJSON(t, jobrunner.StateDone, 42)},
	}}
	got, err := PollStatus(context.Background(), f, "job", "cmd", 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != jobrunner.StateDone {
		t.Errorf("got state %q, want done", got.State)
	}
	if int(f.calls.Load()) != 3 {
		t.Errorf("expected 3 poll calls, got %d", f.calls.Load())
	}
}

func TestPollStatus_ContextCancel(t *testing.T) {
	f := &fakeRunner{responses: []fakeResponse{
		{out: makeStatusJSON(t, jobrunner.StateRunning, 0)},
		{out: makeStatusJSON(t, jobrunner.StateRunning, 0)},
		{out: makeStatusJSON(t, jobrunner.StateRunning, 0)},
		{out: makeStatusJSON(t, jobrunner.StateRunning, 0)},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := PollStatus(ctx, f, "job", "cmd", 10*time.Millisecond)
	if err == nil {
		t.Error("PollStatus should return error on context timeout")
	}
}

func TestPollStatus_RunError(t *testing.T) {
	f := &fakeRunner{responses: []fakeResponse{
		{err: errors.New("ssh: broken pipe")},
	}}
	_, err := PollStatus(context.Background(), f, "job", "cmd", 10*time.Millisecond)
	if err == nil {
		t.Error("PollStatus should propagate run error")
	}
}

func TestCollectTar_WritesFile(t *testing.T) {
	tarBytes := "\x1f\x8b\x08\x00\x00\x00\x00\x00fake-tar-content"
	f := &fakeRunner{responses: []fakeResponse{
		{out: tarBytes},
	}}
	tmp := t.TempDir()
	path, err := CollectTar(context.Background(), f, "/remote/triton", "job-abc", tmp, "web-1")
	if err != nil {
		t.Fatalf("CollectTar: %v", err)
	}
	if path == "" {
		t.Fatal("returned path is empty")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != tarBytes {
		t.Errorf("file content mismatch")
	}
	wantName := filepath.Join(tmp, "web-1.tar.gz")
	if path != wantName {
		t.Errorf("path: got %q, want %q", path, wantName)
	}
}

func TestCollectTar_EmptyStream(t *testing.T) {
	f := &fakeRunner{responses: []fakeResponse{
		{out: ""},
	}}
	tmp := t.TempDir()
	_, err := CollectTar(context.Background(), f, "/remote/triton", "job", tmp, "web-1")
	if err == nil {
		t.Error("CollectTar should fail on empty stream")
	}
}
