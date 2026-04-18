package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

// fakeDialer returns a fixed fakeRunner to every Dial call.
type fakeDialer struct{ runner *fakeRunner }

func (d *fakeDialer) Dial(ctx context.Context, addr, user string, key []byte, passphrase, knownHosts string, insecureHostKey bool) (SSHRunner, error) {
	if d.runner == nil {
		return nil, errors.New("no runner configured")
	}
	return d.runner, nil
}

// makeTestStore is a test-local helper that builds a CredentialStore from
// a slice of credentials without going through the encrypted YAML path.
func makeTestStore(creds []netscan.Credential) *netscan.CredentialStore {
	return netscan.NewInMemoryStore(creds)
}

// newTestCredStore writes a fake private-key file to disk and wraps it
// in an in-memory CredentialStore so scanHost's readFile succeeds.
func newTestCredStore(t *testing.T, name string) *netscan.CredentialStore {
	t.Helper()
	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("fake private key content"), 0o600); err != nil {
		t.Fatal(err)
	}
	return makeTestStore([]netscan.Credential{
		{Name: name, Type: "ssh-key", Username: "tester", PrivateKeyPath: keyPath},
	})
}

func TestScanHost_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "triton-fake")
	if err := os.WriteFile(binPath, []byte("fake"), 0o755); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(tmp, "output")

	statusJSON, _ := json.Marshal(jobrunner.Status{State: jobrunner.StateDone, FindingsCount: 137})

	runner := &fakeRunner{responses: []fakeResponse{
		{out: "Linux x86_64\n"}, // 1. uname
		{out: ""},               // 2. sudo -n true
		{out: "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e\n"},           // 3. launch
		{out: string(statusJSON)},                                 // 4. poll status
		{out: "\x1f\x8b\x08\x00\x00\x00\x00\x00fake-tar-content"}, // 5. collect
		{out: ""}, // 6. cleanup
		{out: ""}, // 7. deferred rm
	}}
	dialer := &fakeDialer{runner: runner}
	creds := newTestCredStore(t, "test-cred")

	d := netscan.Device{Name: "web-1", Type: "unix", Address: "10.0.0.1", Sudo: true, Credential: "test-cred"}
	cfg := FleetConfig{
		Concurrency:    1,
		DeviceTimeout:  time.Minute,
		OutputDir:      outputDir,
		BinaryOverride: binPath,
		Dialer:         dialer,
	}

	res := scanHost(context.Background(), &d, creds, cfg)
	if !res.IsSuccess() {
		t.Errorf("scanHost should succeed: %+v", res)
	}
	if res.JobID != "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e" {
		t.Errorf("JobID = %q, want 7a3f9e2c-...", res.JobID)
	}
	if res.Status == nil || res.Status.FindingsCount != 137 {
		t.Errorf("Status not captured correctly: %+v", res.Status)
	}
	if res.OutputPath == "" {
		t.Error("OutputPath should be set when OutputDir is configured")
	}
}

func TestScanHost_SSHConnectFailure(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "triton")
	if err := os.WriteFile(binPath, []byte("fake"), 0o755); err != nil {
		t.Fatal(err)
	}

	dialer := &fakeDialer{} // no runner → Dial returns error
	creds := newTestCredStore(t, "test-cred")

	d := netscan.Device{Name: "web-1", Type: "unix", Address: "10.0.0.1", Credential: "test-cred"}
	cfg := FleetConfig{
		Concurrency:    1,
		DeviceTimeout:  time.Minute,
		OutputDir:      tmp,
		BinaryOverride: binPath,
		Dialer:         dialer,
	}

	res := scanHost(context.Background(), &d, creds, cfg)
	if res.IsSuccess() {
		t.Error("scanHost should fail on dial error")
	}
	if res.Phase != "ssh connect" {
		t.Errorf("Phase = %q, want 'ssh connect'", res.Phase)
	}
}

func TestScanHost_SudoCheckFailure(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "triton")
	if err := os.WriteFile(binPath, []byte("fake"), 0o755); err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{responses: []fakeResponse{
		{out: "Linux x86_64\n"},
		{err: errors.New("a password is required")},
	}}
	dialer := &fakeDialer{runner: runner}
	creds := newTestCredStore(t, "test-cred")

	d := netscan.Device{Name: "web-1", Type: "unix", Address: "10.0.0.1", Sudo: true, Credential: "test-cred"}
	cfg := FleetConfig{
		Concurrency:    1,
		DeviceTimeout:  time.Minute,
		OutputDir:      tmp,
		BinaryOverride: binPath,
		Dialer:         dialer,
	}

	res := scanHost(context.Background(), &d, creds, cfg)
	if res.IsSuccess() {
		t.Error("scanHost should fail on sudo check")
	}
	if res.Phase != "sudo check" {
		t.Errorf("Phase = %q, want 'sudo check'", res.Phase)
	}
}

func TestScanHost_DryRun(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "triton")
	if err := os.WriteFile(binPath, []byte("fake"), 0o755); err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{responses: []fakeResponse{
		{out: "Linux x86_64\n"},
		{out: ""},
	}}
	dialer := &fakeDialer{runner: runner}
	creds := newTestCredStore(t, "test-cred")

	d := netscan.Device{Name: "web-1", Type: "unix", Address: "10.0.0.1", Sudo: true, Credential: "test-cred"}
	cfg := FleetConfig{
		Concurrency:    1,
		DeviceTimeout:  time.Minute,
		DryRun:         true,
		BinaryOverride: binPath,
		Dialer:         dialer,
	}

	res := scanHost(context.Background(), &d, creds, cfg)
	if !res.IsSuccess() {
		t.Errorf("scanHost dry-run should succeed: %+v", res)
	}
	if int(runner.calls.Load()) > 2 {
		t.Errorf("dry-run should make only preflight calls, made %d", runner.calls.Load())
	}
}

func TestOrchestrator_RunAllSucceed(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "triton")
	os.WriteFile(binPath, []byte("fake"), 0o755)

	statusJSON, _ := json.Marshal(jobrunner.Status{State: jobrunner.StateDone, FindingsCount: 10})
	// Each host gets 7 runs: uname, sudo, launch, poll, collect, --cleanup, rm-f
	makeRunner := func() *fakeRunner {
		return &fakeRunner{responses: []fakeResponse{
			{out: "Linux x86_64\n"},
			{out: ""},
			{out: "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e\n"},
			{out: string(statusJSON)},
			{out: "\x1f\x8b\x08\x00\x00\x00\x00\x00fake-tar"},
			{out: ""},
			{out: ""},
		}}
	}

	dialer := &newRunnerPerDialDialer{newRunner: func() *fakeRunner { return makeRunner() }}
	creds := newTestCredStore(t, "test-cred")

	devices := []netscan.Device{
		{Name: "web-1", Type: "unix", Address: "1.1.1.1", Sudo: true, Credential: "test-cred"},
		{Name: "web-2", Type: "unix", Address: "1.1.1.2", Sudo: true, Credential: "test-cred"},
		{Name: "web-3", Type: "unix", Address: "1.1.1.3", Sudo: true, Credential: "test-cred"},
	}
	cfg := FleetConfig{
		Concurrency:    2,
		DeviceTimeout:  time.Minute,
		OutputDir:      tmp,
		BinaryOverride: binPath,
		Dialer:         dialer,
	}
	orch := NewOrchestrator(cfg)
	results, err := orch.Run(context.Background(), devices, creds)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("results: got %d, want 3", len(results))
	}
	for _, r := range results {
		if !r.IsSuccess() {
			t.Errorf("%s failed: %v", r.Device, r.Err)
		}
	}
}

func TestOrchestrator_MaxFailuresBreach(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "triton")
	os.WriteFile(binPath, []byte("fake"), 0o755)

	// All runners fail at dial stage.
	dialer := &newRunnerPerDialDialer{newRunner: func() *fakeRunner { return nil }}
	creds := newTestCredStore(t, "test-cred")

	devices := []netscan.Device{
		{Name: "web-1", Type: "unix", Address: "1.1.1.1", Credential: "test-cred"},
		{Name: "web-2", Type: "unix", Address: "1.1.1.2", Credential: "test-cred"},
		{Name: "web-3", Type: "unix", Address: "1.1.1.3", Credential: "test-cred"},
		{Name: "web-4", Type: "unix", Address: "1.1.1.4", Credential: "test-cred"},
	}
	cfg := FleetConfig{
		Concurrency:    2,
		DeviceTimeout:  time.Minute,
		OutputDir:      tmp,
		BinaryOverride: binPath,
		MaxFailures:    2,
		Dialer:         dialer,
	}
	orch := NewOrchestrator(cfg)
	results, err := orch.Run(context.Background(), devices, creds)
	if err == nil || !errors.Is(err, ErrMaxFailuresBreached) {
		t.Errorf("expected ErrMaxFailuresBreached, got %v", err)
	}
	_ = results
}

// newRunnerPerDialDialer returns a fresh fakeRunner per Dial call. If
// newRunner() returns nil, Dial returns a dial error.
type newRunnerPerDialDialer struct {
	newRunner func() *fakeRunner
}

func (d *newRunnerPerDialDialer) Dial(ctx context.Context, addr, user string, key []byte, passphrase, knownHosts string, insecureHostKey bool) (SSHRunner, error) {
	r := d.newRunner()
	if r == nil {
		return nil, errors.New("dial failed")
	}
	return r, nil
}
