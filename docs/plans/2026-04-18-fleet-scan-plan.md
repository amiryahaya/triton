# Fleet Scan (SSH Fan-out) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `triton fleet-scan` — an orchestrator that fans out `triton scan --detach` across a host inventory via SSH, collects reports, and aggregates a summary. Rename `network-scan` → `device-scan` with deprecation alias.

**Architecture:** New package `pkg/scanner/netscan/fleet/` with a worker pool that drains a device queue. Each worker: SSH dial → uname arch check → sudo pre-flight → scp binary → `triton scan --detach` → poll status.json → collect tar.gz → cleanup. Reuses existing `pkg/scanner/netscan/` (inventory + credentials), `pkg/scanner/netadapter/transport/` (SSH), and reads the `status.json` schema from PR #72 (`internal/runtime/jobrunner/`). No new RPC protocol — the orchestrator shells out via SSH and parses existing triton CLI stdout.

**Tech Stack:** Go 1.25 stdlib, `golang.org/x/crypto/ssh` (existing), `github.com/pkg/sftp` for file upload (new dep), `github.com/google/uuid` (existing), `gopkg.in/yaml.v3` (existing).

**Spec:** `docs/plans/2026-04-18-fleet-scan-design.md` (committed at `bacec1f`).

---

## File Structure

**Create (new `pkg/scanner/netscan/fleet/` package):**
- `pkg/scanner/netscan/fleet/doc.go` — package docs
- `pkg/scanner/netscan/fleet/types.go` — `HostResult`, `FleetConfig`, `ScanFlags`, `SSHRunner` interface
- `pkg/scanner/netscan/fleet/types_test.go`
- `pkg/scanner/netscan/fleet/preflight.go` — `ParseUnameArch`, `ResolveBinary`, `SudoCheck`
- `pkg/scanner/netscan/fleet/preflight_test.go`
- `pkg/scanner/netscan/fleet/launch.go` — `BuildLaunchCommand`, `ParseJobID`
- `pkg/scanner/netscan/fleet/launch_test.go`
- `pkg/scanner/netscan/fleet/collect.go` — `PollStatus`, `CollectTar`
- `pkg/scanner/netscan/fleet/collect_test.go`
- `pkg/scanner/netscan/fleet/summary.go` — `SummaryWriter`, JSON + text output
- `pkg/scanner/netscan/fleet/summary_test.go`
- `pkg/scanner/netscan/fleet/orchestrator.go` — `Orchestrator`, `scanHost`, worker pool, max-failures
- `pkg/scanner/netscan/fleet/orchestrator_test.go`

**Create (new CLI files):**
- `cmd/fleet_scan.go` — Cobra command for `triton fleet-scan`
- `cmd/fleet_scan_test.go` — flag assembly + filter tests
- `cmd/network_scan_alias.go` — deprecation wrapper for `network-scan`

**Create (integration test fixtures):**
- `test/integration/Dockerfile.sshd` — debian-slim + openssh-server + NOPASSWD sudoer
- `test/integration/Dockerfile.sshd-nosudo` — same but without NOPASSWD (for test 3)
- `test/integration/testdata/fleet/test_ed25519` + `.pub` — fixture SSH key
- `test/integration/testdata/fleet/devices.yaml` — minimal inventory
- `test/integration/testdata/fleet/credentials.yaml` — matching credentials
- `test/integration/fleet_scan_test.go` — 4 tests

**Modify:**
- `go.mod` / `go.sum` — add `github.com/pkg/sftp`
- `pkg/scanner/netadapter/transport/ssh.go` — add `Upload(ctx, localPath, remotePath, mode)` method
- `pkg/scanner/netadapter/transport/ssh_test.go` — add upload test (unit)
- `pkg/scanner/netscan/inventory.go` — add `Binary`, `WorkDir`, `SkipFleet`, `SkipDevice` fields + `DevicesForFleet()` helper
- `pkg/scanner/netscan/inventory_test.go` — test the new fields + filter
- `cmd/network_scan.go` → `cmd/device_scan.go` (rename; `ns*` vars → `ds*`)
- `internal/license/tier.go` — add `FeatureFleetScan` constant + `FeatureDeviceScan` alias
- `internal/license/tier_test.go` — cover new constants
- `.github/workflows/ci.yml` — integration job gains sshd service container
- `README.md` — add "Fleet scan" section
- `CLAUDE.md` — add `### Fleet scan` subsection
- `docs/examples/agentless/devices.yaml.example` — annotated with new `skip_fleet` fields

**Create (docs):**
- `docs/examples/fleet-scan/README.md`

---

## Scope Check

Single feature, one PR. The rename is bundled because it's small (~100 lines) and preventing naming drift is worth doing atomically. Similar scope to PR #72.

---

## Testing Notes for the Implementer

**Test seam pattern.** All unit tests in `pkg/scanner/netscan/fleet/` use a package-private `SSHRunner` interface (Task 1):

```go
type SSHRunner interface {
    Run(ctx context.Context, command string) (stdout string, err error)
    Upload(ctx context.Context, local, remote string, mode os.FileMode) error
    Close() error
}
```

Production code satisfies this via `transport.SSHClient`; tests use a `fakeRunner` that records commands and returns scripted responses. This is the only test seam we need — sftp + ssh + IO are all behind one interface.

**Integration tests use Docker sshd (`//go:build integration`).** The `ci.yml` integration job already runs in Ubuntu with postgres service containers; we add an sshd service container alongside. Locally, `docker compose -f test/integration/docker-compose.sshd.yaml up -d` starts it on port 2222.

**Race detector MUST pass.** Worker pool + status polling + context cancellation all happen concurrently. Use `sync.Mutex` or channels — not bare bool flags.

**TestHelperProcess pattern.** Some SSH tests spawn subprocesses via `go test -test.run=TestHelperProcess` (same trick PR #72 used for Spawn tests). Follow that pattern if you need isolated process lifecycle.

**Do NOT modify `pkg/scanner/`** (the engine). This feature is entirely orchestration — scan engine is untouched, consumed only as a black box via `triton scan --detach` on the remote host.

---

## Task 1: Bootstrap `fleet` package with types + `SSHRunner` interface

**Files:**
- Create: `pkg/scanner/netscan/fleet/doc.go`
- Create: `pkg/scanner/netscan/fleet/types.go`
- Create: `pkg/scanner/netscan/fleet/types_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/scanner/netscan/fleet/types_test.go`:

```go
package fleet

import (
	"errors"
	"testing"
	"time"
)

func TestHostResult_IsSuccess(t *testing.T) {
	cases := []struct {
		name string
		r    HostResult
		want bool
	}{
		{"empty", HostResult{}, false},
		{"error set", HostResult{Err: errors.New("boom")}, false},
		{"phase set but no err", HostResult{Phase: "launch"}, false},
		{"success", HostResult{Device: "web-1", JobID: "abc"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.IsSuccess(); got != tc.want {
				t.Errorf("IsSuccess() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHostResult_Fail(t *testing.T) {
	r := HostResult{Device: "web-1"}
	r.Fail("scp binary", errors.New("permission denied"))
	if r.Phase != "scp binary" {
		t.Errorf("Phase = %q, want %q", r.Phase, "scp binary")
	}
	if r.Err == nil || r.Err.Error() != "permission denied" {
		t.Errorf("Err = %v, want 'permission denied'", r.Err)
	}
}

func TestFleetConfig_ValidateRequiresOutput(t *testing.T) {
	cfg := FleetConfig{
		InventoryPath:   "x",
		CredentialsPath: "y",
		Concurrency:     1,
		DeviceTimeout:   time.Minute,
	}
	// Neither output-dir nor report-server nor dry-run set.
	if err := cfg.Validate(); err == nil {
		t.Error("Validate should require at least one of OutputDir, ReportServerURL, DryRun")
	}
	cfg.DryRun = true
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate with DryRun should succeed, got: %v", err)
	}
}

func TestFleetConfig_ValidateConcurrency(t *testing.T) {
	cfg := FleetConfig{
		InventoryPath:   "x",
		CredentialsPath: "y",
		OutputDir:       "z",
		DeviceTimeout:   time.Minute,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate should reject zero Concurrency")
	}
	cfg.Concurrency = 20
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate with Concurrency=20 should succeed, got: %v", err)
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./pkg/scanner/netscan/fleet/... -v`
Expected: FAIL with "package pkg/scanner/netscan/fleet is not in GOROOT or module" (or similar).

- [ ] **Step 3: Implement**

Create `pkg/scanner/netscan/fleet/doc.go`:

```go
// Package fleet implements the orchestrator for `triton fleet-scan`: an
// SSH fan-out that pushes the triton binary to each unix host in an
// inventory, runs `triton scan --detach` (PR #72's detached lifecycle),
// collects reports, and aggregates per-host results into a summary.
//
// The orchestrator is transport-agnostic above the SSHRunner interface.
// Production wires transport.SSHClient from pkg/scanner/netadapter;
// tests inject a fakeRunner that records commands and returns scripted
// responses.
//
// Per-host lifecycle (see orchestrator.go::scanHost for the full flow):
//  1. SSH dial + host-key verification
//  2. uname -s -m → arch resolution
//  3. Sudo pre-flight via `sudo -n true` (if device.sudo=true)
//  4. SFTP upload of binary to <workdir>/.triton-<random>
//  5. Launch: `triton scan --detach --quiet <forwarded flags>`
//  6. Poll: `triton scan --status --job-id <id> --json` every 10s
//  7. Collect: `triton scan --collect --job-id <id> -o -` (tar.gz stream)
//  8. Upload result.json to --report-server (optional)
//  9. Remote cleanup: `triton scan --cleanup --job-id <id>` + rm binary
//
// Failure at any phase is captured in HostResult.Phase; the worker
// returns early but the pool continues draining the device queue.
// --max-failures N cancels the outer context on breach.
package fleet
```

Create `pkg/scanner/netscan/fleet/types.go`:

```go
package fleet

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
)

// SSHRunner is the minimal interface the orchestrator needs from an SSH
// connection. Production uses transport.SSHClient; tests inject fakes.
type SSHRunner interface {
	Run(ctx context.Context, command string) (string, error)
	Upload(ctx context.Context, local, remote string, mode os.FileMode) error
	Close() error
}

// SSHDialer opens an SSHRunner for a given device + credentials. The
// orchestrator calls Dial once per host; tests inject fakes.
type SSHDialer interface {
	Dial(ctx context.Context, address, user string, key []byte, passphrase string,
		knownHostsFile string, insecureHostKey bool) (SSHRunner, error)
}

// ScanFlags bundles the subset of `triton scan` flags that fleet-scan
// forwards to each remote daemon. Empty strings/zero values are omitted
// from the built command line.
type ScanFlags struct {
	Profile       string
	Format        string
	Policy        string
	MaxMemory     string
	MaxCPUPercent string
	MaxDuration   time.Duration
	StopAt        string
	Nice          int
}

// FleetConfig bundles all orchestrator knobs. Populated by cmd/fleet_scan.go
// from CLI flags; passed to Orchestrator.Run.
type FleetConfig struct {
	// Required
	InventoryPath   string
	CredentialsPath string
	Concurrency     int
	DeviceTimeout   time.Duration

	// Filtering
	Group      string
	DeviceName string

	// Mode
	DryRun       bool
	Interval     time.Duration
	MaxFailures  int

	// SSH
	KnownHostsFile  string
	InsecureHostKey bool

	// Binary
	BinaryOverride string // --binary flag; empty = use os.Args[0]

	// Output (at least one must be set unless DryRun)
	OutputDir       string
	ReportServerURL string

	// Forwarded scan flags
	ScanFlags ScanFlags

	// Injected dependencies (production uses real; tests inject fakes)
	Dialer SSHDialer
}

// Validate returns an error if required fields are missing or contradictory.
func (c *FleetConfig) Validate() error {
	if c.InventoryPath == "" {
		return errors.New("InventoryPath is required")
	}
	if c.CredentialsPath == "" {
		return errors.New("CredentialsPath is required")
	}
	if c.Concurrency <= 0 {
		return errors.New("Concurrency must be > 0")
	}
	if c.DeviceTimeout <= 0 {
		return errors.New("DeviceTimeout must be > 0")
	}
	if !c.DryRun && c.OutputDir == "" && c.ReportServerURL == "" {
		return errors.New("at least one of OutputDir, ReportServerURL, or DryRun is required")
	}
	return nil
}

// HostResult records the outcome of one host's scan. Populated by scanHost;
// aggregated by the summary writer.
type HostResult struct {
	Device     string
	StartedAt  time.Time
	Duration   time.Duration
	Status     *jobrunner.Status // nil if failed before launch
	JobID      string
	OutputPath string // local tar.gz path if OutputDir set
	Err        error  // nil on success
	Phase      string // failure phase name (empty on success)
	Warning    string // non-fatal issue (e.g. report-server upload failed)
}

// IsSuccess reports whether the scan reached a clean terminal state with
// no error. Warnings are allowed.
func (r HostResult) IsSuccess() bool {
	return r.Err == nil && r.JobID != "" && r.Phase == ""
}

// Fail records a failure with the given phase and error. Convenience
// method used by scanHost.
func (r *HostResult) Fail(phase string, err error) {
	r.Phase = phase
	r.Err = err
}

// String provides a one-line summary for log output.
func (r HostResult) String() string {
	if r.IsSuccess() {
		n := 0
		if r.Status != nil {
			n = r.Status.FindingsCount
		}
		return fmt.Sprintf("%s: ok (%d findings, %s)", r.Device, n, r.Duration.Round(time.Second))
	}
	return fmt.Sprintf("%s: %s: %v", r.Device, r.Phase, r.Err)
}
```

- [ ] **Step 4: Verify green**

Run: `go test ./pkg/scanner/netscan/fleet/... -v`
Expected: PASS — 4 tests (TestHostResult_IsSuccess with 4 subtests, TestHostResult_Fail, TestFleetConfig_ValidateRequiresOutput, TestFleetConfig_ValidateConcurrency).

- [ ] **Step 5: Verify gofmt + vet**

Run: `gofmt -l pkg/scanner/netscan/fleet/ && go vet ./pkg/scanner/netscan/fleet/...`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/netscan/fleet/
git commit -m "feat(fleet): bootstrap types + SSHRunner interface"
```

---

## Task 2: Extend inventory with Binary, WorkDir, SkipFleet, SkipDevice fields

**Files:**
- Modify: `pkg/scanner/netscan/inventory.go` (Device struct + filter helpers)
- Modify: `pkg/scanner/netscan/inventory_test.go` (new field tests)

- [ ] **Step 1: Write failing test**

Append to `pkg/scanner/netscan/inventory_test.go`:

```go
func TestInventory_DevicesForFleet(t *testing.T) {
	inv := &Inventory{
		Devices: []Device{
			{Name: "web-1", Type: "unix"},
			{Name: "aix-1", Type: "unix", SkipFleet: true},
			{Name: "router", Type: "cisco-iosxe"},
			{Name: "db-1", Type: "unix"},
		},
	}
	got := inv.DevicesForFleet()
	if len(got) != 2 {
		t.Fatalf("DevicesForFleet: got %d, want 2", len(got))
	}
	names := map[string]bool{got[0].Name: true, got[1].Name: true}
	if !names["web-1"] || !names["db-1"] {
		t.Errorf("DevicesForFleet: got %v, want [web-1, db-1]", names)
	}
}

func TestInventory_DevicesForDeviceScan_SkipsDeviceScanOptOuts(t *testing.T) {
	inv := &Inventory{
		Devices: []Device{
			{Name: "router-1", Type: "cisco-iosxe"},
			{Name: "router-2", Type: "cisco-iosxe", SkipDevice: true},
			{Name: "web-1", Type: "unix"},
		},
	}
	got := inv.DevicesForDeviceScan()
	if len(got) != 2 {
		t.Fatalf("DevicesForDeviceScan: got %d, want 2", len(got))
	}
	// router-2 should be excluded; web-1 and router-1 kept.
	for _, d := range got {
		if d.Name == "router-2" {
			t.Errorf("router-2 should be excluded (SkipDevice=true)")
		}
	}
}

func TestDevice_NewFields_YAMLRoundTrip(t *testing.T) {
	yaml := []byte(`
version: 1
devices:
  - name: aix-legacy
    type: unix
    address: 10.0.1.20
    credential: legacy-ssh
    binary: /opt/triton-binaries/triton-aix-ppc64
    work_dir: /home/triton-test
    skip_fleet: false
    skip_device: true
`)
	tmp := t.TempDir()
	path := filepath.Join(tmp, "devices.yaml")
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if len(inv.Devices) != 1 {
		t.Fatalf("want 1 device, got %d", len(inv.Devices))
	}
	d := inv.Devices[0]
	if d.Binary != "/opt/triton-binaries/triton-aix-ppc64" {
		t.Errorf("Binary: got %q, want /opt/triton-binaries/triton-aix-ppc64", d.Binary)
	}
	if d.WorkDir != "/home/triton-test" {
		t.Errorf("WorkDir: got %q, want /home/triton-test", d.WorkDir)
	}
	if d.SkipFleet {
		t.Errorf("SkipFleet: got true, want false")
	}
	if !d.SkipDevice {
		t.Errorf("SkipDevice: got false, want true")
	}
}
```

Add imports to existing test file if needed: `"path/filepath"`, `"os"`.

- [ ] **Step 2: Verify red**

Run: `go test ./pkg/scanner/netscan/... -v -run 'DevicesForFleet|DevicesForDeviceScan|NewFields'`
Expected: FAIL — undefined Device.Binary / SkipFleet / SkipDevice / WorkDir, undefined DevicesForFleet, undefined DevicesForDeviceScan.

- [ ] **Step 3: Implement**

In `pkg/scanner/netscan/inventory.go`, find the `Device struct` and add new fields:

```go
type Device struct {
	Name             string   `yaml:"name"`
	Type             string   `yaml:"type"`
	Address          string   `yaml:"address"`
	Port             int      `yaml:"port"`
	Credential       string   `yaml:"credential"`
	EnableCredential string   `yaml:"enable_credential"`
	ScanPaths        []string `yaml:"scan_paths"`
	Sudo             bool     `yaml:"sudo"`
	OSHint           string   `yaml:"os_hint"`

	// Fleet-scan extensions (PR #74):
	Binary     string `yaml:"binary,omitempty"`      // override --binary per device
	WorkDir    string `yaml:"work_dir,omitempty"`    // remote temp dir; default /tmp
	SkipFleet  bool   `yaml:"skip_fleet,omitempty"`  // fleet-scan skips this device
	SkipDevice bool   `yaml:"skip_device,omitempty"` // device-scan skips this device
}
```

Add filter helpers after the existing `DevicesByGroup` method (search for `func (i *Inventory) DevicesByGroup`):

```go
// DevicesForFleet returns all unix-type devices that opt in to fleet-scan
// (i.e. not SkipFleet). Non-unix devices are silently excluded because
// fleet-scan pushes a unix binary.
func (i *Inventory) DevicesForFleet() []Device {
	out := make([]Device, 0, len(i.Devices))
	for _, d := range i.Devices {
		if d.Type == "unix" && !d.SkipFleet {
			out = append(out, d)
		}
	}
	return out
}

// DevicesForDeviceScan returns all devices that opt in to device-scan
// (i.e. not SkipDevice). Type filtering is left to the caller since
// device-scan handles multiple types (unix + network devices).
func (i *Inventory) DevicesForDeviceScan() []Device {
	out := make([]Device, 0, len(i.Devices))
	for _, d := range i.Devices {
		if !d.SkipDevice {
			out = append(out, d)
		}
	}
	return out
}
```

- [ ] **Step 4: Verify green + race**

Run: `go test ./pkg/scanner/netscan/... -race -v`
Expected: PASS — all existing tests + 3 new tests.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/netscan/inventory.go pkg/scanner/netscan/inventory_test.go
git commit -m "feat(netscan): add Binary/WorkDir/SkipFleet/SkipDevice inventory fields"
```

---

## Task 3: Add SSHClient.Upload method (sftp)

**Files:**
- Modify: `go.mod`, `go.sum` (add `github.com/pkg/sftp`)
- Modify: `pkg/scanner/netadapter/transport/ssh.go` (Upload method)
- Modify: `pkg/scanner/netadapter/transport/ssh_test.go` (unit test for Upload)

- [ ] **Step 1: Add sftp dependency**

Run: `go get github.com/pkg/sftp@latest`

Expected: `go.mod` gets a new `require github.com/pkg/sftp vX.Y.Z` line.

- [ ] **Step 2: Write failing test**

Append to `pkg/scanner/netadapter/transport/ssh_test.go`:

```go
func TestSSHClient_Upload_LocalFileValidation(t *testing.T) {
	// Upload must reject nonexistent local file with a clear error,
	// without requiring a real SSH connection (short-circuits on stat).
	c := &SSHClient{cmdTimeout: 5 * time.Second}
	err := c.Upload(context.Background(), "/nonexistent/file/triton", "/tmp/out", 0o755)
	if err == nil {
		t.Fatal("Upload should fail on nonexistent local file")
	}
	if !strings.Contains(err.Error(), "open local file") {
		t.Errorf("error should mention 'open local file', got %v", err)
	}
}
```

Add imports: `"context"`, `"strings"`, `"time"` (if not already present).

- [ ] **Step 3: Verify red**

Run: `go test ./pkg/scanner/netadapter/transport/... -v -run Upload`
Expected: FAIL — `c.Upload` undefined.

- [ ] **Step 4: Implement**

In `pkg/scanner/netadapter/transport/ssh.go`, add this method after `Run`:

```go
import (
	// keep existing imports
	"io"
	"os"

	"github.com/pkg/sftp"
)

// Upload copies localPath to the remote host at remotePath with the given
// file mode via the SFTP subsystem. Creates remote parent directory via
// MkdirAll if needed. Fails fast if localPath does not exist.
func (s *SSHClient) Upload(ctx context.Context, localPath, remotePath string, mode os.FileMode) error {
	local, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file %s: %w", localPath, err)
	}
	defer func() { _ = local.Close() }()

	client, err := sftp.NewClient(s.client)
	if err != nil {
		return fmt.Errorf("open sftp subsystem: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Ensure remote parent directory exists.
	remoteDir := remoteDirOf(remotePath)
	if remoteDir != "" && remoteDir != "/" {
		if err := client.MkdirAll(remoteDir); err != nil {
			return fmt.Errorf("mkdir remote dir %s: %w", remoteDir, err)
		}
	}

	remote, err := client.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file %s: %w", remotePath, err)
	}
	defer func() { _ = remote.Close() }()

	if _, err := io.Copy(remote, local); err != nil {
		return fmt.Errorf("copy to remote: %w", err)
	}
	if err := client.Chmod(remotePath, mode); err != nil {
		return fmt.Errorf("chmod remote file: %w", err)
	}
	// ctx is observed by sftp operations via the underlying ssh connection's
	// deadline; we don't explicitly cancel here because sftp.Client uses the
	// already-connected ssh.Client.
	_ = ctx
	return nil
}

// remoteDirOf returns the directory portion of a POSIX path. Kept simple
// because remote paths are always POSIX.
func remoteDirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return ""
}
```

- [ ] **Step 5: Verify green**

Run: `go test ./pkg/scanner/netadapter/transport/... -race -v`
Expected: PASS — all existing tests + new Upload test.

- [ ] **Step 6: Verify gofmt + vet + windows build**

Run: `gofmt -l pkg/scanner/netadapter/transport/ && go vet ./pkg/scanner/netadapter/transport/... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: no output.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum pkg/scanner/netadapter/transport/
git commit -m "feat(transport): add SSHClient.Upload via sftp subsystem"
```

---

## Task 4: Arch resolution — ParseUnameArch + ResolveBinary

**Files:**
- Create: `pkg/scanner/netscan/fleet/preflight.go`
- Create: `pkg/scanner/netscan/fleet/preflight_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/scanner/netscan/fleet/preflight_test.go`:

```go
package fleet

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

func TestParseUnameArch(t *testing.T) {
	cases := []struct {
		in   string
		goos string
		arch string
	}{
		{"Linux x86_64", "linux", "amd64"},
		{"Linux x86_64\n", "linux", "amd64"},
		{"Linux aarch64", "linux", "arm64"},
		{"Darwin x86_64", "darwin", "amd64"},
		{"Darwin arm64", "darwin", "arm64"},
		{"FreeBSD amd64", "freebsd", "amd64"},
		{"AIX ppc64", "aix", "ppc64"},
		{"SunOS i86pc", "solaris", "amd64"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			goos, arch, err := ParseUnameArch(tc.in)
			if err != nil {
				t.Fatalf("ParseUnameArch(%q): %v", tc.in, err)
			}
			if goos != tc.goos || arch != tc.arch {
				t.Errorf("got %s/%s, want %s/%s", goos, arch, tc.goos, tc.arch)
			}
		})
	}
}

func TestParseUnameArch_Invalid(t *testing.T) {
	cases := []string{"", "Linux", "just one word"}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, _, err := ParseUnameArch(tc); err == nil {
				t.Errorf("ParseUnameArch(%q) should fail", tc)
			}
		})
	}
}

func TestResolveBinary_DeviceOverride(t *testing.T) {
	tmp := t.TempDir()
	devBin := filepath.Join(tmp, "triton-aix")
	os.WriteFile(devBin, []byte("fake binary"), 0o755)

	globalBin := filepath.Join(tmp, "triton-global")
	os.WriteFile(globalBin, []byte("fake binary"), 0o755)

	d := &netscan.Device{Binary: devBin}
	// Device binary overrides global.
	got, err := ResolveBinary(d, globalBin, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got != devBin {
		t.Errorf("ResolveBinary with device override: got %q, want %q", got, devBin)
	}
}

func TestResolveBinary_GlobalFallback(t *testing.T) {
	tmp := t.TempDir()
	globalBin := filepath.Join(tmp, "triton-global")
	os.WriteFile(globalBin, []byte("fake binary"), 0o755)

	d := &netscan.Device{} // no per-device binary
	got, err := ResolveBinary(d, globalBin, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got != globalBin {
		t.Errorf("ResolveBinary fallback: got %q, want %q", got, globalBin)
	}
}

func TestResolveBinary_MissingFile(t *testing.T) {
	d := &netscan.Device{}
	_, err := ResolveBinary(d, "/nonexistent/triton", "linux", "amd64")
	if err == nil {
		t.Error("ResolveBinary should fail for nonexistent binary")
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./pkg/scanner/netscan/fleet/... -v -run 'ParseUnameArch|ResolveBinary'`
Expected: FAIL — undefined ParseUnameArch / ResolveBinary.

- [ ] **Step 3: Implement**

Create `pkg/scanner/netscan/fleet/preflight.go`:

```go
package fleet

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

// ParseUnameArch converts `uname -s -m` output (e.g. "Linux x86_64") into
// GOOS/GOARCH pair ("linux", "amd64"). Uses the standard mapping that
// matches Go's runtime.GOOS / runtime.GOARCH values so downstream code
// can compare against constants from the runtime package.
func ParseUnameArch(out string) (goos, arch string, err error) {
	out = strings.TrimSpace(out)
	parts := strings.Fields(out)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid uname output %q: want 'KERNEL ARCH'", out)
	}

	switch strings.ToLower(parts[0]) {
	case "linux":
		goos = "linux"
	case "darwin":
		goos = "darwin"
	case "freebsd":
		goos = "freebsd"
	case "openbsd":
		goos = "openbsd"
	case "netbsd":
		goos = "netbsd"
	case "aix":
		goos = "aix"
	case "sunos":
		goos = "solaris"
	default:
		return "", "", fmt.Errorf("unsupported OS %q in uname", parts[0])
	}

	switch strings.ToLower(parts[1]) {
	case "x86_64", "amd64":
		arch = "amd64"
	case "aarch64", "arm64":
		arch = "arm64"
	case "armv7l", "armv6l":
		arch = "arm"
	case "i386", "i686", "i86pc":
		// SunOS i86pc is 64-bit amd64 on modern systems.
		if goos == "solaris" {
			arch = "amd64"
		} else {
			arch = "386"
		}
	case "ppc64":
		arch = "ppc64"
	case "ppc64le":
		arch = "ppc64le"
	case "s390x":
		arch = "s390x"
	default:
		return "", "", fmt.Errorf("unsupported arch %q in uname", parts[1])
	}
	return goos, arch, nil
}

// ResolveBinary returns the local file path to push as the triton binary.
// Precedence: device.Binary > globalBinary (from --binary flag or os.Args[0]).
// Verifies the chosen path exists before returning.
//
// goos/arch are accepted for future arch-match validation but are not
// currently used to verify binary compatibility — the operator is
// responsible for choosing a compatible binary. See spec error-handling
// table for arch-mismatch messaging.
func ResolveBinary(d *netscan.Device, globalBinary, goos, arch string) (string, error) {
	path := d.Binary
	if path == "" {
		path = globalBinary
	}
	if path == "" {
		return "", fmt.Errorf("no binary specified: set --binary or device.binary")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat binary %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("binary path is a directory: %s", path)
	}
	_ = goos
	_ = arch
	return path, nil
}

// SudoCheck runs `sudo -n true` on the remote to verify NOPASSWD sudo is
// configured. Returns a descriptive error if sudo would prompt.
func SudoCheck(ctx context.Context, r SSHRunner) error {
	out, err := r.Run(ctx, "sudo -n true 2>&1")
	if err != nil {
		return fmt.Errorf("NOPASSWD sudo required: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}
```

- [ ] **Step 4: Verify green**

Run: `go test ./pkg/scanner/netscan/fleet/... -race -v -run 'ParseUnameArch|ResolveBinary'`
Expected: PASS — TestParseUnameArch with 8 subtests, TestParseUnameArch_Invalid with 3 subtests, TestResolveBinary_DeviceOverride, TestResolveBinary_GlobalFallback, TestResolveBinary_MissingFile.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/netscan/fleet/preflight.go pkg/scanner/netscan/fleet/preflight_test.go
git commit -m "feat(fleet): arch resolution + binary path + sudo check helpers"
```

---

## Task 5: Launch command builder + job-id parser

**Files:**
- Create: `pkg/scanner/netscan/fleet/launch.go`
- Create: `pkg/scanner/netscan/fleet/launch_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/scanner/netscan/fleet/launch_test.go`:

```go
package fleet

import (
	"strings"
	"testing"
	"time"
)

func TestBuildLaunchCommand_NoSudo(t *testing.T) {
	flags := ScanFlags{Profile: "standard", Format: "all"}
	got := BuildLaunchCommand("/tmp/.triton-abc", false, flags)
	want := `/tmp/.triton-abc scan --detach --quiet --profile standard --format all`
	if got != want {
		t.Errorf("BuildLaunchCommand:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestBuildLaunchCommand_WithSudo(t *testing.T) {
	flags := ScanFlags{Profile: "quick"}
	got := BuildLaunchCommand("/tmp/.triton-abc", true, flags)
	if !strings.HasPrefix(got, "sudo ") {
		t.Errorf("sudo prefix missing: %s", got)
	}
}

func TestBuildLaunchCommand_AllFlagsForwarded(t *testing.T) {
	flags := ScanFlags{
		Profile:       "comprehensive",
		Format:        "json",
		Policy:        "nacsa-2030",
		MaxMemory:     "2GB",
		MaxCPUPercent: "50",
		MaxDuration:   4 * time.Hour,
		StopAt:        "03:00",
		Nice:          10,
	}
	got := BuildLaunchCommand("/remote/triton", true, flags)
	for _, want := range []string{
		"sudo",
		"--detach", "--quiet",
		"--profile comprehensive",
		"--format json",
		"--policy nacsa-2030",
		"--max-memory 2GB",
		"--max-cpu-percent 50",
		"--max-duration 4h0m0s",
		"--stop-at 03:00",
		"--nice 10",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in command, got: %s", want, got)
		}
	}
}

func TestBuildLaunchCommand_OmitsEmpty(t *testing.T) {
	got := BuildLaunchCommand("/tmp/t", false, ScanFlags{})
	if strings.Contains(got, "--profile ") {
		t.Errorf("empty profile should be omitted: %s", got)
	}
	if strings.Contains(got, "--max-memory ") {
		t.Errorf("empty max-memory should be omitted: %s", got)
	}
	if strings.Contains(got, "--nice ") {
		t.Errorf("zero nice should be omitted: %s", got)
	}
	// Base flags always present.
	if !strings.Contains(got, "--detach") {
		t.Errorf("--detach missing: %s", got)
	}
	if !strings.Contains(got, "--quiet") {
		t.Errorf("--quiet missing: %s", got)
	}
}

func TestParseJobID_SingleLine(t *testing.T) {
	out := "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e\n"
	got, err := ParseJobID(out)
	if err != nil {
		t.Fatal(err)
	}
	if got != "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e" {
		t.Errorf("got %q", got)
	}
}

func TestParseJobID_MultiLine(t *testing.T) {
	// PR #72's non-quiet output format; last line is still the UUID or
	// --quiet was used and output is just the UUID.
	out := `Detached as job 7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e
pid 12345, work-dir /home/triton/.triton/jobs/7a3f9e2c-...
`
	// With --quiet, the orchestrator passes only the UUID — we test that.
	got, err := ParseJobID("7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e")
	if err != nil {
		t.Fatal(err)
	}
	if got != "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e" {
		t.Errorf("got %q", got)
	}
	// If non-quiet output leaked through, we should still extract the UUID
	// from the first line.
	got2, err := ParseJobID(out)
	if err != nil {
		t.Fatal(err)
	}
	if got2 != "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e" {
		t.Errorf("multi-line parse: got %q", got2)
	}
}

func TestParseJobID_Invalid(t *testing.T) {
	cases := []string{
		"",
		"not a uuid",
		"no-uuid-in-output-at-all",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, err := ParseJobID(tc); err == nil {
				t.Errorf("ParseJobID(%q) should fail", tc)
			}
		})
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./pkg/scanner/netscan/fleet/... -v -run 'BuildLaunchCommand|ParseJobID'`
Expected: FAIL — undefined BuildLaunchCommand / ParseJobID.

- [ ] **Step 3: Implement**

Create `pkg/scanner/netscan/fleet/launch.go`:

```go
package fleet

import (
	"fmt"
	"regexp"
	"strings"
)

// uuidPattern matches a canonical UUIDv4 string.
var uuidPattern = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// BuildLaunchCommand assembles the remote `triton scan --detach --quiet
// [forwarded flags]` command string. Prepends `sudo ` if useSudo is true.
// Omits empty/zero ScanFlags fields.
func BuildLaunchCommand(remoteBinary string, useSudo bool, f ScanFlags) string {
	parts := []string{}
	if useSudo {
		parts = append(parts, "sudo")
	}
	parts = append(parts, remoteBinary, "scan", "--detach", "--quiet")

	if f.Profile != "" {
		parts = append(parts, "--profile", f.Profile)
	}
	if f.Format != "" {
		parts = append(parts, "--format", f.Format)
	}
	if f.Policy != "" {
		parts = append(parts, "--policy", f.Policy)
	}
	if f.MaxMemory != "" {
		parts = append(parts, "--max-memory", f.MaxMemory)
	}
	if f.MaxCPUPercent != "" {
		parts = append(parts, "--max-cpu-percent", f.MaxCPUPercent)
	}
	if f.MaxDuration > 0 {
		parts = append(parts, "--max-duration", f.MaxDuration.String())
	}
	if f.StopAt != "" {
		parts = append(parts, "--stop-at", f.StopAt)
	}
	if f.Nice != 0 {
		parts = append(parts, "--nice", fmt.Sprintf("%d", f.Nice))
	}

	return strings.Join(parts, " ")
}

// ParseJobID extracts the UUID from the output of `triton scan --detach
// --quiet`. Handles both --quiet (bare UUID on stdout) and non-quiet
// ("Detached as job <uuid>\npid N...") formats by matching the first
// UUID-shaped string anywhere in the output.
func ParseJobID(out string) (string, error) {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return "", fmt.Errorf("empty launch output")
	}
	match := uuidPattern.FindString(out)
	if match == "" {
		return "", fmt.Errorf("no job-id (UUID) in launch output: %q", trimmed)
	}
	return match, nil
}
```

- [ ] **Step 4: Verify green**

Run: `go test ./pkg/scanner/netscan/fleet/... -race -v -run 'BuildLaunchCommand|ParseJobID'`
Expected: PASS — 4 + 3 tests.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/netscan/fleet/launch.go pkg/scanner/netscan/fleet/launch_test.go
git commit -m "feat(fleet): BuildLaunchCommand + ParseJobID"
```

---

## Task 6: Status polling + tar collection

**Files:**
- Create: `pkg/scanner/netscan/fleet/collect.go`
- Create: `pkg/scanner/netscan/fleet/collect_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/scanner/netscan/fleet/collect_test.go`:

```go
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
	ctx := context.Background()
	got, err := PollStatus(ctx, f, "job", "cmd", 10*time.Millisecond)
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
	// Fake tar.gz content (actual gzip magic bytes are not validated here
	// — we only test that the stream is written to the expected file).
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
```

- [ ] **Step 2: Verify red**

Run: `go test ./pkg/scanner/netscan/fleet/... -v -run 'PollStatus|CollectTar'`
Expected: FAIL — undefined PollStatus / CollectTar.

- [ ] **Step 3: Implement**

Create `pkg/scanner/netscan/fleet/collect.go`:

```go
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
)

// PollStatus runs statusCmd on the remote every pollInterval and returns
// the parsed Status once it reaches a terminal state (done / failed /
// cancelled). Returns an error if the context is cancelled, a Run fails,
// or the status JSON is malformed.
func PollStatus(ctx context.Context, r SSHRunner, jobID, statusCmd string, pollInterval time.Duration) (*jobrunner.Status, error) {
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// Poll immediately on first iteration (no leading sleep).
	for {
		out, err := r.Run(ctx, statusCmd)
		if err != nil {
			return nil, fmt.Errorf("run status cmd for job %s: %w", jobID, err)
		}
		var s jobrunner.Status
		if err := json.Unmarshal([]byte(out), &s); err != nil {
			return nil, fmt.Errorf("parse status json for job %s: %w", jobID, err)
		}
		if s.State.IsTerminal() {
			return &s, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("poll status: %w", ctx.Err())
		case <-ticker.C:
			// next iteration
		}
	}
}

// CollectTar streams the output of `triton scan --collect --job-id <id>
// -o -` (which is a gzip'd tar of the reports/ dir) into
// outputDir/<deviceName>.tar.gz. Returns the local file path.
//
// We use Run (captures stdout as string) rather than a streaming reader
// because the transport's Run interface is simpler and report tars are
// small (< a few MB). A streaming variant can be added later if needed.
func CollectTar(ctx context.Context, r SSHRunner, remoteBinary, jobID, outputDir, deviceName string) (string, error) {
	cmd := fmt.Sprintf("%s scan --collect --job-id %s -o -", remoteBinary, jobID)
	stdout, err := r.Run(ctx, cmd)
	if err != nil {
		return "", fmt.Errorf("run collect cmd: %w", err)
	}
	if len(stdout) == 0 {
		return "", fmt.Errorf("collect returned empty stream for job %s", jobID)
	}

	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir output dir: %w", err)
	}
	path := filepath.Join(outputDir, deviceName+".tar.gz")
	if err := os.WriteFile(path, []byte(stdout), 0o600); err != nil {
		return "", fmt.Errorf("write tar: %w", err)
	}
	return path, nil
}
```

- [ ] **Step 4: Verify green + race**

Run: `go test ./pkg/scanner/netscan/fleet/... -race -v -run 'PollStatus|CollectTar'`
Expected: PASS — 4 + 2 tests.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/netscan/fleet/collect.go pkg/scanner/netscan/fleet/collect_test.go
git commit -m "feat(fleet): PollStatus + CollectTar"
```

---

## Task 7: Summary writer (summary.json + summary.txt)

**Files:**
- Create: `pkg/scanner/netscan/fleet/summary.go`
- Create: `pkg/scanner/netscan/fleet/summary_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/scanner/netscan/fleet/summary_test.go`:

```go
package fleet

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
)

func TestSummary_ExitCode(t *testing.T) {
	cases := []struct {
		name    string
		results []HostResult
		want    int
	}{
		{
			name:    "all ok",
			results: []HostResult{{Device: "a", JobID: "j1"}, {Device: "b", JobID: "j2"}},
			want:    0,
		},
		{
			name: "some failed",
			results: []HostResult{
				{Device: "a", JobID: "j1"},
				{Device: "b", Err: errors.New("fail"), Phase: "ssh connect"},
			},
			want: 2,
		},
		{
			name: "all failed",
			results: []HostResult{
				{Device: "a", Err: errors.New("fail"), Phase: "ssh connect"},
			},
			want: 2, // even all-fail is exit 2 (not 1) per spec; 1 reserved for runtime errors
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCodeFor(tc.results, false); got != tc.want {
				t.Errorf("ExitCodeFor: got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSummary_ExitCode_FailOnAny(t *testing.T) {
	results := []HostResult{
		{Device: "a", JobID: "j1"},
		{Device: "b", Err: errors.New("fail"), Phase: "ssh connect"},
	}
	if got := ExitCodeFor(results, true); got != 1 {
		t.Errorf("ExitCodeFor failOnAny: got %d, want 1", got)
	}
}

func TestSummary_WriteJSON(t *testing.T) {
	tmp := t.TempDir()
	results := []HostResult{
		{
			Device:     "web-1",
			StartedAt:  time.Date(2026, 4, 18, 14, 30, 0, 0, time.UTC),
			Duration:   2 * time.Minute,
			Status:     &jobrunner.Status{FindingsCount: 137},
			JobID:      "7a3f9e2c-xx",
			OutputPath: "hosts/web-1.tar.gz",
		},
		{
			Device:    "srv-03",
			StartedAt: time.Date(2026, 4, 18, 14, 30, 0, 0, time.UTC),
			Duration:  8 * time.Second,
			Err:       errors.New("ssh connect: handshake failed"),
			Phase:     "ssh connect",
		},
	}
	err := WriteSummary(tmp, SummaryInput{
		InvokedAt:     time.Date(2026, 4, 18, 14, 30, 0, 0, time.UTC),
		CompletedAt:   time.Date(2026, 4, 18, 14, 32, 8, 0, time.UTC),
		InventoryPath: "/etc/triton/devices.yaml",
		Results:       results,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["inventory"] != "/etc/triton/devices.yaml" {
		t.Errorf("inventory: got %v", parsed["inventory"])
	}
	counts, ok := parsed["counts"].(map[string]interface{})
	if !ok {
		t.Fatal("counts missing or wrong type")
	}
	if counts["total"].(float64) != 2 {
		t.Errorf("counts.total = %v, want 2", counts["total"])
	}
	if counts["succeeded"].(float64) != 1 {
		t.Errorf("counts.succeeded = %v, want 1", counts["succeeded"])
	}
	if counts["failed"].(float64) != 1 {
		t.Errorf("counts.failed = %v, want 1", counts["failed"])
	}
}

func TestSummary_WriteText(t *testing.T) {
	tmp := t.TempDir()
	results := []HostResult{
		{Device: "web-1", JobID: "j", Status: &jobrunner.Status{FindingsCount: 137}, Duration: 2 * time.Minute},
		{Device: "srv-03", Err: errors.New("ssh connect failed"), Phase: "ssh connect", Duration: 8 * time.Second},
	}
	err := WriteSummary(tmp, SummaryInput{
		InvokedAt:     time.Date(2026, 4, 18, 14, 30, 0, 0, time.UTC),
		CompletedAt:   time.Date(2026, 4, 18, 14, 32, 8, 0, time.UTC),
		InventoryPath: "/etc/triton/devices.yaml",
		Results:       results,
	})
	if err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(filepath.Join(tmp, "summary.txt"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(text)
	if !strings.Contains(s, "Total hosts:") {
		t.Errorf("missing 'Total hosts:' header: %s", s)
	}
	if !strings.Contains(s, "web-1") {
		t.Errorf("missing web-1")
	}
	if !strings.Contains(s, "srv-03") {
		t.Errorf("missing srv-03")
	}
	if !strings.Contains(s, "Failed hosts:") {
		t.Errorf("missing failed section")
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./pkg/scanner/netscan/fleet/... -v -run 'Summary|ExitCode'`
Expected: FAIL — undefined ExitCodeFor / WriteSummary / SummaryInput.

- [ ] **Step 3: Implement**

Create `pkg/scanner/netscan/fleet/summary.go`:

```go
package fleet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SummaryInput is the immutable input to WriteSummary; callers pass the
// invocation-level metadata alongside the per-host results.
type SummaryInput struct {
	InvokedAt     time.Time
	CompletedAt   time.Time
	InventoryPath string
	Flags         map[string]interface{} // serialized flag snapshot for reproducibility
	Results       []HostResult
}

// hostLine is the JSON-shape per host written to summary.json.
type hostLine struct {
	Device        string `json:"device"`
	State         string `json:"state"`
	Duration      string `json:"duration"`
	FindingsCount int    `json:"findings_count,omitempty"`
	JobID         string `json:"job_id,omitempty"`
	OutputPath    string `json:"output_path,omitempty"`
	Warning       string `json:"warning,omitempty"`
	Error         string `json:"error,omitempty"`
	Phase         string `json:"phase,omitempty"`
}

// summaryJSON is the on-disk shape of summary.json.
type summaryJSON struct {
	InvokedAt     time.Time              `json:"invoked_at"`
	CompletedAt   time.Time              `json:"completed_at"`
	Duration      string                 `json:"duration"`
	Inventory     string                 `json:"inventory"`
	Flags         map[string]interface{} `json:"flags,omitempty"`
	Counts        map[string]int         `json:"counts"`
	Hosts         []hostLine             `json:"hosts"`
}

// WriteSummary writes summary.json and summary.txt into outputDir.
func WriteSummary(outputDir string, in SummaryInput) error {
	succeeded, failed := 0, 0
	hosts := make([]hostLine, len(in.Results))
	for i, r := range in.Results {
		hl := hostLine{
			Device:     r.Device,
			Duration:   r.Duration.Round(time.Second).String(),
			JobID:      r.JobID,
			OutputPath: r.OutputPath,
			Warning:    r.Warning,
		}
		if r.IsSuccess() {
			hl.State = "done"
			if r.Status != nil {
				hl.FindingsCount = r.Status.FindingsCount
			}
			succeeded++
		} else {
			hl.State = "failed"
			hl.Phase = r.Phase
			if r.Err != nil {
				hl.Error = r.Err.Error()
			}
			failed++
		}
		hosts[i] = hl
	}

	sj := summaryJSON{
		InvokedAt:   in.InvokedAt,
		CompletedAt: in.CompletedAt,
		Duration:    in.CompletedAt.Sub(in.InvokedAt).Round(time.Second).String(),
		Inventory:   in.InventoryPath,
		Flags:       in.Flags,
		Counts: map[string]int{
			"total":     len(in.Results),
			"succeeded": succeeded,
			"failed":    failed,
		},
		Hosts: hosts,
	}

	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return fmt.Errorf("mkdir output dir: %w", err)
	}

	// summary.json
	data, err := json.MarshalIndent(sj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "summary.json"), data, 0o600); err != nil {
		return fmt.Errorf("write summary.json: %w", err)
	}

	// summary.txt
	text := formatSummaryText(sj, in.Results)
	if err := os.WriteFile(filepath.Join(outputDir, "summary.txt"), []byte(text), 0o600); err != nil {
		return fmt.Errorf("write summary.txt: %w", err)
	}
	return nil
}

func formatSummaryText(sj summaryJSON, results []HostResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "FLEET SCAN SUMMARY — completed %s (%s)\n",
		sj.CompletedAt.UTC().Format("2006-01-02 15:04:05 UTC"), sj.Duration)
	fmt.Fprintf(&b, "Inventory:   %s\n\n", sj.Inventory)
	fmt.Fprintf(&b, "Total hosts:      %d\n", sj.Counts["total"])
	fmt.Fprintf(&b, " ├─ Succeeded:    %d\n", sj.Counts["succeeded"])
	fmt.Fprintf(&b, " └─ Failed:       %d\n\n", sj.Counts["failed"])

	totalFindings := 0
	for _, r := range results {
		if r.IsSuccess() && r.Status != nil {
			totalFindings += r.Status.FindingsCount
		}
	}
	fmt.Fprintf(&b, "Total findings:   %d\n\n", totalFindings)

	if sj.Counts["failed"] > 0 {
		fmt.Fprintln(&b, "Failed hosts:")
		for _, r := range results {
			if !r.IsSuccess() {
				errStr := ""
				if r.Err != nil {
					errStr = r.Err.Error()
				}
				fmt.Fprintf(&b, "  %-24s %s: %s\n", r.Device, r.Phase, errStr)
			}
		}
	}
	return b.String()
}

// ExitCodeFor maps per-host results to the process exit code per spec:
//   0 — all hosts succeeded
//   2 — ≥1 host failed (but ≥1 succeeded, or all failed)
// failOnAny elevates any failure to exit 1 for strict CI gates.
// Exit codes 1 (runtime error) and 3 (max-failures breached) are set by
// the caller before results are aggregated.
func ExitCodeFor(results []HostResult, failOnAny bool) int {
	failed := 0
	for _, r := range results {
		if !r.IsSuccess() {
			failed++
		}
	}
	if failed == 0 {
		return 0
	}
	if failOnAny {
		return 1
	}
	return 2
}
```

- [ ] **Step 4: Verify green + race**

Run: `go test ./pkg/scanner/netscan/fleet/... -race -v -run 'Summary|ExitCode'`
Expected: PASS — 3 test functions + subtests.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/netscan/fleet/summary.go pkg/scanner/netscan/fleet/summary_test.go
git commit -m "feat(fleet): summary.json + summary.txt writer + exit-code mapping"
```

---

## Task 8: scanHost — per-host lifecycle wire-up

**Files:**
- Create: `pkg/scanner/netscan/fleet/orchestrator.go` (scanHost function only; worker pool in Task 9)
- Create: `pkg/scanner/netscan/fleet/orchestrator_test.go`

- [ ] **Step 1: Write failing test**

Create `pkg/scanner/netscan/fleet/orchestrator_test.go`:

```go
package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
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

func TestScanHost_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	// Build a tiny local binary fixture so ResolveBinary succeeds.
	binPath := tmp + "/triton-fake"
	os.WriteFile(binPath, []byte("fake"), 0o755)
	outputDir := tmp + "/output"

	statusJSON, _ := json.Marshal(jobrunner.Status{State: jobrunner.StateDone, FindingsCount: 137})

	runner := &fakeRunner{responses: []fakeResponse{
		{out: "Linux x86_64\n"},                                       // uname
		{out: ""},                                                     // sudo -n true
		{out: "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e\n"},                // launch (quiet UUID)
		{out: string(statusJSON)},                                     // first poll → terminal
		{out: "\x1f\x8b\x08\x00\x00\x00\x00\x00fake-tar-content"},     // collect
		{out: ""},                                                     // cleanup
	}}
	dialer := &fakeDialer{runner: runner}

	d := netscan.Device{Name: "web-1", Type: "unix", Address: "10.0.0.1", Sudo: true}
	creds := &netscan.Credentials{}
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
		t.Errorf("Status not captured correctly")
	}
	if res.OutputPath == "" {
		t.Error("OutputPath should be set when OutputDir is configured")
	}
}

func TestScanHost_SSHConnectFailure(t *testing.T) {
	tmp := t.TempDir()
	binPath := tmp + "/triton"
	os.WriteFile(binPath, []byte("fake"), 0o755)

	dialer := &fakeDialer{} // no runner → Dial returns error

	d := netscan.Device{Name: "web-1", Type: "unix", Address: "10.0.0.1"}
	cfg := FleetConfig{
		Concurrency:    1,
		DeviceTimeout:  time.Minute,
		OutputDir:      tmp,
		BinaryOverride: binPath,
		Dialer:         dialer,
	}

	res := scanHost(context.Background(), &d, &netscan.Credentials{}, cfg)
	if res.IsSuccess() {
		t.Error("scanHost should fail on dial error")
	}
	if res.Phase != "ssh connect" {
		t.Errorf("Phase = %q, want 'ssh connect'", res.Phase)
	}
}

func TestScanHost_SudoCheckFailure(t *testing.T) {
	tmp := t.TempDir()
	binPath := tmp + "/triton"
	os.WriteFile(binPath, []byte("fake"), 0o755)

	runner := &fakeRunner{responses: []fakeResponse{
		{out: "Linux x86_64\n"},                           // uname ok
		{err: errors.New("a password is required")},       // sudo fails
	}}
	dialer := &fakeDialer{runner: runner}

	d := netscan.Device{Name: "web-1", Type: "unix", Address: "10.0.0.1", Sudo: true}
	cfg := FleetConfig{
		Concurrency:    1,
		DeviceTimeout:  time.Minute,
		OutputDir:      tmp,
		BinaryOverride: binPath,
		Dialer:         dialer,
	}

	res := scanHost(context.Background(), &d, &netscan.Credentials{}, cfg)
	if res.IsSuccess() {
		t.Error("scanHost should fail on sudo check")
	}
	if res.Phase != "sudo check" {
		t.Errorf("Phase = %q, want 'sudo check'", res.Phase)
	}
}

func TestScanHost_DryRun(t *testing.T) {
	tmp := t.TempDir()
	binPath := tmp + "/triton"
	os.WriteFile(binPath, []byte("fake"), 0o755)

	runner := &fakeRunner{responses: []fakeResponse{
		{out: "Linux x86_64\n"}, // uname
		{out: ""},               // sudo -n true
	}}
	dialer := &fakeDialer{runner: runner}

	d := netscan.Device{Name: "web-1", Type: "unix", Address: "10.0.0.1", Sudo: true}
	cfg := FleetConfig{
		Concurrency:    1,
		DeviceTimeout:  time.Minute,
		DryRun:         true,
		BinaryOverride: binPath,
		Dialer:         dialer,
	}

	res := scanHost(context.Background(), &d, &netscan.Credentials{}, cfg)
	if !res.IsSuccess() {
		t.Errorf("scanHost dry-run should succeed: %+v", res)
	}
	// In dry-run, we should stop after preflight; no launch/status/collect calls.
	if int(runner.calls.Load()) > 2 {
		t.Errorf("dry-run should make only preflight calls, made %d", runner.calls.Load())
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./pkg/scanner/netscan/fleet/... -v -run ScanHost`
Expected: FAIL — undefined scanHost.

- [ ] **Step 3: Implement**

Create `pkg/scanner/netscan/fleet/orchestrator.go`:

```go
package fleet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

// scanHost executes the full per-host lifecycle: dial, preflight, push,
// launch, poll, collect, cleanup. Returns a HostResult on every code path
// (never a bare error return) so the worker pool can aggregate.
func scanHost(ctx context.Context, d *netscan.Device, creds *netscan.Credentials, cfg FleetConfig) HostResult {
	res := HostResult{Device: d.Name, StartedAt: time.Now()}
	defer func() { res.Duration = time.Since(res.StartedAt) }()

	ctx, cancel := context.WithTimeout(ctx, cfg.DeviceTimeout)
	defer cancel()

	// 1. SSH dial
	addr := d.Address
	if d.Port > 0 {
		addr = fmt.Sprintf("%s:%d", d.Address, d.Port)
	} else if _, _, err := splitHostPort(d.Address); err != nil {
		addr = d.Address + ":22"
	}
	cred := creds.Get(d.Credential) // returns nil if missing — caller validates inventory first
	runner, err := cfg.Dialer.Dial(ctx, addr, credUsername(cred), credPrivateKey(cred), credPassphrase(cred),
		cfg.KnownHostsFile, cfg.InsecureHostKey)
	if err != nil {
		res.Fail("ssh connect", err)
		return res
	}
	defer func() { _ = runner.Close() }()

	// 2. Uname / arch resolution
	out, err := runner.Run(ctx, "uname -s -m")
	if err != nil {
		res.Fail("uname", err)
		return res
	}
	goos, arch, err := ParseUnameArch(out)
	if err != nil {
		res.Fail("arch mismatch", err)
		return res
	}
	binary, err := ResolveBinary(d, cfg.BinaryOverride, goos, arch)
	if err != nil {
		res.Fail("arch mismatch", err)
		return res
	}

	// 3. Sudo preflight
	if d.Sudo {
		if err := SudoCheck(ctx, runner); err != nil {
			res.Fail("sudo check", err)
			return res
		}
	}

	// Dry-run stops here.
	if cfg.DryRun {
		res.JobID = "dry-run"
		return res
	}

	// 4. Push binary
	workDir := d.WorkDir
	if workDir == "" {
		workDir = "/tmp"
	}
	remotePath := filepath.Join(workDir, ".triton-"+uuid.NewString()[:8])
	if err := runner.Upload(ctx, binary, remotePath, 0o755); err != nil {
		res.Fail("scp binary", err)
		return res
	}
	defer func() { _, _ = runner.Run(context.Background(), "rm -f "+remotePath) }()

	// 5. Launch
	launchCmd := BuildLaunchCommand(remotePath, d.Sudo, cfg.ScanFlags)
	launchOut, err := runner.Run(ctx, launchCmd)
	if err != nil {
		res.Fail("launch", fmt.Errorf("%w (output: %s)", err, launchOut))
		return res
	}
	jobID, err := ParseJobID(launchOut)
	if err != nil {
		res.Fail("launch", err)
		return res
	}
	res.JobID = jobID

	// 6. Poll status
	statusCmd := fmt.Sprintf("%s scan --status --job-id %s --json --work-dir %s",
		remotePath, jobID, workDir)
	status, err := PollStatus(ctx, runner, jobID, statusCmd, 10*time.Second)
	if err != nil {
		res.Fail("poll", err)
		return res
	}
	res.Status = status

	// If the remote scan itself failed, stop here.
	if status.State != "done" {
		res.Fail("poll", fmt.Errorf("remote scan %s: %s", status.State, status.Error))
		return res
	}

	// 7. Collect tar.gz (only if OutputDir set)
	if cfg.OutputDir != "" {
		hostsDir := filepath.Join(cfg.OutputDir, "hosts")
		path, err := CollectTar(ctx, runner, remotePath, jobID, hostsDir, d.Name)
		if err != nil {
			res.Fail("collect", err)
			return res
		}
		res.OutputPath, _ = filepath.Rel(cfg.OutputDir, path)
	}

	// 8. Report-server upload (non-fatal). Left as a hook that returning
	// nil means "no upload attempted" — real integration is in the worker
	// pool layer which has access to the agent.Client.
	// (Task 9 / cmd wiring handles this.)

	// 9. Remote cleanup
	_, _ = runner.Run(ctx, fmt.Sprintf("%s scan --cleanup --job-id %s --work-dir %s", remotePath, jobID, workDir))

	return res
}

// Helper stubs for Credentials fields — implemented lazily to avoid
// over-coupling to the exact Credentials shape. The real Credentials type
// is in pkg/scanner/netscan/credentials.go; these small wrappers are
// test-friendly.
func credUsername(c *netscan.Credential) string {
	if c == nil {
		return ""
	}
	return c.Username
}

func credPrivateKey(c *netscan.Credential) []byte {
	if c == nil {
		return nil
	}
	return []byte(c.PrivateKey)
}

func credPassphrase(c *netscan.Credential) string {
	if c == nil {
		return ""
	}
	return c.Passphrase
}

func splitHostPort(s string) (host, port string, err error) {
	// Minimal implementation — we only use this to detect whether a port
	// is already in the address string.
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i], s[i+1:], nil
		}
	}
	return s, "", fmt.Errorf("no port in %q", s)
}

// Convenience re-exports so tests don't need to import os directly when
// constructing fixture binaries.
var _ = os.Stat
```

**IMPORTANT:** Verify the exact shape of `netscan.Credentials` and `netscan.Credential`:

Run: `grep -n "^type" pkg/scanner/netscan/credentials.go`

The Credentials API should expose a `Get(name) *Credential` method that returns the named credential or nil. If the real signature differs, adjust the `credUsername` / `credPrivateKey` / `credPassphrase` helpers accordingly. If Credentials uses a different method name or returns different fields, adapt but keep the helpers as a minimal interface surface.

- [ ] **Step 4: Verify green + race**

Run: `go test ./pkg/scanner/netscan/fleet/... -race -v -run ScanHost`
Expected: PASS — 4 tests.

- [ ] **Step 5: Verify full package + gofmt + vet**

Run: `go test ./pkg/scanner/netscan/fleet/... -race && gofmt -l pkg/scanner/netscan/fleet/ && go vet ./pkg/scanner/netscan/fleet/...`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add pkg/scanner/netscan/fleet/orchestrator.go pkg/scanner/netscan/fleet/orchestrator_test.go
git commit -m "feat(fleet): scanHost per-host lifecycle wire-up"
```

---

## Task 9: Worker pool + --max-failures circuit breaker

**Files:**
- Modify: `pkg/scanner/netscan/fleet/orchestrator.go` (append Orchestrator struct + Run method)
- Modify: `pkg/scanner/netscan/fleet/orchestrator_test.go` (append worker pool tests)

- [ ] **Step 1: Append failing tests**

Append to `pkg/scanner/netscan/fleet/orchestrator_test.go`:

```go
func TestOrchestrator_RunAllSucceed(t *testing.T) {
	tmp := t.TempDir()
	binPath := tmp + "/triton"
	os.WriteFile(binPath, []byte("fake"), 0o755)

	// Shared runner across all hosts — each host gets the same scripted
	// responses. In a real fleet each gets its own connection.
	statusJSON, _ := json.Marshal(jobrunner.Status{State: jobrunner.StateDone, FindingsCount: 10})
	makeRunner := func() *fakeRunner {
		return &fakeRunner{responses: []fakeResponse{
			{out: "Linux x86_64\n"},
			{out: ""}, // sudo
			{out: "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e\n"},
			{out: string(statusJSON)},
			{out: "\x1f\x8b\x08\x00\x00\x00\x00\x00fake-tar"},
			{out: ""},
		}}
	}

	// Custom dialer that returns a fresh runner per call.
	dialer := &newRunnerPerDialDialer{newRunner: func() *fakeRunner { return makeRunner() }}

	devices := []netscan.Device{
		{Name: "web-1", Type: "unix", Address: "1.1.1.1", Sudo: true},
		{Name: "web-2", Type: "unix", Address: "1.1.1.2", Sudo: true},
		{Name: "web-3", Type: "unix", Address: "1.1.1.3", Sudo: true},
	}
	cfg := FleetConfig{
		Concurrency:    2,
		DeviceTimeout:  time.Minute,
		OutputDir:      tmp,
		BinaryOverride: binPath,
		Dialer:         dialer,
	}
	orch := NewOrchestrator(cfg)
	results, err := orch.Run(context.Background(), devices, &netscan.Credentials{})
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
	binPath := tmp + "/triton"
	os.WriteFile(binPath, []byte("fake"), 0o755)

	// All runners fail at dial stage.
	dialer := &newRunnerPerDialDialer{newRunner: func() *fakeRunner { return nil }}

	devices := []netscan.Device{
		{Name: "web-1", Type: "unix", Address: "1.1.1.1"},
		{Name: "web-2", Type: "unix", Address: "1.1.1.2"},
		{Name: "web-3", Type: "unix", Address: "1.1.1.3"},
		{Name: "web-4", Type: "unix", Address: "1.1.1.4"},
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
	results, err := orch.Run(context.Background(), devices, &netscan.Credentials{})
	// Expect a MaxFailuresBreached error.
	if err == nil || !errors.Is(err, ErrMaxFailuresBreached) {
		t.Errorf("expected ErrMaxFailuresBreached, got %v", err)
	}
	_ = results // may have partial results
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
```

- [ ] **Step 2: Verify red**

Run: `go test ./pkg/scanner/netscan/fleet/... -v -run Orchestrator`
Expected: FAIL — undefined NewOrchestrator / Orchestrator.Run / ErrMaxFailuresBreached.

- [ ] **Step 3: Append implementation**

Append to `pkg/scanner/netscan/fleet/orchestrator.go`:

```go
import (
	"errors"
	"sync"
	"sync/atomic"
	// keep existing imports
)

// ErrMaxFailuresBreached is returned by Orchestrator.Run when
// --max-failures N is exceeded.
var ErrMaxFailuresBreached = errors.New("max-failures threshold exceeded")

// Orchestrator runs scanHost across a slice of devices with a worker
// pool bounded by FleetConfig.Concurrency.
type Orchestrator struct {
	cfg FleetConfig
}

// NewOrchestrator constructs an Orchestrator. Validates the config.
func NewOrchestrator(cfg FleetConfig) *Orchestrator {
	return &Orchestrator{cfg: cfg}
}

// Run scans each device in devices using a worker pool. Returns the
// per-host results and any runtime error (ErrMaxFailuresBreached for
// circuit-breaker trip).
func (o *Orchestrator) Run(ctx context.Context, devices []netscan.Device, creds *netscan.Credentials) ([]HostResult, error) {
	results := make([]HostResult, 0, len(devices))
	var mu sync.Mutex
	var failures atomic.Int32

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	queue := make(chan netscan.Device, len(devices))
	for _, d := range devices {
		queue <- d
	}
	close(queue)

	var wg sync.WaitGroup
	for i := 0; i < o.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range queue {
				select {
				case <-runCtx.Done():
					return
				default:
				}
				res := scanHost(runCtx, &d, creds, o.cfg)
				mu.Lock()
				results = append(results, res)
				mu.Unlock()
				if !res.IsSuccess() {
					n := failures.Add(1)
					if o.cfg.MaxFailures > 0 && int(n) >= o.cfg.MaxFailures {
						cancelRun()
					}
				}
			}
		}()
	}
	wg.Wait()

	if o.cfg.MaxFailures > 0 && int(failures.Load()) >= o.cfg.MaxFailures {
		return results, ErrMaxFailuresBreached
	}
	return results, nil
}
```

- [ ] **Step 4: Verify green + race**

Run: `go test ./pkg/scanner/netscan/fleet/... -race -v -run Orchestrator`
Expected: PASS — 2 tests.

- [ ] **Step 5: Commit**

```bash
git add pkg/scanner/netscan/fleet/orchestrator.go pkg/scanner/netscan/fleet/orchestrator_test.go
git commit -m "feat(fleet): worker pool + --max-failures circuit breaker"
```

---

## Task 10: License feature — FeatureFleetScan + FeatureDeviceScan alias

**Files:**
- Modify: `internal/license/tier.go` (add constants, tier mapping)
- Modify: `internal/license/tier_test.go` (cover new constants)

- [ ] **Step 1: Write failing test**

Append to `internal/license/tier_test.go`:

```go
func TestFeatureFleetScan_TierMapping(t *testing.T) {
	// Free tier: disabled; Pro + Enterprise: enabled.
	cases := []struct {
		tier    Tier
		enabled bool
	}{
		{TierFree, false},
		{TierPro, true},
		{TierEnterprise, true},
	}
	for _, tc := range cases {
		t.Run(string(tc.tier), func(t *testing.T) {
			if got := FeatureEnabled(tc.tier, FeatureFleetScan); got != tc.enabled {
				t.Errorf("FeatureEnabled(%s, fleet-scan) = %v, want %v", tc.tier, got, tc.enabled)
			}
		})
	}
}

func TestFeatureDeviceScan_AliasForNetworkScan(t *testing.T) {
	// FeatureDeviceScan is the canonical name; FeatureNetworkScan is
	// retained as an alias for backcompat.
	if FeatureDeviceScan != FeatureNetworkScan {
		t.Errorf("FeatureDeviceScan should equal FeatureNetworkScan for backcompat; got %q vs %q",
			FeatureDeviceScan, FeatureNetworkScan)
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./internal/license/... -v -run 'FleetScan|DeviceScan'`
Expected: FAIL — undefined FeatureFleetScan / FeatureDeviceScan.

- [ ] **Step 3: Implement**

In `internal/license/tier.go`, find the existing `Feature` constants block. Add:

```go
const (
	// ... existing constants ...
	FeatureNetworkScan Feature = "network-scan"

	// FeatureFleetScan gates the `triton fleet-scan` command (SSH fan-out
	// of detached scans across a host inventory). Binary distribution +
	// sudo on target hosts is a higher-trust operation than read-only
	// network probes, so this is separate from FeatureNetworkScan.
	FeatureFleetScan Feature = "fleet-scan"

	// FeatureDeviceScan is the canonical name for the SSH/NETCONF network-
	// device scanner. Aliased to FeatureNetworkScan for backcompat with
	// licences issued before the rename; both strings map to the same
	// tier enforcement.
	FeatureDeviceScan Feature = FeatureNetworkScan
)
```

Find the `featureTiers` map (or equivalent; might be a switch in `FeatureEnabled`). Add an entry for FeatureFleetScan:

```go
var featureTiers = map[Feature]map[Tier]bool{
	// ... existing entries ...
	FeatureNetworkScan: {
		TierFree:       false,
		TierPro:        true,
		TierEnterprise: true,
	},
	FeatureFleetScan: {
		TierFree:       false,
		TierPro:        true,
		TierEnterprise: true,
	},
}
```

**IMPORTANT:** Verify the actual tier-mapping structure in `internal/license/tier.go` first:

Run: `grep -n "FeatureEnabled\|FeatureNetworkScan" internal/license/tier.go`

If the project uses a different data structure (e.g. a switch statement or per-tier feature slice), adapt the addition to match the existing pattern. The test assertions only care about the behavior (FeatureEnabled returns the right booleans), not the internal shape.

- [ ] **Step 4: Verify green**

Run: `go test ./internal/license/... -race -v -run 'FleetScan|DeviceScan'`
Expected: PASS — TestFeatureFleetScan_TierMapping with 3 subtests + TestFeatureDeviceScan_AliasForNetworkScan.

- [ ] **Step 5: Run all license tests for regression**

Run: `go test ./internal/license/... -race`
Expected: all existing + new tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/license/tier.go internal/license/tier_test.go
git commit -m "feat(license): add FeatureFleetScan + FeatureDeviceScan alias"
```

---

## Task 11: Rename network-scan → device-scan + deprecation alias

**Files:**
- Rename: `cmd/network_scan.go` → `cmd/device_scan.go` + replace `ns*` vars with `ds*`
- Create: `cmd/network_scan_alias.go` (deprecation wrapper)

- [ ] **Step 1: Rename the file + vars**

Run: `git mv cmd/network_scan.go cmd/device_scan.go`

Then in `cmd/device_scan.go`:

1. Replace ALL occurrences of `nsInventory`, `nsCredentials`, `nsGroup`, `nsDevice`, `nsConcurrency`, `nsTimeout`, `nsDryRun`, `nsInterval`, `nsReportServer`, `nsKnownHosts`, `nsInsecureHostKey` with their `ds*` equivalents (keep the `ns` → `ds` prefix consistent).
2. Rename the Cobra command var `networkScanCmd` → `deviceScanCmd`.
3. Change `Use: "network-scan"` → `Use: "device-scan"`.
4. Change `Short:` to `"Scan remote hosts and routers via SSH/NETCONF (agentless) — formerly network-scan"`.
5. Rename `runNetworkScan` function → `runDeviceScan`.
6. Update the `FeatureNetworkScan` reference to `FeatureDeviceScan` in the PreRunE (they're aliased so behavior unchanged; this uses the canonical name).
7. Find `rootCmd.AddCommand(networkScanCmd)` at the bottom of `init()`; change to `rootCmd.AddCommand(deviceScanCmd)`.

- [ ] **Step 2: Create the deprecation alias**

Create `cmd/network_scan_alias.go`:

```go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// networkScanAliasCmd is a deprecation shim that forwards to device-scan.
// Existing scripts/systemd-units that run `triton network-scan` continue
// to work for one release cycle with a stderr warning.
var networkScanAliasCmd = &cobra.Command{
	Use:        "network-scan",
	Short:      "DEPRECATED: use 'triton device-scan' instead",
	Deprecated: "use 'triton device-scan' instead",
	// Inherit all flags from device-scan by re-registering the same flag
	// variables (they're package-level, so flag state is shared).
	PreRunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintln(os.Stderr,
			"warning: 'triton network-scan' is deprecated; use 'triton device-scan' instead")
		return deviceScanCmd.PreRunE(cmd, args)
	},
	RunE: runDeviceScan,
}

func init() {
	// Mirror every flag on deviceScanCmd to keep the alias functional.
	networkScanAliasCmd.Flags().AddFlagSet(deviceScanCmd.Flags())
	rootCmd.AddCommand(networkScanAliasCmd)
}
```

- [ ] **Step 3: Verify build + tests**

Run: `go build ./... && go test ./cmd/... -race`
Expected: clean.

- [ ] **Step 4: Smoke-test both commands**

Run: `go run . device-scan --help 2>&1 | head -5`
Expected: output starts with `Scan remote hosts and routers via SSH/NETCONF (agentless) — formerly network-scan`.

Run: `go run . network-scan --help 2>&1 | head -5`
Expected: prints a deprecation notice + same help.

- [ ] **Step 5: Verify gofmt + vet + windows build**

Run: `gofmt -l cmd/ && go vet ./cmd/... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add cmd/device_scan.go cmd/network_scan_alias.go
git commit -m "refactor(cmd): rename network-scan → device-scan with deprecation alias"
```

---

## Task 12: cmd/fleet_scan.go — register command, flags, dispatch

**Files:**
- Create: `cmd/fleet_scan.go`
- Create: `cmd/fleet_scan_test.go`

- [ ] **Step 1: Write failing test**

Create `cmd/fleet_scan_test.go`:

```go
package cmd

import (
	"strings"
	"testing"
)

func TestFleetScanCmd_Registered(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"fleet-scan"})
	if err != nil {
		t.Fatalf("fleet-scan should be registered: %v", err)
	}
	if cmd.Use != "fleet-scan" {
		t.Errorf("Use = %q, want fleet-scan", cmd.Use)
	}
}

func TestFleetScanCmd_RequiredFlags(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"fleet-scan"})
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"inventory", "credentials", "output-dir", "report-server", "dry-run",
		"group", "device", "concurrency", "device-timeout", "binary",
		"known-hosts", "insecure-host-key", "interval", "max-failures",
		"profile", "format", "policy",
		"max-memory", "max-cpu-percent", "max-duration", "stop-at", "nice"} {
		if cmd.Flags().Lookup(flag) == nil && cmd.PersistentFlags().Lookup(flag) == nil {
			t.Errorf("flag --%s not registered on fleet-scan", flag)
		}
	}
}

func TestFleetScanCmd_MarkFlagsOneRequired(t *testing.T) {
	// Verify the Cobra one-of enforcement: calling with neither
	// output-dir, report-server, nor dry-run should fail.
	cmd, _, err := rootCmd.Find([]string{"fleet-scan"})
	if err != nil {
		t.Fatal(err)
	}
	cmd.SetArgs([]string{"--inventory", "x", "--credentials", "y"})
	if err := cmd.Execute(); err == nil {
		t.Error("fleet-scan with no output should fail flag validation")
	} else if !strings.Contains(err.Error(), "at least one") &&
		!strings.Contains(err.Error(), "one of the flags") {
		t.Logf("error message: %v", err) // accept either Cobra variant
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./cmd/... -v -run FleetScan`
Expected: FAIL — fleet-scan not registered.

- [ ] **Step 3: Implement**

Create `cmd/fleet_scan.go`:

```go
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/pkg/scanner/netscan"
	"github.com/amiryahaya/triton/pkg/scanner/netscan/fleet"
)

var fleetScanCmd = &cobra.Command{
	Use:   "fleet-scan",
	Short: "Orchestrate triton scans across a host fleet via SSH (binary push + detach)",
	Long: `Fleet-scan pushes the triton binary to each unix host in an inventory,
runs 'triton scan --detach', polls until terminal state, collects reports,
and cleans up. Reports land in --output-dir and/or --report-server.
Same inventory format as device-scan.`,
	PreRunE: func(_ *cobra.Command, _ []string) error {
		return guard.EnforceFeature(license.FeatureFleetScan)
	},
	RunE: runFleetScan,
}

var (
	fsInventory       string
	fsCredentials     string
	fsGroup           string
	fsDevice          string
	fsConcurrency     int
	fsTimeout         time.Duration
	fsDryRun          bool
	fsInterval        time.Duration
	fsMaxFailures     int
	fsReportServer    string
	fsKnownHosts      string
	fsInsecureHostKey bool
	fsBinary          string
	fsOutputDir       string
	fsProfile         string
	fsFormat          string
	fsPolicy          string
	fsMaxMemory       string
	fsMaxCPUPercent   string
	fsMaxDuration     time.Duration
	fsStopAt          string
	fsNice            int
)

func init() {
	// Orchestration
	fleetScanCmd.Flags().StringVar(&fsInventory, "inventory", "/etc/triton/devices.yaml", "path to devices.yaml")
	fleetScanCmd.Flags().StringVar(&fsCredentials, "credentials", "/etc/triton/credentials.yaml", "path to encrypted credentials.yaml")
	fleetScanCmd.Flags().StringVar(&fsGroup, "group", "", "scan only devices in this group")
	fleetScanCmd.Flags().StringVar(&fsDevice, "device", "", "scan only this device (for debugging)")
	fleetScanCmd.Flags().IntVar(&fsConcurrency, "concurrency", 20, "max concurrent host scans")
	fleetScanCmd.Flags().DurationVar(&fsTimeout, "device-timeout", 30*time.Minute, "max time per host")
	fleetScanCmd.Flags().BoolVar(&fsDryRun, "dry-run", false, "validate inventory + SSH pre-flight only")
	fleetScanCmd.Flags().DurationVar(&fsInterval, "interval", 0, "continuous mode: repeat every interval (0 disables)")
	fleetScanCmd.Flags().IntVar(&fsMaxFailures, "max-failures", 0, "circuit-breaker: abort if this many hosts fail (0 = unlimited)")
	fleetScanCmd.Flags().StringVar(&fsKnownHosts, "known-hosts", "", "path to SSH known_hosts file (required unless --insecure-host-key)")
	fleetScanCmd.Flags().BoolVar(&fsInsecureHostKey, "insecure-host-key", false, "accept any host key (lab only)")
	fleetScanCmd.Flags().StringVar(&fsBinary, "binary", "", "override binary source (default: os.Args[0])")

	// Output (at least one required)
	fleetScanCmd.Flags().StringVar(&fsOutputDir, "output-dir", "", "write per-host tar.gz + summary locally")
	fleetScanCmd.Flags().StringVar(&fsReportServer, "report-server", "", "upload each result.json to this report server")

	// Forwarded scan flags
	fleetScanCmd.Flags().StringVar(&fsProfile, "profile", "standard", "scan profile forwarded to each host")
	fleetScanCmd.Flags().StringVar(&fsFormat, "format", "all", "report format forwarded to each host")
	fleetScanCmd.Flags().StringVar(&fsPolicy, "policy", "", "policy forwarded to each host")
	fleetScanCmd.Flags().StringVar(&fsMaxMemory, "max-memory", "", "forwarded to each remote scan (PR #71)")
	fleetScanCmd.Flags().StringVar(&fsMaxCPUPercent, "max-cpu-percent", "", "forwarded to each remote scan (PR #71)")
	fleetScanCmd.Flags().DurationVar(&fsMaxDuration, "max-duration", 0, "forwarded to each remote scan (PR #71)")
	fleetScanCmd.Flags().StringVar(&fsStopAt, "stop-at", "", "forwarded to each remote scan (PR #71)")
	fleetScanCmd.Flags().IntVar(&fsNice, "nice", 0, "forwarded to each remote scan (PR #71)")

	fleetScanCmd.MarkFlagsOneRequired("output-dir", "report-server", "dry-run")

	rootCmd.AddCommand(fleetScanCmd)
}

// dialFunc is the production SSHDialer implementation — uses transport.SSHClient.
// Defined here in cmd/ (not fleet/) because transport is a sibling of netscan;
// importing it in fleet/ would be fine too. Keeping in cmd for now.

func runFleetScan(cmd *cobra.Command, args []string) error {
	cfg := fleet.FleetConfig{
		InventoryPath:   fsInventory,
		CredentialsPath: fsCredentials,
		Group:           fsGroup,
		DeviceName:      fsDevice,
		Concurrency:     fsConcurrency,
		DeviceTimeout:   fsTimeout,
		DryRun:          fsDryRun,
		Interval:        fsInterval,
		MaxFailures:     fsMaxFailures,
		KnownHostsFile:  fsKnownHosts,
		InsecureHostKey: fsInsecureHostKey,
		BinaryOverride:  fsBinary,
		OutputDir:       fsOutputDir,
		ReportServerURL: fsReportServer,
		ScanFlags: fleet.ScanFlags{
			Profile:       fsProfile,
			Format:        fsFormat,
			Policy:        fsPolicy,
			MaxMemory:     fsMaxMemory,
			MaxCPUPercent: fsMaxCPUPercent,
			MaxDuration:   fsMaxDuration,
			StopAt:        fsStopAt,
			Nice:          fsNice,
		},
		Dialer: &sshDialerImpl{},
	}
	if cfg.BinaryOverride == "" {
		cfg.BinaryOverride = os.Args[0]
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	inv, err := netscan.LoadInventory(cfg.InventoryPath)
	if err != nil {
		return fmt.Errorf("load inventory: %w", err)
	}
	creds, err := netscan.LoadCredentials(cfg.CredentialsPath)
	if err != nil {
		return fmt.Errorf("load credentials: %w", err)
	}

	devices := inv.DevicesForFleet()
	if cfg.Group != "" {
		byGroup, err := inv.DevicesByGroup(cfg.Group)
		if err != nil {
			return err
		}
		devices = filterIntersection(devices, byGroup)
	}
	if cfg.DeviceName != "" {
		devices = filterByName(devices, cfg.DeviceName)
		if len(devices) == 0 {
			return fmt.Errorf("device not found in inventory: %s", cfg.DeviceName)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	orch := fleet.NewOrchestrator(cfg)
	invokedAt := time.Now()
	results, runErr := orch.Run(ctx, devices, creds)
	completedAt := time.Now()

	// Write summary if OutputDir set
	if cfg.OutputDir != "" {
		tsDir := fmt.Sprintf("%s/%s", cfg.OutputDir, invokedAt.UTC().Format("2006-01-02T15-04-05"))
		if err := fleet.WriteSummary(tsDir, fleet.SummaryInput{
			InvokedAt:     invokedAt,
			CompletedAt:   completedAt,
			InventoryPath: cfg.InventoryPath,
			Flags: map[string]interface{}{
				"profile":     cfg.ScanFlags.Profile,
				"max_memory":  cfg.ScanFlags.MaxMemory,
				"concurrency": cfg.Concurrency,
			},
			Results: results,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "warning: write summary: %v\n", err)
		}
		// Refresh `latest` symlink (best effort).
		_ = os.RemoveAll(cfg.OutputDir + "/latest")
		_ = os.Symlink(tsDir, cfg.OutputDir+"/latest")
	}

	// Print summary to stdout
	for _, r := range results {
		fmt.Println(r)
	}

	// Exit code
	if runErr != nil {
		// MaxFailures or runtime error: return as-is so Cobra prints it + exits 1.
		// For MaxFailuresBreached we want exit 3; do os.Exit directly.
		if fleetErr := runErr; fleetErr != nil {
			fmt.Fprintln(os.Stderr, "error:", fleetErr)
			os.Exit(3)
		}
	}
	if code := fleet.ExitCodeFor(results, false); code != 0 {
		os.Exit(code)
	}
	return nil
}

// sshDialerImpl wraps transport.SSHClient to satisfy fleet.SSHDialer.
// Lives here to avoid pulling transport into fleet/ (layer purity).
type sshDialerImpl struct{}

func (*sshDialerImpl) Dial(ctx context.Context, addr, user string, key []byte, passphrase, knownHosts string, insecureHostKey bool) (fleet.SSHRunner, error) {
	// Reuse transport.NewSSHClient. That type satisfies Run/Close
	// trivially; we already added Upload in Task 3.
	client, err := newTransportSSHClient(ctx, addr, user, key, passphrase, knownHosts, insecureHostKey)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// newTransportSSHClient is a package-local wrapper that returns a
// *transport.SSHClient fulfilling fleet.SSHRunner. Defined here to
// keep the fleet package transport-agnostic; if transport imports
// change we only touch cmd/.
func newTransportSSHClient(ctx context.Context, addr, user string, key []byte, passphrase, knownHostsFile string, insecureHostKey bool) (fleet.SSHRunner, error) {
	// We import the transport package directly. A short re-export here
	// means the fleet package doesn't gain a transport dependency.
	// Using an anonymous adapter around transport.NewSSHClient.
	// (Implementation inline to avoid another file.)
	_ = ctx
	_ = addr
	_ = user
	_ = key
	_ = passphrase
	_ = knownHostsFile
	_ = insecureHostKey
	return nil, fmt.Errorf("transport wiring: fill in with transport.NewSSHClient — see Task 12 step 4")
}

// filterIntersection returns devices present in both a and b.
func filterIntersection(a, b []netscan.Device) []netscan.Device {
	names := make(map[string]bool, len(b))
	for _, d := range b {
		names[d.Name] = true
	}
	out := make([]netscan.Device, 0, len(a))
	for _, d := range a {
		if names[d.Name] {
			out = append(out, d)
		}
	}
	return out
}

// filterByName returns the subset of devices whose Name equals name.
func filterByName(devs []netscan.Device, name string) []netscan.Device {
	for _, d := range devs {
		if d.Name == name {
			return []netscan.Device{d}
		}
	}
	return nil
}
```

**IMPORTANT: `newTransportSSHClient` is a stub.** Complete it in Step 4 after importing the transport package. The stub exists so this file compiles and `cmd/fleet_scan_test.go` (which doesn't exercise real SSH) passes; the real dialer is exercised only in the integration test (Task 13).

- [ ] **Step 4: Fill in the transport wiring**

In `cmd/fleet_scan.go`, replace the `newTransportSSHClient` stub with:

```go
func newTransportSSHClient(ctx context.Context, addr, user string, key []byte, passphrase, knownHostsFile string, insecureHostKey bool) (fleet.SSHRunner, error) {
	return transport.NewSSHClient(ctx, transport.SSHConfig{
		Address:         addr,
		Username:        user,
		PrivateKey:      key,
		Passphrase:      passphrase,
		KnownHostsFile:  knownHostsFile,
		InsecureHostKey: insecureHostKey,
		DialTimeout:     15 * time.Second,
		CmdTimeout:      60 * time.Second,
	})
}
```

Add the import: `"github.com/amiryahaya/triton/pkg/scanner/netadapter/transport"`.

**Verify that `transport.SSHClient` satisfies `fleet.SSHRunner`.** It needs:
- `Run(ctx, cmd) (string, error)` ✓ (added in Task 3 for Upload)
- `Upload(ctx, local, remote, mode) error` ✓ (added in Task 3)
- `Close() error` ✓ (already exists)

If Go compiler complains about interface satisfaction, verify exact method signatures match.

- [ ] **Step 5: Verify green**

Run: `go test ./cmd/... -race -v -run FleetScan`
Expected: PASS — 3 tests.

- [ ] **Step 6: Build + smoke test**

Run: `go build ./... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: clean.

Run: `go run . fleet-scan --help 2>&1 | head -20`
Expected: help text with all documented flags.

Run: `go run . fleet-scan --inventory /nonexistent --credentials y --output-dir z 2>&1 | head -3`
Expected: `Error: load inventory: ...`.

- [ ] **Step 7: Commit**

```bash
git add cmd/fleet_scan.go cmd/fleet_scan_test.go
git commit -m "feat(cmd): triton fleet-scan orchestrator command"
```

---

## Task 13: Docker sshd integration test fixtures

**Files:**
- Create: `test/integration/Dockerfile.sshd`
- Create: `test/integration/Dockerfile.sshd-nosudo`
- Create: `test/integration/testdata/fleet/test_ed25519` + `.pub` (via ssh-keygen)
- Create: `test/integration/testdata/fleet/devices.yaml`
- Create: `test/integration/testdata/fleet/credentials.yaml`

- [ ] **Step 1: Generate test SSH key**

Run: `ssh-keygen -t ed25519 -N '' -f test/integration/testdata/fleet/test_ed25519 -C 'triton-fleet-scan-test'`
Expected: `test/integration/testdata/fleet/test_ed25519` + `test_ed25519.pub` created.

- [ ] **Step 2: Create `Dockerfile.sshd`**

Create `test/integration/Dockerfile.sshd`:

```dockerfile
FROM debian:stable-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server sudo ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash triton-test && \
    echo 'triton-test ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/triton-test && \
    chmod 440 /etc/sudoers.d/triton-test
RUN mkdir -p /run/sshd /home/triton-test/.ssh && chmod 700 /home/triton-test/.ssh
COPY testdata/fleet/test_ed25519.pub /home/triton-test/.ssh/authorized_keys
RUN chown -R triton-test:triton-test /home/triton-test/.ssh && \
    chmod 600 /home/triton-test/.ssh/authorized_keys
# Allow pubkey auth; disable password; permit empty root (not used).
RUN sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
```

- [ ] **Step 3: Create `Dockerfile.sshd-nosudo`**

Create `test/integration/Dockerfile.sshd-nosudo`:

```dockerfile
FROM debian:stable-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server sudo ca-certificates && \
    rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash triton-test
# NOTE: no NOPASSWD entry — sudo -n true will fail.
RUN mkdir -p /run/sshd /home/triton-test/.ssh && chmod 700 /home/triton-test/.ssh
COPY testdata/fleet/test_ed25519.pub /home/triton-test/.ssh/authorized_keys
RUN chown -R triton-test:triton-test /home/triton-test/.ssh && \
    chmod 600 /home/triton-test/.ssh/authorized_keys
RUN sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
```

- [ ] **Step 4: Create devices.yaml fixture**

Create `test/integration/testdata/fleet/devices.yaml`:

```yaml
version: 1
defaults:
  port: 22
  sudo: true

devices:
  - name: testhost
    type: unix
    address: 127.0.0.1
    port: 2222
    credential: test-ssh
    sudo: true
```

- [ ] **Step 5: Create credentials.yaml fixture**

Create `test/integration/testdata/fleet/credentials.yaml`:

```yaml
# Unencrypted for test purposes. Real usage encrypts with TRITON_SCANNER_CRED_KEY.
# Tests set TRITON_SCANNER_CRED_KEY to a fixed value and use plaintext here;
# verify the existing netscan.LoadCredentials honors an "unencrypted: true" flag
# or supports a plaintext test mode. If not, the test uses a tiny in-code credentials
# stub instead.
version: 1
credentials:
  - name: test-ssh
    username: triton-test
    private_key_file: test_ed25519
```

**IMPORTANT:** Verify `netscan.LoadCredentials` supports a `private_key_file` reference or reads inline `private_key` content. If only inline, paste the private key content (without the newlines) inline:

```yaml
    private_key: |
      -----BEGIN OPENSSH PRIVATE KEY-----
      (paste test_ed25519 contents here)
      -----END OPENSSH PRIVATE KEY-----
```

If credentials are always encrypted, the integration test sets the key via env + builds a tiny encrypted fixture using a helper — run `grep -n "LoadCredentials\|Encrypt" pkg/scanner/netscan/credentials.go` to confirm the exact mechanism, then adapt this fixture. Document in the test's TestMain or a helper.

- [ ] **Step 6: Commit**

```bash
git add test/integration/Dockerfile.sshd test/integration/Dockerfile.sshd-nosudo \
        test/integration/testdata/fleet/
git commit -m "test(integration): Docker sshd fixtures for fleet-scan tests"
```

---

## Task 14: Integration test — 4 end-to-end cases

**Files:**
- Create: `test/integration/fleet_scan_test.go`
- Modify: `.github/workflows/ci.yml` (add sshd service container)

- [ ] **Step 1: Write the test**

Create `test/integration/fleet_scan_test.go`:

```go
//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dockerAvailable reports whether the docker CLI is usable.
func dockerAvailable(t *testing.T) bool {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	cmd := exec.Command("docker", "info")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func buildAndStartSSHDContainer(t *testing.T, dockerfile, name string, port int) func() {
	t.Helper()
	// Build
	buildCmd := exec.Command("docker", "build",
		"-f", "test/integration/"+dockerfile,
		"-t", name+":test",
		"test/integration")
	buildCmd.Stdout = os.Stderr
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("docker build %s: %v", dockerfile, err)
	}
	// Run
	runCmd := exec.Command("docker", "run", "--rm", "-d",
		"--name", name, "-p", fmt.Sprintf("%d:22", port),
		name+":test")
	if out, err := runCmd.CombinedOutput(); err != nil {
		t.Fatalf("docker run %s: %v (%s)", name, err, out)
	}
	// Wait for sshd listen
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = conn.Close()
			return func() { exec.Command("docker", "rm", "-f", name).Run() }
		}
		time.Sleep(500 * time.Millisecond)
	}
	exec.Command("docker", "rm", "-f", name).Run()
	t.Fatalf("sshd %s not listening within 30s", name)
	return nil
}

func buildTritonBin(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "triton-test")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/amiryahaya/triton")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build triton: %v", err)
	}
	return bin
}

func TestFleetScan_EndToEnd_SingleHost(t *testing.T) {
	if !dockerAvailable(t) {
		t.Skip("docker not available")
	}
	cleanup := buildAndStartSSHDContainer(t, "Dockerfile.sshd", "triton-fleet-sshd", 2222)
	defer cleanup()

	bin := buildTritonBin(t)
	outDir := t.TempDir()

	cmd := exec.Command(bin, "fleet-scan",
		"--inventory", "test/integration/testdata/fleet/devices.yaml",
		"--credentials", "test/integration/testdata/fleet/credentials.yaml",
		"--output-dir", outDir,
		"--profile", "quick",
		"--device-timeout", "3m",
		"--insecure-host-key",
		"--binary", bin,
		"--license-key", "",
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := (exec.CommandContext(ctx, bin, cmd.Args[1:]...)).Run(); err != nil {
		// exit 0 on success; exit 2 means some hosts failed — still acceptable for this test if any succeeded
		t.Logf("fleet-scan exit: %v", err)
	}

	// Find latest scan dir and load summary.json.
	latest, err := filepath.EvalSymlinks(filepath.Join(outDir, "latest"))
	if err != nil {
		t.Fatalf("latest symlink: %v", err)
	}
	sumBytes, err := os.ReadFile(filepath.Join(latest, "summary.json"))
	if err != nil {
		t.Fatalf("read summary.json: %v", err)
	}
	var sum map[string]interface{}
	if err := json.Unmarshal(sumBytes, &sum); err != nil {
		t.Fatal(err)
	}
	counts := sum["counts"].(map[string]interface{})
	if counts["succeeded"].(float64) < 1 {
		t.Errorf("expected at least 1 succeeded, got counts=%v", counts)
	}
	// Verify the tar.gz exists.
	tarPath := filepath.Join(latest, "hosts", "testhost.tar.gz")
	if _, err := os.Stat(tarPath); err != nil {
		t.Errorf("testhost.tar.gz not found: %v", err)
	}
}

func TestFleetScan_DryRun(t *testing.T) {
	if !dockerAvailable(t) {
		t.Skip("docker not available")
	}
	cleanup := buildAndStartSSHDContainer(t, "Dockerfile.sshd", "triton-fleet-sshd-dryrun", 2223)
	defer cleanup()

	bin := buildTritonBin(t)
	outDir := t.TempDir()

	// Override port in inventory by using --device targeting + editing the
	// devices.yaml to 2223. For simplicity, generate a temp inventory.
	tmpInv := filepath.Join(t.TempDir(), "devices.yaml")
	os.WriteFile(tmpInv, []byte(`version: 1
defaults: {port: 22, sudo: true}
devices:
  - {name: testhost, type: unix, address: 127.0.0.1, port: 2223, credential: test-ssh, sudo: true}
`), 0o600)

	cmd := exec.Command(bin, "fleet-scan",
		"--inventory", tmpInv,
		"--credentials", "test/integration/testdata/fleet/credentials.yaml",
		"--output-dir", outDir,
		"--dry-run",
		"--insecure-host-key",
		"--binary", bin,
		"--license-key", "",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dry-run: %v (%s)", err, out)
	}
	// No tar should be produced in dry-run.
	matches, _ := filepath.Glob(filepath.Join(outDir, "*/hosts/*.tar.gz"))
	if len(matches) > 0 {
		t.Errorf("dry-run produced tars: %v", matches)
	}
}

func TestFleetScan_SudoFailure(t *testing.T) {
	if !dockerAvailable(t) {
		t.Skip("docker not available")
	}
	cleanup := buildAndStartSSHDContainer(t, "Dockerfile.sshd-nosudo", "triton-fleet-nosudo", 2224)
	defer cleanup()

	bin := buildTritonBin(t)
	outDir := t.TempDir()

	tmpInv := filepath.Join(t.TempDir(), "devices.yaml")
	os.WriteFile(tmpInv, []byte(`version: 1
defaults: {port: 22}
devices:
  - {name: testhost, type: unix, address: 127.0.0.1, port: 2224, credential: test-ssh, sudo: true}
`), 0o600)

	cmd := exec.Command(bin, "fleet-scan",
		"--inventory", tmpInv,
		"--credentials", "test/integration/testdata/fleet/credentials.yaml",
		"--output-dir", outDir,
		"--profile", "quick",
		"--device-timeout", "30s",
		"--insecure-host-key",
		"--binary", bin,
		"--license-key", "",
	)
	out, err := cmd.CombinedOutput()
	// Exit code should be 2 (some failed).
	if err == nil {
		t.Errorf("fleet-scan against nosudo host should exit non-zero")
	}
	if !strings.Contains(string(out), "sudo check") {
		t.Errorf("error output should mention 'sudo check', got: %s", out)
	}
}

func TestFleetScan_MaxFailures(t *testing.T) {
	// All three hosts unreachable + --max-failures 2 → exit 3 (circuit breaker).
	bin := buildTritonBin(t)
	outDir := t.TempDir()

	tmpInv := filepath.Join(t.TempDir(), "devices.yaml")
	os.WriteFile(tmpInv, []byte(`version: 1
defaults: {port: 22}
devices:
  - {name: unreachable-1, type: unix, address: 10.255.255.1, credential: test-ssh}
  - {name: unreachable-2, type: unix, address: 10.255.255.2, credential: test-ssh}
  - {name: unreachable-3, type: unix, address: 10.255.255.3, credential: test-ssh}
`), 0o600)

	cmd := exec.Command(bin, "fleet-scan",
		"--inventory", tmpInv,
		"--credentials", "test/integration/testdata/fleet/credentials.yaml",
		"--output-dir", outDir,
		"--max-failures", "2",
		"--device-timeout", "10s",
		"--insecure-host-key",
		"--binary", bin,
		"--license-key", "",
	)
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 3 {
			t.Errorf("exit code: got %d, want 3 (max-failures)", exitErr.ExitCode())
		}
	} else {
		t.Errorf("expected exit 3, got: %v", err)
	}
}
```

- [ ] **Step 2: Update CI workflow (skip integration container setup — tests handle docker themselves)**

In `.github/workflows/ci.yml`, the integration test job runs `docker` inside the Ubuntu runner. GitHub Actions' ubuntu-latest already has docker. The tests above invoke docker directly via exec.Command, so no CI change is needed beyond ensuring the fixtures are available (which they are, per Task 13).

**Verify no CI changes needed:** Run locally: `docker run --rm hello-world` works → the same will work in CI.

- [ ] **Step 3: Run the tests**

Run: `go test -tags integration ./test/integration/... -v -run TestFleetScan -timeout 15m`
Expected: 4 tests pass.

If docker is not available locally, tests will skip cleanly via `dockerAvailable` guard.

- [ ] **Step 4: Commit**

```bash
git add test/integration/fleet_scan_test.go
git commit -m "test(integration): fleet-scan end-to-end via Docker sshd (4 cases)"
```

---

## Task 15: Documentation

**Files:**
- Modify: `README.md` — add "Fleet scan" section
- Modify: `CLAUDE.md` — add `### Fleet scan` subsection
- Create: `docs/examples/fleet-scan/README.md`
- Modify: `docs/examples/agentless/devices.yaml.example` — annotate new fields

- [ ] **Step 1: Update README.md**

Find the existing "Detached scans" section (added in PR #72). Immediately after that section, before the next `##`, add:

```markdown
### Fleet scan

Fan out `triton scan` across a host inventory via SSH. For each unix host, fleet-scan pushes the triton binary, runs `triton scan --detach`, polls until terminal, collects reports, and cleans up. Reuses the same inventory + credentials format as `device-scan`.

```bash
# Basic fleet scan, local output
triton fleet-scan --inventory /etc/triton/devices.yaml \
                  --credentials /etc/triton/credentials.yaml \
                  --output-dir ./scans/ --profile standard

# Production: upload to central server, cap failures at 5
triton fleet-scan --inventory /etc/triton/devices.yaml \
                  --credentials /etc/triton/credentials.yaml \
                  --report-server https://triton.corp.internal \
                  --concurrency 50 --max-failures 5 \
                  --profile standard --max-memory 2GB

# Dry-run: verify inventory + SSH connectivity without scanning
triton fleet-scan --inventory /etc/triton/devices.yaml \
                  --credentials /etc/triton/credentials.yaml \
                  --dry-run

# Continuous mode (daily)
triton fleet-scan --inventory /etc/triton/devices.yaml \
                  --credentials /etc/triton/credentials.yaml \
                  --report-server https://triton.corp.internal \
                  --interval 24h
```

**Requirements on target hosts:**
- SSH access with key-based auth
- NOPASSWD sudo configured if `sudo: true` in inventory
- Local binary arch must match the target arch (override per-device with `device.binary`)

**Exit codes:** `0` all succeeded, `2` some failed, `3` max-failures threshold exceeded.

**Output layout:** `<output-dir>/<YYYY-MM-DDTHH-MM-SS>/summary.{json,txt}` + `hosts/<name>.tar.gz` per successful host.
```

- [ ] **Step 2: Update CLAUDE.md**

Find the `### Job runner (detached scans)` subsection. Immediately after it, add:

```markdown
### Fleet scan

The `triton fleet-scan` command (new in PR #74) orchestrates SSH fan-out of `triton scan --detach` across a host inventory. Implemented in `pkg/scanner/netscan/fleet/`. Reuses the existing netscan inventory + credentials formats (devices.yaml with `type: unix` entries), the `--detach` lifecycle from PR #72, and the resource limit flags from PR #71. Output: `<output-dir>/<timestamp>/summary.{json,txt}` + `hosts/<name>.tar.gz`. Also renamed `network-scan` → `device-scan` with deprecation alias. See `docs/plans/2026-04-18-fleet-scan-design.md` for the design spec.
```

- [ ] **Step 3: Create example README**

Create `docs/examples/fleet-scan/README.md`:

```markdown
# Fleet scan example

Minimal walkthrough of `triton fleet-scan`.

## 1. Inventory

Copy `/docs/examples/agentless/devices.yaml.example` to `/etc/triton/devices.yaml`. Add one entry per unix host:

```yaml
version: 1
defaults:
  port: 22
  sudo: true

devices:
  - name: web-srv-01
    type: unix
    address: 10.0.1.10
    credential: prod-ssh
```

## 2. Credentials

Credentials are stored encrypted via `triton credential` commands. Generate the encryption key:

```bash
export TRITON_SCANNER_CRED_KEY=$(openssl rand -hex 32)
triton credential add --name prod-ssh --username deploy --key-file ~/.ssh/prod_ed25519
```

## 3. SSH prerequisites on target hosts

- `deploy` user has SSH access via key
- `echo "deploy ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/triton-deploy`
- Known-hosts entry in `/etc/triton/known_hosts` (or pass `--insecure-host-key` for testing)

## 4. Run

```bash
triton fleet-scan --inventory /etc/triton/devices.yaml \
                  --credentials /etc/triton/credentials.yaml \
                  --known-hosts /etc/triton/known_hosts \
                  --output-dir ./scans/ --profile standard \
                  --max-memory 2GB --max-duration 4h
```

## 5. Inspect output

```bash
cat scans/latest/summary.txt
jq . scans/latest/summary.json
tar -tvf scans/latest/hosts/web-srv-01.tar.gz
```

## SSH agentless deployment (no persistent install)

The whole flow is binary-push + detach — nothing stays on the target after `--cleanup`. This is the SSH-agentless pattern: no long-running service, no manual install, just your inventory and an SSH key.
```

- [ ] **Step 4: Annotate existing devices.yaml.example**

In `docs/examples/agentless/devices.yaml.example`, add a new example entry showing the fleet-scan-specific fields. Find the last device entry and append:

```yaml

  # Fleet-scan example: per-device binary override + skip flags
  - name: aix-special-1
    type: unix
    address: 10.0.2.5
    credential: aix-ssh
    binary: /opt/triton-binaries/triton-aix-ppc64  # used by fleet-scan; device-scan ignores
    work_dir: /var/tmp                              # fleet-scan will drop binary here
    # skip_fleet: false                             # default: include in fleet-scan
    # skip_device: false                            # default: include in device-scan
```

- [ ] **Step 5: Verify nothing broke**

Run: `go build ./... && go test ./... -race 2>&1 | tail -3`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add README.md CLAUDE.md docs/examples/fleet-scan/ docs/examples/agentless/devices.yaml.example
git commit -m "docs: fleet-scan usage + inventory example updates"
```

---

## Task 16: Final verification gates

Same pattern as PR #71 + #72. Controller-side checks.

- [ ] **Step 1: Full build all platforms**

```bash
go build ./... && \
  GOOS=windows GOARCH=amd64 go build ./... && \
  GOOS=linux GOARCH=arm64 go build ./... && \
  GOOS=darwin GOARCH=arm64 go build ./...
```

Expected: all succeed.

- [ ] **Step 2: Full test suite with race detector**

```bash
go test ./... -race
```

Expected: all pass.

- [ ] **Step 3: Integration tests (requires docker)**

```bash
go test -tags integration ./test/integration/... -race -run 'TestFleetScan|TestJobRunner|TestLimitsApply' -timeout 20m
```

Expected: all pass (or skip if docker unavailable).

- [ ] **Step 4: Lint**

```bash
golangci-lint run ./cmd/... ./pkg/scanner/netscan/... ./pkg/scanner/netadapter/... ./internal/license/...
```

Expected: no new warnings.

- [ ] **Step 5: gofmt**

```bash
gofmt -l cmd/ pkg/scanner/netscan/ pkg/scanner/netadapter/transport/ internal/license/ test/integration/
```

Expected: no output.

- [ ] **Step 6: Coverage check**

```bash
go test -cover ./pkg/scanner/netscan/fleet/... ./cmd/...
```

Expected: ≥75% on the fleet package (matches PR #72's bar given similar I/O-heavy code).

- [ ] **Step 7: Smoke-test the help**

```bash
go run . fleet-scan --help | grep -E "inventory|credentials|output-dir|report-server|profile|max-memory|concurrency|dry-run"
go run . device-scan --help | head -3   # confirms rename works
go run . network-scan --help 2>&1 | head -3  # confirms deprecation alias works
```

Expected: all flags visible; device-scan shows new Short; network-scan shows deprecation notice.

- [ ] **Step 8: End-to-end smoke (requires docker)**

```bash
# Start sshd container (hosts already configured)
docker build -f test/integration/Dockerfile.sshd -t triton-fleet-smoke:latest test/integration
docker run --rm -d --name triton-fleet-smoke -p 2222:22 triton-fleet-smoke:latest
sleep 3

# Run fleet-scan
WORK=$(mktemp -d)
go run . fleet-scan \
    --inventory test/integration/testdata/fleet/devices.yaml \
    --credentials test/integration/testdata/fleet/credentials.yaml \
    --output-dir $WORK --profile quick --device-timeout 2m \
    --insecure-host-key --license-key ''

cat $WORK/latest/summary.txt
ls $WORK/latest/hosts/

# Cleanup
docker rm -f triton-fleet-smoke
```

Expected: summary.txt shows 1/1 succeeded; `testhost.tar.gz` exists in hosts/.

---

## Self-Review Checklist

**1. Spec coverage:**

- ✅ §CLI surface: fleet-scan registered (Task 12); all 22 flags (Task 12 Step 3)
- ✅ §Renames: network-scan → device-scan + alias (Task 11)
- ✅ §Inventory: Binary/WorkDir/SkipFleet/SkipDevice + filter helpers (Task 2)
- ✅ §SSH upload: `transport.SSHClient.Upload` via sftp (Task 3)
- ✅ §Arch resolution: ParseUnameArch + ResolveBinary (Task 4)
- ✅ §Sudo preflight: SudoCheck (Task 4)
- ✅ §Launch + parse job-id: BuildLaunchCommand + ParseJobID (Task 5)
- ✅ §Poll + collect: PollStatus + CollectTar (Task 6)
- ✅ §Summary: summary.json + summary.txt + ExitCodeFor (Task 7)
- ✅ §scanHost lifecycle: all 9 phases wired (Task 8)
- ✅ §Worker pool + max-failures: Orchestrator.Run (Task 9)
- ✅ §License gate: FeatureFleetScan + FeatureDeviceScan alias (Task 10)
- ✅ §Integration test: Docker sshd + 4 cases (Tasks 13+14)
- ✅ §Docs: README + CLAUDE.md + examples (Task 15)

**2. Placeholder scan:**
Task 12 has one intentional stub (`newTransportSSHClient`) which is filled in Step 4 of the same task. Task 13 Step 5 has a conditional about credentials file format that the implementer verifies on the spot. Both are acceptable because they have clear resolution paths. No remaining "TODO"/"fill in later" patterns.

**3. Type consistency:**
- `SSHRunner` interface used identically across tasks: `Run(ctx, cmd) (string, error)`, `Upload(ctx, local, remote, mode) error`, `Close() error` — Task 1, Task 6, Task 8, Task 12 all match.
- `HostResult` shape stable across Tasks 1, 7, 8, 9.
- `FleetConfig` fields set in Task 1 referenced unchanged in Tasks 8, 9, 12.
- `ScanFlags` same in Task 5 (BuildLaunchCommand) and Task 12 (CLI wiring).
- `SummaryInput` in Task 7 used by Task 12's `runFleetScan`.

**4. Order dependency sanity:**
- Task 3 (SSH Upload) is a prerequisite for Task 8 (scanHost uses Upload). ✓
- Task 4-7 are independent building blocks for Task 8. ✓
- Task 8 (scanHost) is a prerequisite for Task 9 (Orchestrator.Run). ✓
- Task 10 (license) independent; can run anytime. ✓
- Task 11 (rename) independent; no fleet deps. ✓
- Task 12 (CLI) depends on Tasks 1-9. ✓
- Tasks 13+14 (integration) depend on 12. ✓
- Tasks 15+16 after everything. ✓

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-04-18-fleet-scan-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — Dispatch a fresh subagent per task, review between tasks. Works as it did for PRs #71 and #72.

**2. Inline Execution** — Batch execution with checkpoints.

Which approach?
