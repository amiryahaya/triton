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
	DryRun      bool
	Interval    time.Duration
	MaxFailures int

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
		return errors.New("concurrency must be > 0")
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
