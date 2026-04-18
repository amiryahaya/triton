package fleet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

// pollInterval is the default interval for polling remote scan status.
// Exposed as a package var so tests (once added) can shorten it; callers
// should not mutate it.
var pollInterval = 10 * time.Second

// scanHost executes the full per-host lifecycle: dial, preflight, push,
// launch, poll, collect, cleanup. Returns a HostResult on every path
// (never a bare error) so the worker pool (Task 9) can aggregate.
//
// Failures set res.Phase to a short phase identifier so the summary
// writer can group failures by phase.
func scanHost(ctx context.Context, d *netscan.Device, creds *netscan.CredentialStore, cfg FleetConfig) HostResult {
	res := HostResult{Device: d.Name, StartedAt: time.Now()}
	defer func() { res.Duration = time.Since(res.StartedAt) }()

	ctx, cancel := context.WithTimeout(ctx, cfg.DeviceTimeout)
	defer cancel()

	// 1. Resolve credential + load private key bytes.
	cred := creds.Get(d.Credential)
	if cred == nil {
		res.Fail("ssh connect", fmt.Errorf("credential %q not found", d.Credential))
		return res
	}
	var keyBytes []byte
	if cred.PrivateKeyPath != "" {
		b, err := os.ReadFile(cred.PrivateKeyPath)
		if err != nil {
			res.Fail("ssh connect", fmt.Errorf("read private key %s: %w", cred.PrivateKeyPath, err))
			return res
		}
		keyBytes = b
	}

	// 2. Compose address with port (default 22).
	addr := d.Address
	if d.Port > 0 {
		addr = fmt.Sprintf("%s:%d", d.Address, d.Port)
	} else {
		addr = d.Address + ":22"
	}

	// 3. SSH dial.
	runner, err := cfg.Dialer.Dial(ctx, addr, cred.Username, keyBytes, cred.Passphrase,
		cfg.KnownHostsFile, cfg.InsecureHostKey)
	if err != nil {
		res.Fail("ssh connect", err)
		return res
	}
	defer func() { _ = runner.Close() }()

	// 4. Uname / arch resolution.
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

	// 5. Sudo preflight (only if the device requires it).
	if d.Sudo {
		if err := SudoCheck(ctx, runner); err != nil {
			res.Fail("sudo check", err)
			return res
		}
	}

	// Dry-run stops here — preflight succeeded, we skip the push/launch.
	if cfg.DryRun {
		res.JobID = "dry-run"
		return res
	}

	// 6. Push binary to a scratch path under the device work dir.
	workDir := d.WorkDir
	if workDir == "" {
		workDir = "/tmp"
	}
	remotePath := filepath.ToSlash(filepath.Join(workDir, ".triton-"+uuid.NewString()[:8]))
	if err := runner.Upload(ctx, binary, remotePath, 0o755); err != nil {
		res.Fail("scp binary", err)
		return res
	}
	// Always attempt to remove the pushed binary, even on failure. Use a
	// detached context so a cancelled parent ctx doesn't suppress cleanup.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = runner.Run(cleanupCtx, "rm -f "+remotePath)
	}()

	// 7. Launch detached scan.
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

	// 8. Poll status until terminal.
	statusCmd := fmt.Sprintf("%s scan --status --job-id %s --json --work-dir %s",
		remotePath, jobID, workDir)
	status, err := PollStatus(ctx, runner, jobID, statusCmd, pollInterval)
	if err != nil {
		res.Fail("poll", err)
		return res
	}
	res.Status = status

	if status.State != jobrunner.StateDone {
		res.Fail("poll", fmt.Errorf("remote scan %s: %s", status.State, status.Error))
		return res
	}

	// 9. Collect tar.gz (only if OutputDir configured).
	if cfg.OutputDir != "" {
		hostsDir := filepath.Join(cfg.OutputDir, "hosts")
		path, err := CollectTar(ctx, runner, remotePath, jobID, hostsDir, d.Name)
		if err != nil {
			res.Fail("collect", err)
			return res
		}
		if rel, relErr := filepath.Rel(cfg.OutputDir, path); relErr == nil {
			res.OutputPath = rel
		} else {
			res.OutputPath = path
		}
	}

	// 10. Remote cleanup of job state dir. Best-effort — the deferred rm
	// above always runs for the pushed binary.
	_, _ = runner.Run(ctx, fmt.Sprintf("%s scan --cleanup --job-id %s --work-dir %s",
		remotePath, jobID, workDir))

	return res
}
