package fleet

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

// ErrMaxFailuresBreached is returned by Orchestrator.Run when
// --max-failures N is exceeded.
var ErrMaxFailuresBreached = errors.New("max-failures threshold exceeded")

// Orchestrator runs scanHost across a slice of devices with a worker
// pool bounded by FleetConfig.Concurrency.
type Orchestrator struct {
	cfg FleetConfig
}

// NewOrchestrator constructs an Orchestrator.
func NewOrchestrator(cfg FleetConfig) *Orchestrator {
	return &Orchestrator{cfg: cfg}
}

// Run scans each device in devices using a worker pool. Returns the
// per-host results and any runtime error (ErrMaxFailuresBreached for
// circuit-breaker trip).
func (o *Orchestrator) Run(ctx context.Context, devices []netscan.Device, creds *netscan.CredentialStore) ([]HostResult, error) {
	results := make([]HostResult, 0, len(devices))
	var mu sync.Mutex
	var failures atomic.Int32

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	queue := make(chan netscan.Device, len(devices))
	for i := range devices {
		queue <- devices[i]
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
	var addr string
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
	launchCmd := BuildLaunchCommand(remotePath, d.Sudo, workDir, cfg.ScanFlags)
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

	// 8. Poll status until terminal. Use sudo if launch used sudo so we
	// can read root-owned status.json under the work-dir.
	sudoPrefix := ""
	if d.Sudo {
		sudoPrefix = "sudo "
	}
	statusCmd := fmt.Sprintf("%s%s --status --job-id %s --json --work-dir %s",
		sudoPrefix, remotePath, jobID, workDir)
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

	// 9. Collect tar.gz (only if OutputDir configured). Pass sudo + workDir
	// so we read the root-owned reports dir.
	if cfg.OutputDir != "" {
		hostsDir := filepath.Join(cfg.OutputDir, "hosts")
		path, err := CollectTarWithOpts(ctx, runner, remotePath, jobID, hostsDir, d.Name, d.Sudo, workDir)
		if err != nil {
			res.Fail("collect", err)
			return res
		}
		if rel, relErr := filepath.Rel(cfg.OutputDir, path); relErr == nil {
			res.OutputPath = rel
		} else {
			res.OutputPath = path
		}

		// Upload to report-server if configured. Failures here are
		// non-fatal (recorded as res.Warning so the summary surfaces
		// them per-host) — the local tar is already on disk.
		if cfg.ReportServerURL != "" {
			if jsonPath, err := extractResultJSONFromTar(path); err == nil {
				uploadToReportServer(ctx, cfg, &res, jsonPath)
				_ = os.Remove(jsonPath)
			} else {
				res.Warning = fmt.Sprintf("extract result.json for upload: %v", err)
			}
		}
	}

	// 10. Remote cleanup of job state dir. Best-effort — the deferred rm
	// above always runs for the pushed binary.
	_, _ = runner.Run(ctx, fmt.Sprintf("%s%s --cleanup --job-id %s --work-dir %s",
		sudoPrefix, remotePath, jobID, workDir))

	return res
}

// uploadToReportServer POSTs a collected host's result.json to the
// orchestrator's configured ReportServerURL using pkg/agent.Client.
// Non-fatal: any failure is recorded in res.Warning so the summary
// surfaces it per-host; the local tar.gz has already been written.
func uploadToReportServer(ctx context.Context, cfg FleetConfig, res *HostResult, resultJSONPath string) {
	if cfg.ReportServerURL == "" {
		return
	}
	data, err := os.ReadFile(resultJSONPath)
	if err != nil {
		res.Warning = fmt.Sprintf("read result.json for upload: %v", err)
		return
	}
	result, err := decodeScanResult(data)
	if err != nil {
		res.Warning = fmt.Sprintf("parse result.json for upload: %v", err)
		return
	}
	client := agent.New(cfg.ReportServerURL)
	if _, err := client.Submit(ctx, result); err != nil {
		res.Warning = fmt.Sprintf("report-server upload: %v", err)
	}
}

// decodeScanResult accepts either a raw model.ScanResult or the
// wrapped `{generatedAt, result}` envelope produced by
// report.Generator.GenerateTritonJSON (the format that lands inside
// the collected tar). Returns the unwrapped ScanResult.
func decodeScanResult(data []byte) (*model.ScanResult, error) {
	var wrapped struct {
		GeneratedAt string            `json:"generatedAt"`
		Result      *model.ScanResult `json:"result"`
	}
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Result != nil && wrapped.Result.ID != "" {
		return wrapped.Result, nil
	}
	var raw model.ScanResult
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return &raw, nil
}

// extractResultJSONFromTar reads the scan-result JSON out of a
// collected fleet-scan tar.gz. The tar contains files from the remote
// job-dir's reports/ directory; the canonical ScanResult is written
// as triton-report-<ts>.json (without the .cdx. infix used by
// CycloneDX output). Returns the path to a temp file holding the
// extracted JSON — caller must os.Remove.
func extractResultJSONFromTar(tarPath string) (string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		// result.json is a .json file directly (not .cdx.json,
		// .sarif, .html, .xlsx, etc.).
		if strings.HasSuffix(h.Name, ".json") && !strings.Contains(h.Name, ".cdx.") {
			tmp, err := os.CreateTemp("", "triton-result-*.json")
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(tmp, tr); err != nil {
				_ = tmp.Close()
				_ = os.Remove(tmp.Name())
				return "", err
			}
			if err := tmp.Close(); err != nil {
				_ = os.Remove(tmp.Name())
				return "", err
			}
			return tmp.Name(), nil
		}
	}
	return "", fmt.Errorf("no result.json found in tar")
}
