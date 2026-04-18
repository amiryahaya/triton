package cmd

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
	"runtime"
	"strings"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/license"
	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
	"github.com/amiryahaya/triton/internal/runtime/limits"
	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/policy"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/store"
)

// statusWriteInterval is the periodic tick for rewriting status.json when
// no progress event has arrived. 2 seconds balances freshness and I/O.
const statusWriteInterval = 2 * time.Second

// applyProgress merges a Progress event into the Status in place.
func applyProgress(s *jobrunner.Status, p scanner.Progress) {
	s.ProgressPct = p.Percent * 100
	if p.Status != "" {
		s.CurrentModule = p.Status
	}
	if p.Result != nil {
		s.FindingsCount = len(p.Result.Findings)
	}
}

// currentRSSMB returns the Go runtime's memory footprint in MB as a proxy
// for RSS. This matches the metric used by PR #71's memory watchdog.
func currentRSSMB() int {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int(m.Sys / (1 << 20))
}

// cancelPollInterval is the default poll rate for the cancel-flag watcher.
const cancelPollInterval = 2 * time.Second

// cancelFlagPoller watches jobDir/cancel.flag and invokes cancel() once
// the flag appears, then returns. Exits on ctx.Done without calling cancel.
func cancelFlagPoller(ctx context.Context, jobDir string, cancel context.CancelFunc) {
	cancelFlagPollerWithInterval(ctx, jobDir, cancel, cancelPollInterval)
}

// cancelFlagPollerWithInterval is the testable form with an explicit interval.
func cancelFlagPollerWithInterval(ctx context.Context, jobDir string, cancel func(), interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if jobrunner.IsCancelled(jobDir) {
				cancel()
				return
			}
		}
	}
}

// isDaemonMode reports whether the current process is a detached daemon
// (i.e. started by runScanDetached with TRITON_DETACHED=1 in its env).
func isDaemonMode() bool {
	return os.Getenv("TRITON_DETACHED") == "1"
}

// runScanDaemon is the entry point for a detached child process. It
// activates only when TRITON_DETACHED=1; otherwise the normal runScan
// path runs. Reads TRITON_JOB_ID and TRITON_WORK_DIR from env, acquires
// state.lock (fails fast if another daemon holds it), builds the scan
// engine, and launches three goroutines: eng.Scan, runStatusAndCollect,
// cancelFlagPoller.
func runScanDaemon(cmd *cobra.Command, _ []string) error {
	jobID := os.Getenv("TRITON_JOB_ID")
	workDir := os.Getenv("TRITON_WORK_DIR")
	if jobID == "" || workDir == "" {
		return errors.New("daemon mode requires TRITON_JOB_ID and TRITON_WORK_DIR")
	}
	jobDir := filepath.Join(workDir, jobID)

	lock, err := jobrunner.AcquireFileLock(filepath.Join(jobDir, "state.lock"))
	if err != nil {
		return fmt.Errorf("acquire state.lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// D1: self-report our PID so the parent's initial status (PID=0) is
	// corrected before any reader observes it. Without this, the status
	// writer goroutine can race with the parent's post-spawn patch and
	// leave PID=0 persisted — which Reconcile then treats as a stale
	// daemon and marks the job failed.
	if s, rerr := jobrunner.ReadStatus(jobDir); rerr == nil {
		s.PID = os.Getpid()
		_ = jobrunner.WriteStatusAtomic(jobDir, s)
	}

	cfg, err := buildScanConfigForCmd(cmd)
	if err != nil {
		writeTerminalFailure(jobDir, err)
		return err
	}
	lim, err := buildLimitsForCmd(cmd)
	if err != nil {
		writeTerminalFailure(jobDir, err)
		return err
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()
	ctx, cleanup := lim.Apply(baseCtx)
	defer cleanup()

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()
	if cfg.DBUrl != "" {
		if db, err := store.NewPostgresStore(ctx, cfg.DBUrl); err == nil {
			eng.SetStore(db)
			defer func() { _ = db.Close() }()
		}
	}

	progressCh := make(chan scanner.Progress, progressBufferSize)

	var firstResult atomic.Pointer[model.ScanResult]
	go eng.Scan(ctx, progressCh)
	go cancelFlagPoller(ctx, jobDir, baseCancel)

	// Status-writer runs inline so we can capture the final Result and
	// determine the terminal state after progressCh closes.
	runStatusAndCollect(ctx, jobDir, progressCh, &firstResult)

	result := firstResult.Load()
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		writeTerminalStatus(jobDir, jobrunner.StateCancelled, result, nil)
	case result != nil:
		if err := saveResultAndReports(jobDir, result, cfg); err != nil {
			writeTerminalStatus(jobDir, jobrunner.StateFailed, result, err)
			return err
		}
		writeTerminalStatus(jobDir, jobrunner.StateDone, result, nil)
	default:
		writeTerminalStatus(jobDir, jobrunner.StateFailed, nil, errors.New("scan ended without result"))
	}
	return nil
}

// runStatusAndCollect drains progressCh, mirrors progress to status.json,
// and stores the first Result into dst for later report generation.
func runStatusAndCollect(ctx context.Context, jobDir string, progressCh <-chan scanner.Progress, dst *atomic.Pointer[model.ScanResult]) {
	ticker := time.NewTicker(statusWriteInterval)
	defer ticker.Stop()
	current, err := jobrunner.ReadStatus(jobDir)
	if err != nil {
		current = jobrunner.InitialStatus("unknown", 0, "", "", "")
	}
	flush := func() {
		current.RSSMB = currentRSSMB()
		_ = jobrunner.WriteStatusAtomic(jobDir, current)
	}
	for {
		select {
		case p, ok := <-progressCh:
			if !ok {
				flush()
				return
			}
			applyProgress(current, p)
			if p.Result != nil && dst.Load() == nil {
				dst.Store(p.Result)
			}
			fmt.Printf("[%3.0f%%] %s\n", p.Percent*100, p.Status)
			if p.Complete {
				flush()
				return
			}
			flush()
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
}

// writeTerminalStatus is a convenience that reads current status, marks
// it terminal, and writes it back.
func writeTerminalStatus(jobDir string, state jobrunner.State, result *model.ScanResult, err error) {
	s, readErr := jobrunner.ReadStatus(jobDir)
	if readErr != nil {
		s = jobrunner.InitialStatus("unknown", 0, "", "", "")
	}
	if result != nil {
		s.FindingsCount = len(result.Findings)
	}
	s.MarkTerminal(state, err)
	_ = jobrunner.WriteStatusAtomic(jobDir, s)
}

func writeTerminalFailure(jobDir string, err error) {
	writeTerminalStatus(jobDir, jobrunner.StateFailed, nil, err)
}

// buildScanConfigForCmd wraps the existing scannerconfig.BuildConfig with
// the full set of package-level flag variables so both runScan and
// runScanDaemon share the same config path. Any flag handled in the
// foreground runScan in cmd/root.go must also be applied here; otherwise
// detached scans will silently drop that configuration.
func buildScanConfigForCmd(cmd *cobra.Command) (*scannerconfig.Config, error) {
	cfg, err := scannerconfig.BuildConfig(scannerconfig.BuildOptions{
		Profile:       scanProfile,
		Modules:       modules,
		ImageRefs:     imageRefs,
		Kubeconfig:    kubeconfigPath,
		K8sContext:    k8sContext,
		K8sNamespace:  k8sNamespace,
		RegistryAuth:  registryAuth,
		DBUrl:         dbPath,
		Metrics:       showMetrics,
		Incremental:   incremental,
		OIDCEndpoints: oidcEndpoints,
		DNSSECZones:   dnssecZones,
	})
	if err != nil {
		return nil, err
	}

	// Apply eBPF trace flag overrides (same clamping as runScan).
	if v, err := cmd.Flags().GetDuration("ebpf-window"); err == nil && v > 0 {
		if v < time.Second {
			v = time.Second
		}
		if v > 30*time.Minute {
			v = 30 * time.Minute
		}
		cfg.EBPFWindow = v
	}
	if v, err := cmd.Flags().GetBool("ebpf-skip-uprobes"); err == nil {
		cfg.EBPFSkipUprobes = v
	}
	if v, err := cmd.Flags().GetBool("ebpf-skip-kprobes"); err == nil {
		cfg.EBPFSkipKprobes = v
	}

	// Apply pcap / TLS observer flag overrides.
	if v, _ := cmd.Flags().GetString("pcap-file"); v != "" {
		cfg.PcapFile = v
		cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
			Type: model.TargetPcap, Value: v,
		})
	}
	if v, _ := cmd.Flags().GetString("pcap-interface"); v != "" {
		cfg.PcapInterface = v
		cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
			Type: model.TargetPcap, Value: "iface:" + v,
		})
	}
	if v, err := cmd.Flags().GetDuration("pcap-window"); err == nil && v > 0 {
		if v < time.Second {
			v = time.Second
		}
		if v > 5*time.Minute {
			v = 5 * time.Minute
		}
		cfg.PcapWindow = v
	}
	if v, _ := cmd.Flags().GetString("pcap-filter"); v != "" {
		cfg.PcapFilter = v
	}

	// Keystore passwords: CLI flag -> env var -> empty (built-in defaults only).
	if len(keystorePasswords) > 0 {
		cfg.KeystorePasswords = keystorePasswords
	} else if envPW := os.Getenv("TRITON_KEYSTORE_PASSWORDS"); envPW != "" {
		cfg.KeystorePasswords = strings.Split(envPW, ",")
	}

	if cfg.DBUrl == "" {
		cfg.DBUrl = scannerconfig.DefaultDBUrl()
	}

	// Apply licence-based config filtering (restricts modules for free tier).
	// Must run after all flag overrides so the filter sees the final module set.
	guard.FilterConfig(cfg)
	return cfg, nil
}

// enforceScanLicense applies the licence-tier restrictions used by both the
// foreground runScan path and the detached runScanDetached path. It must
// run before buildScanConfigForCmd so any profile downgrade is reflected
// in the resulting config. This is the single source of truth for which
// features require which tier; runScan should call this helper rather than
// inline the checks to prevent the two paths from drifting.
func enforceScanLicense(cmd *cobra.Command) error {
	if cmd.Flags().Changed("profile") {
		if err := guard.EnforceProfile(scanProfile); err != nil {
			return err
		}
	} else {
		allowed := license.AllowedProfiles(guard.Tier())
		if len(allowed) > 0 {
			scanProfile = allowed[len(allowed)-1]
		}
	}
	if cmd.Flags().Changed("format") {
		if err := guard.EnforceFormat(format); err != nil {
			return err
		}
	} else if err := guard.EnforceFormat(format); err != nil {
		format = "json"
	}
	if showMetrics {
		if err := guard.EnforceFeature(license.FeatureMetrics); err != nil {
			return err
		}
	}
	if incremental {
		if err := guard.EnforceFeature(license.FeatureIncremental); err != nil {
			return err
		}
	}
	if dbPath != "" {
		if err := guard.EnforceFeature(license.FeatureDB); err != nil {
			return err
		}
	}
	if scanPolicyArg != "" {
		f := license.FeaturePolicyBuiltin
		if _, err := policy.LoadBuiltin(scanPolicyArg); err != nil {
			f = license.FeaturePolicyCustom
		}
		if err := guard.EnforceFeature(f); err != nil {
			return err
		}
	}
	return nil
}

// buildLimitsForCmd wraps cmd/root.go's buildLimits by reading flag values
// from the command.
func buildLimitsForCmd(cmd *cobra.Command) (limits.Limits, error) {
	maxMem, _ := cmd.Flags().GetString("max-memory")
	maxCPU, _ := cmd.Flags().GetString("max-cpu-percent")
	maxDur, _ := cmd.Flags().GetDuration("max-duration")
	stopAt, _ := cmd.Flags().GetString("stop-at")
	niceVal, _ := cmd.Flags().GetInt("nice")
	return buildLimits(maxMem, maxCPU, maxDur, stopAt, niceVal)
}

// saveResultAndReports writes result.json and generates configured
// report formats into jobDir/reports/ using the existing report.Generator.
// Honours the package-level `format` variable (set by --format flag):
//   - "json": only result.json (no reports/)
//   - "cdx"/"html"/"sarif"/"xlsx": only that one format
//   - "all": all five formats
func saveResultAndReports(jobDir string, result *model.ScanResult, _ *scannerconfig.Config) error {
	if err := jobrunner.WriteJSON(filepath.Join(jobDir, "result.json"), result); err != nil {
		return fmt.Errorf("write result.json: %w", err)
	}

	reportsDir := filepath.Join(jobDir, "reports")
	if err := os.MkdirAll(reportsDir, 0o700); err != nil {
		return fmt.Errorf("create reports dir: %w", err)
	}

	ts := result.Metadata.Timestamp.Format("2006-01-02T15-04-05")
	gen := report.New(reportsDir)

	writers := map[string]func() error{
		"json": func() error {
			return gen.GenerateTritonJSON(result, filepath.Join(reportsDir, "triton-report-"+ts+".json"))
		},
		"cdx": func() error {
			return gen.GenerateCycloneDXBOM(result, filepath.Join(reportsDir, "triton-report-"+ts+".cdx.json"))
		},
		"html": func() error {
			return gen.GenerateHTML(result, filepath.Join(reportsDir, "triton-report-"+ts+".html"))
		},
		"sarif": func() error {
			return gen.GenerateSARIF(result, filepath.Join(reportsDir, "triton-report-"+ts+".sarif"))
		},
		"xlsx": func() error {
			return gen.GenerateExcel(result, filepath.Join(reportsDir, "triton-report-"+ts+".xlsx"))
		},
	}

	var formats []string
	switch format {
	case "all":
		formats = []string{"json", "cdx", "html", "sarif", "xlsx"}
	case "":
		// no-op: result.json only
	default:
		formats = []string{format}
	}

	for _, f := range formats {
		if w, ok := writers[f]; ok {
			if err := w(); err != nil {
				return fmt.Errorf("generate %s: %w", f, err)
			}
		}
	}
	return nil
}

// runScanDetached is the parent-side entry point for `triton scan --detach`.
// Generates a job-id, creates the work-dir, snapshots the scan config,
// spawns a detached child via jobrunner.Spawn, writes the initial status,
// and prints the job-id to stdout. Returns immediately after fork.
func runScanDetached(cmd *cobra.Command, _ []string) error {
	// D3: enforce licence tier BEFORE dispatching to the daemon. Without
	// this, a free-tier user could bypass profile/format/feature gating
	// by passing --detach. enforceScanLicense also downgrades defaults,
	// so buildScanConfigForCmd below observes the restricted profile.
	if err := enforceScanLicense(cmd); err != nil {
		return err
	}

	jobID := detachJobID
	if jobID == "" {
		jobID = uuid.NewString()
	}
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)

	existing := jobrunner.JobDir(workDir, jobID)
	if _, err := os.Stat(existing); err == nil {
		return fmt.Errorf("job %s already exists at %s; use --cleanup first", jobID, existing)
	}

	jobDir, err := jobrunner.EnsureJobDir(workDir, jobID)
	if err != nil {
		return fmt.Errorf("create job dir: %w", err)
	}

	cfg, err := buildScanConfigForCmd(cmd)
	if err != nil {
		_ = os.RemoveAll(jobDir)
		return fmt.Errorf("build scan config: %w", err)
	}
	_ = jobrunner.WriteJSON(filepath.Join(jobDir, "config.json"), cfg)

	lim, err := buildLimitsForCmd(cmd)
	if err != nil {
		_ = os.RemoveAll(jobDir)
		return err
	}

	host, _ := os.Hostname()
	initial := jobrunner.InitialStatus(jobID, 0, scanProfile, versionString(), lim.String())
	initial.Host = host
	_ = jobrunner.WriteStatusAtomic(jobDir, initial)

	childArgs := rebuildArgsWithoutDetach(os.Args[1:])
	pid, err := jobrunner.Spawn(jobrunner.SpawnConfig{
		Executable: os.Args[0],
		Args:       childArgs,
		Env: []string{
			"TRITON_DETACHED=1",
			"TRITON_JOB_ID=" + jobID,
			"TRITON_WORK_DIR=" + workDir,
		},
		JobDir: jobDir,
	})
	if err != nil {
		_ = os.RemoveAll(jobDir)
		return fmt.Errorf("spawn daemon: %w", err)
	}

	if s, rerr := jobrunner.ReadStatus(jobDir); rerr == nil {
		s.PID = pid
		_ = jobrunner.WriteStatusAtomic(jobDir, s)
	}

	// --output-dir has no effect in detached mode: reports land in the
	// job's work-dir/reports/ and are retrieved via --collect. Warn the
	// user explicitly so the silent drop doesn't surprise them.
	if outputDir != "" && outputDir != "." {
		fmt.Fprintf(os.Stderr,
			"warning: --output-dir is ignored with --detach; reports will be in %s/reports. Use 'triton scan --collect --job-id %s' to retrieve.\n",
			jobDir, jobID)
	}

	if detachQuiet {
		fmt.Println(jobID)
	} else {
		fmt.Printf("Detached as job %s\npid %d, work-dir %s\n", jobID, pid, jobDir)
	}
	return nil
}

// rebuildArgsWithoutDetach returns args with `--detach` removed so the
// child process does not recursively detach.
func rebuildArgsWithoutDetach(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--detach" {
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// versionString returns the build-time version. Wraps the internal/version
// import to localise it.
func versionString() string {
	return version.Version
}

// --- runJobStatus ---

func runJobStatus(cmd *cobra.Command, _ []string) error {
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)
	jsonOut, _ := cmd.Flags().GetBool("json")
	return runJobStatusCore(workDir, detachJobID, jsonOut)
}

func runJobStatusCore(workDir, jobID string, jsonOut bool) error {
	if jobID == "" {
		return errors.New("--job-id required")
	}
	jobDir := jobrunner.JobDir(workDir, jobID)
	s, _, err := jobrunner.Reconcile(jobDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("job %s not found at %s", jobID, jobDir)
		}
		return err
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}
	fmt.Printf("job_id:         %s\n", s.JobID)
	fmt.Printf("state:          %s\n", s.State)
	fmt.Printf("pid:            %d\n", s.PID)
	fmt.Printf("started_at:     %s\n", s.StartedAt.Format(time.RFC3339))
	fmt.Printf("updated_at:     %s\n", s.UpdatedAt.Format(time.RFC3339))
	fmt.Printf("progress:       %.1f%%\n", s.ProgressPct)
	fmt.Printf("current_module: %s\n", s.CurrentModule)
	fmt.Printf("findings:       %d\n", s.FindingsCount)
	fmt.Printf("rss_mb:         %d\n", s.RSSMB)
	fmt.Printf("limits:         %s\n", s.Limits)
	if s.Error != "" {
		fmt.Printf("error:          %s\n", s.Error)
	}
	return nil
}

// --- runJobCollect ---

func runJobCollect(cmd *cobra.Command, _ []string) error {
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)
	out, _ := cmd.Flags().GetString("output")
	keep, _ := cmd.Flags().GetBool("keep")
	return runJobCollectCore(workDir, detachJobID, out, format, keep, jobrunner.IsProcessAlive)
}

func runJobCollectCore(workDir, jobID, outputPath, fmtName string, keep bool, pidAlive func(int) bool) error {
	if jobID == "" {
		return errors.New("--job-id required")
	}
	jobDir := jobrunner.JobDir(workDir, jobID)
	s, err := jobrunner.ReadStatus(jobDir)
	if err != nil {
		return fmt.Errorf("read status: %w", err)
	}
	if !s.State.IsTerminal() && s.PID > 0 && pidAlive(s.PID) {
		return fmt.Errorf("job %s is running (pid %d); cancel first or wait", jobID, s.PID)
	}

	switch fmtName {
	case "json":
		return writeCollectedFile(filepath.Join(jobDir, "result.json"), outputPath, keep, jobDir)
	case "", "tar", "all":
		return writeCollectedTar(filepath.Join(jobDir, "reports"), outputPath, keep, jobDir)
	default:
		matches, _ := filepath.Glob(filepath.Join(jobDir, "reports", "*."+fmtName))
		if len(matches) == 0 {
			return fmt.Errorf("no %s report found in %s/reports", fmtName, jobDir)
		}
		return writeCollectedFile(matches[0], outputPath, keep, jobDir)
	}
}

func writeCollectedFile(src, out string, keep bool, jobDir string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	var w io.Writer
	if out == "" || out == "-" {
		w = os.Stdout
	} else {
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if _, err := io.Copy(w, in); err != nil {
		return err
	}
	if !keep {
		return os.RemoveAll(jobDir)
	}
	return nil
}

func writeCollectedTar(reportsDir, out string, keep bool, jobDir string) error {
	// D5: write via a tempfile and rename on success so a walk failure
	// never leaves a corrupt/zero-byte .tar.gz on disk.
	var w io.Writer
	var tmpFile *os.File
	var tmpPath string
	if out == "" || out == "-" {
		w = os.Stdout
	} else {
		dir := filepath.Dir(out)
		tmp, err := os.CreateTemp(dir, "."+filepath.Base(out)+".tmp-*")
		if err != nil {
			return err
		}
		tmpFile = tmp
		tmpPath = tmp.Name()
		w = tmp
	}
	defer func() {
		// If tmpPath is non-empty here, rename did not succeed; clean up.
		if tmpPath != "" {
			if tmpFile != nil {
				_ = tmpFile.Close()
			}
			_ = os.Remove(tmpPath)
		}
	}()

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	walkErr := filepath.Walk(reportsDir, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(reportsDir, path)
		// D6: surface tar.FileInfoHeader errors (symlinks, ownership
		// lookup failures) instead of silently writing a zero-value
		// header that would panic on WriteHeader.
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = io.Copy(tw, f)
		return err
	})

	// Close writers in reverse order so the gzip trailer lands before
	// we commit the tempfile. Preserve the first error encountered.
	err := walkErr
	if cerr := tw.Close(); err == nil {
		err = cerr
	}
	if cerr := gz.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}

	if tmpPath != "" {
		if cerr := tmpFile.Close(); cerr != nil {
			return cerr
		}
		if err := os.Rename(tmpPath, out); err != nil {
			return err
		}
		tmpPath = "" // prevent the deferred cleanup from removing the output
	}
	if !keep {
		return os.RemoveAll(jobDir)
	}
	return nil
}

// --- runJobCancel ---

func runJobCancel(cmd *cobra.Command, _ []string) error {
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)
	wait, _ := cmd.Flags().GetBool("wait")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	return runJobCancelCore(workDir, detachJobID, wait, timeout)
}

func runJobCancelCore(workDir, jobID string, wait bool, timeout time.Duration) error {
	if jobID == "" {
		return errors.New("--job-id required")
	}
	jobDir := jobrunner.JobDir(workDir, jobID)
	if _, err := os.Stat(jobDir); os.IsNotExist(err) {
		return fmt.Errorf("job %s not found", jobID)
	}
	if err := jobrunner.TouchCancelFlag(jobDir); err != nil {
		return fmt.Errorf("touch cancel.flag: %w", err)
	}
	fmt.Printf("cancel requested for %s\n", jobID)

	if !wait {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s, err := jobrunner.ReadStatus(jobDir)
		if err == nil && s.State.IsTerminal() {
			fmt.Printf("job %s reached terminal state: %s\n", jobID, s.State)
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("job %s did not terminate within %s (cancel still pending)", jobID, timeout)
}

// --- runJobList ---

func runJobList(cmd *cobra.Command, _ []string) error {
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)
	jsonOut, _ := cmd.Flags().GetBool("json")
	return runJobListCore(workDir, jsonOut)
}

func runJobListCore(workDir string, jsonOut bool) error {
	jobs, err := jobrunner.List(workDir)
	if err != nil {
		return err
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(jobs)
	}
	if len(jobs) == 0 {
		fmt.Println("no jobs found")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "JOB ID\tSTATE\tSTARTED\tPROGRESS\tFINDINGS")
	for _, j := range jobs {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%.1f%%\t%d\n",
			j.JobID, j.Status.State,
			j.Status.StartedAt.Format("2006-01-02 15:04:05"),
			j.Status.ProgressPct, j.Status.FindingsCount)
	}
	return tw.Flush()
}

// --- runJobCleanup ---

func runJobCleanup(cmd *cobra.Command, _ []string) error {
	workDir := jobrunner.ResolveWorkDir(detachWorkDir)
	all, _ := cmd.Flags().GetBool("all")
	return runJobCleanupCore(workDir, detachJobID, all)
}

func runJobCleanupCore(workDir, jobID string, all bool) error {
	if all {
		n, err := jobrunner.RemoveAll(workDir)
		if err != nil {
			return err
		}
		fmt.Printf("removed %d finished jobs\n", n)
		return nil
	}
	if jobID == "" {
		return errors.New("--job-id or --all required")
	}
	if err := jobrunner.Remove(workDir, jobID); err != nil {
		return err
	}
	fmt.Printf("removed job %s\n", jobID)
	return nil
}
