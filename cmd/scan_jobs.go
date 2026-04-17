package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
	"github.com/amiryahaya/triton/internal/runtime/limits"
	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/report"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/store"
)

// statusWriteInterval is the periodic tick for rewriting status.json when
// no progress event has arrived. 2 seconds balances freshness and I/O.
const statusWriteInterval = 2 * time.Second

// writeStatusLoop drains progressCh, updating status.json atomically on
// every progress event (bounded to statusWriteInterval by ticker if
// progress events are absent). Returns when progressCh closes or ctx ends.
//
// scanner.Progress does not carry a dedicated Module field today; the
// Status string is the module/phase label that the engine emits (e.g.
// "certificate", "library"), so we use it as the source for
// Status.CurrentModule.
func writeStatusLoop(ctx context.Context, jobDir string, progressCh <-chan scanner.Progress) {
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
func runScanDaemon(cmd *cobra.Command, args []string) error {
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
// the package-level flag variables so both runScan and runScanDaemon share
// the same config path.
func buildScanConfigForCmd(cmd *cobra.Command) (*scannerconfig.Config, error) {
	return scannerconfig.BuildConfig(scannerconfig.BuildOptions{
		Profile: scanProfile,
		Modules: modules,
	})
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
func saveResultAndReports(jobDir string, result *model.ScanResult, cfg *scannerconfig.Config) error {
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
