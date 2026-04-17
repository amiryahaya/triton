package cmd

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/jobrunner"
	"github.com/amiryahaya/triton/pkg/scanner"
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
