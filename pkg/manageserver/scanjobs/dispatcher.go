// pkg/manageserver/scanjobs/dispatcher.go
package scanjobs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	gopsutilcpu "github.com/shirou/gopsutil/v4/cpu"
	gopsutilmem "github.com/shirou/gopsutil/v4/mem"
)

// DispatcherConfig holds the knobs for the generic job-type→binary spawner.
// Zero values receive sane defaults in NewDispatcher.
type DispatcherConfig struct {
	// Store is the job queue backing store. Required.
	Store Store

	// BinaryPath is the absolute path to the triton-portscan binary (or any
	// binary) that should be spawned for each queued port_survey job.
	BinaryPath string

	// ManageURL is the base URL of the Manage Server, forwarded to the spawned
	// binary via --manage-url.
	ManageURL string

	// WorkerKey is the X-Worker-Key secret, forwarded via the
	// TRITON_WORKER_KEY environment variable (not a CLI flag, to keep
	// it out of ps aux).
	WorkerKey string

	// Concurrency is the maximum number of simultaneous subprocesses.
	// 0 means "call ComputeCaps and use the result".
	Concurrency int

	// PollInterval controls how often the poll loop calls ListQueued.
	// Default: 5 s.
	PollInterval time.Duration
}

// Dispatcher polls the store for queued port_survey jobs and spawns the
// configured binary for each one, enforcing a concurrency cap.
// Call Run(ctx) to start; it blocks until ctx is cancelled.
type Dispatcher struct {
	cfg      DispatcherConfig
	workerID string
}

// NewDispatcher applies defaults and returns a ready Dispatcher.
func NewDispatcher(cfg DispatcherConfig) *Dispatcher {
	if cfg.Concurrency <= 0 {
		maxProcs, _ := ComputeCaps() // maxMemMB returned for callers to pass as subprocess flag; dispatcher enforces concurrency only
		cfg.Concurrency = maxProcs
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	host, _ := os.Hostname()
	return &Dispatcher{
		cfg:      cfg,
		workerID: fmt.Sprintf("dispatcher-%s", host),
	}
}

// Run blocks until ctx is cancelled. It polls ListQueued, spawns one subprocess
// per job (up to Concurrency), and on context cancellation sends SIGTERM to all
// running subprocesses and waits for them to exit.
func (d *Dispatcher) Run(ctx context.Context) {
	// sem limits the number of simultaneously running subprocesses.
	sem := make(chan struct{}, d.cfg.Concurrency)

	var wg sync.WaitGroup

	for {
		// Try to drain the semaphore slot before polling — if all slots are
		// taken we wait here until one is free or the context is cancelled.
		select {
		case sem <- struct{}{}:
			// Got a slot; release immediately if we don't find a job.
		case <-ctx.Done():
			wg.Wait()
			return
		}

		jobs, err := d.cfg.Store.ListQueued(ctx, []string{string(JobTypePortSurvey)}, 1)
		if err != nil {
			if ctx.Err() != nil {
				// Release the slot and exit.
				<-sem
				wg.Wait()
				return
			}
			log.Printf("dispatcher: ListQueued error: %v", err)
			<-sem
			select {
			case <-time.After(d.cfg.PollInterval):
			case <-ctx.Done():
				wg.Wait()
				return
			}
			continue
		}

		if len(jobs) == 0 {
			// No work right now — release the slot and wait before polling again.
			<-sem
			select {
			case <-time.After(d.cfg.PollInterval):
			case <-ctx.Done():
				wg.Wait()
				return
			}
			continue
		}

		// We have a job and a semaphore slot. Spawn the subprocess.
		j := jobs[0]
		wg.Add(1)
		go func(job Job) {
			defer wg.Done()
			defer func() { <-sem }() // release slot when subprocess exits

			d.spawnOne(ctx, job)
		}(j)

		// Immediately loop to check for more work (up to the cap).
	}
}

// spawnOne claims the job, spawns the binary for it, and waits for it to finish.
// On context cancellation it sends SIGTERM to the subprocess and waits.
func (d *Dispatcher) spawnOne(ctx context.Context, j Job) {
	// Claim the job before spawning to prevent duplicate spawns across poll
	// ticks or multiple dispatcher instances racing on the same job.
	if _, err := d.cfg.Store.ClaimByID(ctx, j.ID, d.workerID); err != nil {
		if !errors.Is(err, ErrAlreadyClaimed) {
			log.Printf("dispatcher: claim job %s: %v", j.ID, err)
		}
		return
	}

	args := []string{
		"--manage-url", d.cfg.ManageURL,
		"--job-id", j.ID.String(),
	}

	// Use a background context for the command so we can send SIGTERM
	// manually instead of having exec.CommandContext send SIGKILL immediately.
	cmd := exec.Command(d.cfg.BinaryPath, args...) //nolint:gosec // path is operator-supplied config
	// Pass secrets via environment variables rather than CLI flags to
	// keep them out of the process argv (visible to all users via ps aux).
	cmd.Env = append(os.Environ(),
		"TRITON_WORKER_KEY="+d.cfg.WorkerKey,
	)

	if err := cmd.Start(); err != nil {
		log.Printf("dispatcher: start job %s: %v", j.ID, err)
		if ferr := d.cfg.Store.Fail(context.Background(), j.ID, fmt.Sprintf("dispatcher: start binary: %v", err)); ferr != nil {
			log.Printf("dispatcher: revert claim on start failure %s: %v", j.ID, ferr)
		}
		return
	}

	// Wait for subprocess to exit or context to be cancelled.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err != nil {
			log.Printf("dispatcher: job %s exited with error: %v", j.ID, err)
			if ferr := d.cfg.Store.Fail(context.Background(), j.ID, fmt.Sprintf("subprocess: %v", err)); ferr != nil {
				log.Printf("dispatcher: mark job %s failed: %v", j.ID, ferr)
			}
		}
	case <-ctx.Done():
		// Graceful shutdown: send SIGTERM to the subprocess.
		if cmd.Process != nil {
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				log.Printf("dispatcher: SIGTERM job %s: %v", j.ID, err)
			}
		}
		// Wait for the process to actually exit. On graceful shutdown we do
		// not mark the job failed — the stale-job reaper will revert it.
		if err := <-done; err != nil {
			log.Printf("dispatcher: job %s after SIGTERM: %v", j.ID, err)
		}
	}
}

// ComputeCaps reads the host's CPU and memory availability and returns
// conservative limits suitable for use as a concurrency cap.
//
// Formula:
//
//	maxProcs  = max(1, physicalCores/2)
//	maxMemMB  = (totalMem - usedMem) / 2 / (1024*1024)
//
// If gopsutil fails (unsupported OS, permission error, etc.) safe defaults
// of (2, 512) are returned.
func ComputeCaps() (maxProcs int, maxMemMB int64) {
	const defaultProcs = 2
	const defaultMemMB = 512

	counts, err := gopsutilcpu.Counts(true /* physical */)
	if err != nil || counts <= 0 {
		counts = defaultProcs * 2
	}
	maxProcs = max(1, counts/2)

	vm, err := gopsutilmem.VirtualMemory()
	if err != nil || vm.Total == 0 {
		return maxProcs, defaultMemMB
	}
	if vm.Used >= vm.Total {
		// Guard against uint64 underflow: on some Linux kernels with unusual
		// accounting, Used can equal or exceed Total, wrapping to a huge value.
		return maxProcs, defaultMemMB
	}
	available := vm.Total - vm.Used
	if available == 0 {
		// Edge case: machine is completely swapped / reporting bad stats.
		return maxProcs, defaultMemMB
	}
	maxMemMB = max(1, int64(available)/2/(1024*1024))
	return maxProcs, maxMemMB
}
