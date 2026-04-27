package scanjobs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// ResultEnqueuer is the downstream sink for completed scan results.
// Batch E's scanresults package satisfies this interface; this package
// declares it locally to avoid an import cycle and to keep the
// orchestrator testable without pulling in Postgres-backed collaborators.
type ResultEnqueuer interface {
	Enqueue(ctx context.Context, scanJobID uuid.UUID, sourceType string, sourceID uuid.UUID, scan *model.ScanResult) error
}

// ScanFunc is the pluggable scanner entry point. The default
// implementation lives in scan_runner.go and bridges into
// pkg/scanner.Engine; tests swap this out for deterministic stubs.
type ScanFunc func(ctx context.Context, j Job) (*model.ScanResult, error)

// OrchestratorConfig captures the knobs the Manage server's Run loop
// needs to configure a worker pool. Zero values get sane defaults;
// tests commonly override Parallelism, HeartbeatInterval and
// PollInterval to keep wall-clock runtime bounded.
type OrchestratorConfig struct {
	Store       Store
	ResultStore ResultEnqueuer

	// Parallelism is the worker-goroutine count. Capped at 50 to
	// keep a misconfigured production deploy from opening thousands
	// of Postgres connections.
	Parallelism int

	// ScanFunc is the scanner invocation. nil → defaultScanFunc,
	// which returns an error; production wiring must either supply
	// a ScanFunc or use NewScanFunc() from scan_runner.go.
	ScanFunc ScanFunc

	// ReapAfter controls the stale-heartbeat threshold the reaper
	// passes to Store.ReapStale. Default 5 minutes.
	ReapAfter time.Duration

	// HeartbeatInterval is how often the per-job heartbeat loop
	// refreshes running_heartbeat_at and checks cancel_requested.
	// Default 60 s; tests override to accelerate cancellation.
	HeartbeatInterval time.Duration

	// PollInterval is how long workerLoop sleeps after an empty
	// ClaimNext before retrying. Default 2 s.
	PollInterval time.Duration

	// SourceID is the Manage instance's uuid, stamped into every
	// result row so downstream pushers know which installation
	// produced the scan.
	SourceID uuid.UUID
}

// Orchestrator runs a bounded pool of scan workers + a reaper loop.
// It's constructed once at server startup and Run blocks until the
// supplied context is cancelled.
type Orchestrator struct {
	cfg OrchestratorConfig
}

// NewOrchestrator applies defaults and returns an Orchestrator.
// Parallelism is clamped to [1, 50]; negative or zero means "use 10".
//
// Misconfigured ResultStore is fail-loud, not fail-silent: a nil value
// would otherwise cause the orchestrator to complete jobs with no
// downstream persistence and the operator would have no signal. The
// fallback enqueuer returns an explicit error which runOneJob maps to
// Store.Fail, so the job ends up in `failed` state with a readable
// error_message that points at the missing collaborator.
func NewOrchestrator(cfg OrchestratorConfig) *Orchestrator {
	if cfg.Parallelism <= 0 {
		cfg.Parallelism = 10
	}
	if cfg.Parallelism > 50 {
		cfg.Parallelism = 50
	}
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 60 * time.Second
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 2 * time.Second
	}
	if cfg.ReapAfter == 0 {
		cfg.ReapAfter = 5 * time.Minute
	}
	if cfg.ScanFunc == nil {
		cfg.ScanFunc = defaultScanFunc
	}
	if cfg.ResultStore == nil {
		log.Printf("orchestrator: WARNING: ResultStore is nil — scan results will surface as job failures")
		cfg.ResultStore = noopResultEnqueuer{}
	}
	return &Orchestrator{cfg: cfg}
}

// noopResultEnqueuer is the fallback ResultStore installed by
// NewOrchestrator when the operator forgot to wire a real one. It
// returns an explicit error from Enqueue so runOneJob's failure branch
// fires and the job surfaces in the admin UI with a readable message.
// Never fail-silent on a misconfiguration that would otherwise drop
// scan results.
type noopResultEnqueuer struct{}

func (noopResultEnqueuer) Enqueue(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID, _ *model.ScanResult) error {
	return errors.New("ResultStore not configured on orchestrator")
}

// Run spawns N worker goroutines + one reaper goroutine and blocks
// until the context is cancelled. When ctx.Done fires, workers exit
// after their current job (or their next poll tick), and Run waits
// for every goroutine to return before itself returning.
func (o *Orchestrator) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < o.cfg.Parallelism; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			o.workerLoop(ctx, workerID(idx))
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.reaperLoop(ctx)
	}()
	wg.Wait()
}

// workerID builds a stable per-worker identifier of the form
// hostname:pid:index. Lands in manage_scan_jobs.worker_id for audit.
func workerID(i int) string {
	hn, _ := os.Hostname()
	return fmt.Sprintf("%s:%d:%d", hn, os.Getpid(), i)
}

// workerLoop is the per-worker mainline: claim a job, run it, repeat
// until the context is cancelled. Empty queue triggers a PollInterval
// sleep; claim errors are logged and also back off via PollInterval.
//
// runOneJob is wrapped in an IIFE with a deferred recover() so that a
// panic inside ScanFunc (nil deref in a scanner module, out-of-bounds,
// etc.) does NOT kill the worker goroutine. The panicking job is marked
// failed with "internal panic: ..." and the loop continues; otherwise
// the pool would silently shrink and the panicking row would sit in
// `running` until the reaper noticed it minutes later.
func (o *Orchestrator) workerLoop(ctx context.Context, wid string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		j, ok, err := o.cfg.Store.ClaimNext(ctx, wid)
		if err != nil {
			// Log but keep the loop alive: transient DB errors
			// must not kill a worker permanently.
			if !errors.Is(err, context.Canceled) {
				log.Printf("orchestrator: claim error: %v", err)
			}
			select {
			case <-time.After(o.cfg.PollInterval):
			case <-ctx.Done():
				return
			}
			continue
		}
		if !ok {
			select {
			case <-time.After(o.cfg.PollInterval):
			case <-ctx.Done():
				return
			}
			continue
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("orchestrator: panic in job %s: %v", j.ID, r)
					// Use a fresh context so we can still write
					// the terminal state even if the parent ctx
					// was the thing that was cancelled.
					if ferr := o.cfg.Store.Fail(context.Background(), j.ID,
						fmt.Sprintf("internal panic: %v", r)); ferr != nil {
						log.Printf("orchestrator: fail-after-panic write failed: %v", ferr)
					}
				}
			}()
			o.runOneJob(ctx, j)
		}()
	}
}

// runOneJob executes a single claimed job: starts the heartbeat +
// cancel watcher in a helper goroutine, invokes the scan func, and
// writes the appropriate terminal state.
//
// Error / cancellation decision tree after ScanFunc returns:
//
//   - If the parent context is already cancelled, we're shutting down;
//     don't write anything — the reaper will eventually revive the row
//     if this process crashed, or another worker picks it up.
//   - If jobCtx is cancelled but parent is live, the heartbeat watcher
//     tugged on cancelJob because an admin flipped cancel_requested.
//     Write Cancel terminally.
//   - If ScanFunc returned an error (non-ctx), Fail with err.Error().
//   - Otherwise enqueue the result and Complete.
func (o *Orchestrator) runOneJob(parent context.Context, j Job) {
	jobCtx, cancelJob := context.WithCancel(parent)
	defer cancelJob()

	hbDone := make(chan struct{})
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		t := time.NewTicker(o.cfg.HeartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-hbDone:
				return
			case <-jobCtx.Done():
				return
			case <-t.C:
				// Heartbeat uses parent so a cancelled
				// jobCtx doesn't kill the write itself; the
				// whole watcher exits as soon as jobCtx is
				// cancelled (via the select branch above),
				// before the next tick anyway.
				_ = o.cfg.Store.Heartbeat(parent, j.ID, j.ProgressText)
				if req, err := o.cfg.Store.IsCancelRequested(parent, j.ID); err == nil && req {
					cancelJob()
					return
				}
			}
		}
	}()

	// Select scanner based on job type.
	scanFn := o.cfg.ScanFunc
	if scanFn == nil {
		scanFn = defaultScanFunc
	}
	scan, scanErr := scanFn(jobCtx, j)
	close(hbDone)
	hbWG.Wait()

	// Shutdown propagates from parent.Done → jobCtx.Done. Skip
	// terminal writes; the reaper and a subsequent server start
	// handle recovery.
	if parent.Err() != nil {
		return
	}

	// jobCtx cancelled but parent alive ⇒ cancel-on-request path.
	if jobCtx.Err() != nil {
		if err := o.cfg.Store.Cancel(parent, j.ID); err != nil {
			log.Printf("orchestrator: cancel write failed: %v", err)
		}
		return
	}

	if scanErr != nil {
		if err := o.cfg.Store.Fail(parent, j.ID, scanErr.Error()); err != nil {
			log.Printf("orchestrator: fail write failed: %v", err)
		}
		return
	}

	// ResultStore is never nil here — NewOrchestrator installs a
	// noopResultEnqueuer fallback that errors loudly rather than
	// silently dropping results on the floor.
	if scan != nil {
		if err := o.cfg.ResultStore.Enqueue(parent, j.ID, "manage", o.cfg.SourceID, scan); err != nil {
			// Result enqueue failure ⇒ mark the job failed so
			// the operator sees the error surface.
			if ferr := o.cfg.Store.Fail(parent, j.ID, "enqueue result: "+err.Error()); ferr != nil {
				log.Printf("orchestrator: fail-after-enqueue-error write failed: %v", ferr)
			}
			return
		}
	}

	if err := o.cfg.Store.Complete(parent, j.ID); err != nil {
		log.Printf("orchestrator: complete write failed: %v", err)
	}
}

// reaperLoop periodically walks the running set and reverts any job
// whose heartbeat is older than ReapAfter back to queued. The cadence
// is 1 minute — same as the default HeartbeatInterval, so a crashed
// worker is reclaimable within ~6 minutes worst case (5 min stale
// threshold + 1 min reaper tick).
func (o *Orchestrator) reaperLoop(ctx context.Context) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := o.cfg.Store.ReapStale(ctx, o.cfg.ReapAfter)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Printf("orchestrator: reap error: %v", err)
				}
				continue
			}
			if n > 0 {
				log.Printf("orchestrator: reaped %d stale jobs", n)
			}
		}
	}
}

// defaultScanFunc is the zero-configuration stub returned by
// NewOrchestrator when the caller forgot to wire a ScanFunc. It's
// deliberately an error so the mistake is visible at first run rather
// than silently skipping jobs.
func defaultScanFunc(_ context.Context, _ Job) (*model.ScanResult, error) {
	return nil, errors.New("orchestrator: no ScanFunc configured (use NewScanFunc or supply one explicitly)")
}
