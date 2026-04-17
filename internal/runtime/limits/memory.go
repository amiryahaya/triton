package limits

import (
	"context"
	"os"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"
)

// defaultWatchdogInterval is how often the watchdog samples memory usage
// when the soft limit is set. 2 seconds is a reasonable balance: fast
// enough to catch runaway allocations, slow enough to not burn CPU.
const defaultWatchdogInterval = 2 * time.Second

// defaultHardMultiple is how far above the soft limit triggers self-kill.
// GOMEMLIMIT is a soft target; the GC tries hard to stay under. If we are
// 1.5x over despite that, the workload is fundamentally infeasible and we
// should bail rather than get OOM-killed.
const defaultHardMultiple = 1.5

// ApplyMemoryLimit installs a soft memory limit via
// runtime/debug.SetMemoryLimit. Zero or negative is a no-op.
func ApplyMemoryLimit(bytes int64) {
	if bytes <= 0 {
		return
	}
	debug.SetMemoryLimit(bytes)
}

// watchdogConfig bundles the knobs for watchdogLoop. Exposed for testing;
// production code uses StartMemoryWatchdog which wires the real sampler
// and kill hook.
type watchdogConfig struct {
	softLimit    int64
	hardMultiple float64
	sampleEvery  time.Duration
	sampleMemory func() uint64
	kill         func()
}

// watchdogLoop samples memory at sampleEvery and invokes kill() if usage
// exceeds softLimit*hardMultiple. Exits cleanly when ctx is cancelled.
// Called once by StartMemoryWatchdog; exported at package level only for tests.
func watchdogLoop(ctx context.Context, cfg watchdogConfig) {
	if cfg.sampleEvery <= 0 {
		cfg.sampleEvery = defaultWatchdogInterval
	}
	hardCap := uint64(float64(cfg.softLimit) * cfg.hardMultiple)
	t := time.NewTicker(cfg.sampleEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if cfg.sampleMemory() > hardCap {
				cfg.kill()
				return // no point sampling further
			}
		}
	}
}

// StartMemoryWatchdog launches the watchdog goroutine if softLimit > 0.
// Returns a cleanup func the caller must defer.
func StartMemoryWatchdog(ctx context.Context, softLimit int64) func() {
	if softLimit <= 0 {
		return func() {}
	}
	wdCtx, cancel := context.WithCancel(ctx)
	cfg := watchdogConfig{
		softLimit:    softLimit,
		hardMultiple: defaultHardMultiple,
		sampleEvery:  defaultWatchdogInterval,
		sampleMemory: sampleGoRuntimeMem,
		kill:         killSelf,
	}
	go watchdogLoop(wdCtx, cfg)
	return cancel
}

// sampleGoRuntimeMem returns runtime.MemStats.Sys — the total bytes of
// memory obtained from the OS by the Go runtime. For CGO_ENABLED=0 builds
// (triton's default) this is the closest portable proxy for RSS.
func sampleGoRuntimeMem() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys
}

// killSelf sends SIGKILL to the current process. On breach there is no
// point returning an error or running shutdown hooks: the runtime is
// already unhealthy.
func killSelf() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
}
