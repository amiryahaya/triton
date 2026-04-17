# Resource Limits Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add in-process resource limits (`--max-memory`, `--max-cpu-percent`, `--max-duration`, `--stop-at`, `--nice`) to the `triton scan` command so a single code path works identically for foreground runs, in-host agent scans, and SSH-agentless orchestration.

**Architecture:** A new `internal/runtime/limits` package exposes one public API: `Limits.Apply(ctx)` which returns a derived `context.Context` (with deadline if `--max-duration` or `--stop-at` set) and a cleanup `func()`. It installs `runtime/debug.SetMemoryLimit` for memory soft-limit, calls `runtime.GOMAXPROCS` for CPU throttle, calls `syscall.Setpriority` for nice (Unix-only), and launches a watchdog goroutine that samples `runtime.MemStats.Sys` every 2s and self-SIGKILLs if the process exceeds 1.5× the soft memory limit. The watchdog is belt-and-suspenders — GOMEMLIMIT alone handles the 99% case via aggressive GC. `runScan` / `runScanHeadless` in `cmd/root.go` call `Apply()` once before building the scan engine and pass the returned context into the scan pipeline.

**Tech Stack:** Go 1.25 stdlib only (`runtime/debug`, `syscall`, `time`, `context`, `os`). No new module dependencies. Cobra flags on the existing `rootCmd`.

**Design rationale (why this shape):**
- **One API for three delivery modes.** Same flags work foreground (`triton scan --max-memory 2GB`), agent-supervised (`agent.yaml → resource_limits:` → same flags internally), and SSH-detached (future `triton ssh-scan` orchestrator passes the same flags over SSH). No per-mode code.
- **In-process first, systemd-optional.** SSH-agentless has no systemd, so we cannot rely on `CPUQuota=`/`MemoryMax=` unit-file directives. An optional agent-side wrapper using `systemd-run --scope -p CPUQuota=...` can layer kernel enforcement on top when available — but is a future task, not this one.
- **Soft limits with a hard watchdog.** `SetMemoryLimit` is soft (GC pressure); the watchdog converts catastrophic breaches into a clean self-kill rather than OS OOM-kill. The agent supervisor (future task) will see exit code `137` (SIGKILL) and retry with reduced scope.
- **Peak-vs-current RSS tradeoff.** We use `runtime.MemStats.Sys` (go runtime's total memory footprint) rather than OS RSS. This is portable, requires no syscalls, and is accurate for `CGO_ENABLED=0` builds (triton's production binary). Documented as a caveat in the package doc.
- **`--stop-at` computes to a `time.Duration` at flag-parse time.** If both `--max-duration` and `--stop-at` are set, the tighter deadline wins. No surprises from TZ drift mid-scan.

---

## File Structure

**Create:**
- `internal/runtime/limits/limits.go` — public API: `Limits` struct, `Apply()`, `String()`
- `internal/runtime/limits/limits_test.go` — `Limits.Apply()` composition tests
- `internal/runtime/limits/parse.go` — `ParseSize`, `ParseStopAt`, `ParsePercent` helpers
- `internal/runtime/limits/parse_test.go` — table tests for each parser
- `internal/runtime/limits/memory.go` — `SetMemoryLimit` wrapper + watchdog goroutine
- `internal/runtime/limits/memory_test.go` — watchdog trigger test (skipped by default, behind build tag)
- `internal/runtime/limits/cpu.go` — `ApplyCPUPercent` via GOMAXPROCS
- `internal/runtime/limits/cpu_test.go`
- `internal/runtime/limits/nice_unix.go` — `//go:build unix`, calls `syscall.Setpriority`
- `internal/runtime/limits/nice_windows.go` — `//go:build windows`, no-op
- `internal/runtime/limits/nice_test.go` — unit test that does not require root
- `internal/runtime/limits/doc.go` — package doc with caveats

**Modify:**
- `cmd/root.go` — add 5 flag definitions in `init()`, call `limits.Apply()` in both `runScan` and `runScanHeadless`

**No changes to:** scanner engine, any module, the progress pipeline, report generation, store, server, agent, or any test outside `internal/runtime/limits`. The scan engine already respects `ctx.Done()` end-to-end (per CLAUDE.md), so a cancelled context propagates with no scanner-side code change.

---

## Scope Check

This plan covers **only step 1** of the 4-step roadmap ("Limits.Apply() + CLI flags" from `memory/agent-control-features.md`). Future plans will cover:
- Step 2: Job runner (`--detach` / `--status` / `--collect` / `--cancel` / `--list-jobs`)
- Step 3: `triton ssh-scan` orchestrator
- Step 4: Agent supervisor integration (`agent.yaml` + optional `systemd-run` wrapper)

Each subsequent plan reuses this plan's `Limits` struct and `Apply()` function verbatim. That's the point of building this foundation first.

---

## Testing Strategy Notes for the Implementer

**You will see a lot of table-driven tests.** That's the Go idiom — a slice of input/expected pairs, one `t.Run` per case. Trust the pattern; don't try to refactor each case into its own function. See `internal/license/license_test.go` for examples already in this repo.

**The watchdog test is hard to write without allocating multi-GB.** We test it indirectly: (a) the watchdog goroutine can be stopped cleanly via the returned cleanup func, (b) when `runtime.MemStats.Sys` exceeds the hard cap, a *hook function* (injectable in tests) is called. In production the hook is `syscall.Kill(os.Getpid(), syscall.SIGKILL)`; in tests we inject a counter. This is the one place we use a test seam — don't try to make production code more complex to avoid the seam.

**Race detector must pass.** The watchdog is a goroutine that reads memory state and can call a kill hook; the cleanup func signals it to stop. Use `sync/atomic` or a cancel context — not a shared bool. Tests run with `-race` by default in CI.

**Platform-specific files.** `nice_unix.go` has `//go:build unix` and compiles on Linux + Darwin + BSDs. `nice_windows.go` has `//go:build windows` and is a no-op (Windows doesn't have `setpriority`; there's a future task to map this to `SetPriorityClass` but not now — `--nice` on Windows silently does nothing, documented in the flag help text).

---

## Task 1: Bootstrap the `limits` package with the `Limits` struct

**Files:**
- Create: `internal/runtime/limits/limits.go`
- Create: `internal/runtime/limits/limits_test.go`
- Create: `internal/runtime/limits/doc.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/limits/limits_test.go`:

```go
package limits

import (
	"testing"
	"time"
)

func TestLimitsZeroValueIsDisabled(t *testing.T) {
	var l Limits
	if l.Enabled() {
		t.Errorf("zero-value Limits should report Enabled() == false")
	}
}

func TestLimitsEnabled(t *testing.T) {
	cases := []struct {
		name string
		l    Limits
		want bool
	}{
		{"empty", Limits{}, false},
		{"memory set", Limits{MaxMemoryBytes: 1 << 20}, true},
		{"cpu set", Limits{MaxCPUPercent: 50}, true},
		{"duration set", Limits{MaxDuration: time.Second}, true},
		{"stop-at set", Limits{StopAtOffset: time.Hour}, true},
		{"nice set", Limits{Nice: 10}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.l.Enabled(); got != tc.want {
				t.Errorf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLimitsString(t *testing.T) {
	l := Limits{
		MaxMemoryBytes: 2 * (1 << 30),
		MaxCPUPercent:  50,
		MaxDuration:    4 * time.Hour,
		Nice:           10,
	}
	got := l.String()
	// Just check all fields appear - don't pin format too tightly.
	for _, want := range []string{"memory=2147483648", "cpu=50%", "duration=4h0m0s", "nice=10"} {
		if !containsSubstr(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}

func containsSubstr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runtime/limits/... -v`
Expected: FAIL with "package internal/runtime/limits is not in GOROOT" or similar (package doesn't exist yet).

- [ ] **Step 3: Write minimal implementation**

Create `internal/runtime/limits/limits.go`:

```go
// Package limits provides in-process resource limits for triton scans.
//
// The Limits struct bundles memory, CPU, duration, and scheduling priority
// caps. A single Apply() call installs all configured limits and returns a
// context whose deadline matches MaxDuration/StopAtOffset (tightest wins) plus
// a cleanup function that must be deferred by the caller.
//
// All fields are optional. A zero-value Limits is a no-op; Enabled() returns
// false and Apply() returns the input context unchanged plus a no-op cleanup.
package limits

import (
	"fmt"
	"strings"
	"time"
)

// Limits bundles all in-process resource caps that Apply() installs.
// Zero values mean "no limit" for that dimension.
type Limits struct {
	// MaxMemoryBytes is the soft memory limit installed via
	// runtime/debug.SetMemoryLimit. A hard watchdog kills the process at
	// 1.5x this value. Zero disables both.
	MaxMemoryBytes int64

	// MaxCPUPercent caps GOMAXPROCS to max(1, NumCPU*pct/100). Values
	// outside (0,100] are ignored.
	MaxCPUPercent int

	// MaxDuration is the wall-clock budget for the scan. Translates to
	// context.WithTimeout on the context returned by Apply.
	MaxDuration time.Duration

	// StopAtOffset is an alternative expression of MaxDuration: computed
	// at flag-parse time from --stop-at HH:MM as "duration until that
	// clock time today (or tomorrow if already past)". If both are set,
	// the smaller of the two wins.
	StopAtOffset time.Duration

	// Nice is passed to syscall.Setpriority (unix only). Range is
	// typically [-20, 19]; higher = nicer = lower priority. Zero skips.
	Nice int
}

// Enabled reports whether any limit is configured.
func (l Limits) Enabled() bool {
	return l.MaxMemoryBytes > 0 ||
		l.MaxCPUPercent > 0 ||
		l.MaxDuration > 0 ||
		l.StopAtOffset > 0 ||
		l.Nice != 0
}

// String produces a single-line human summary for startup logs.
func (l Limits) String() string {
	if !l.Enabled() {
		return "limits=none"
	}
	parts := []string{"limits:"}
	if l.MaxMemoryBytes > 0 {
		parts = append(parts, fmt.Sprintf("memory=%d", l.MaxMemoryBytes))
	}
	if l.MaxCPUPercent > 0 {
		parts = append(parts, fmt.Sprintf("cpu=%d%%", l.MaxCPUPercent))
	}
	if d := l.effectiveDuration(); d > 0 {
		parts = append(parts, fmt.Sprintf("duration=%s", d))
	}
	if l.Nice != 0 {
		parts = append(parts, fmt.Sprintf("nice=%d", l.Nice))
	}
	return strings.Join(parts, " ")
}

// effectiveDuration returns the tighter of MaxDuration and StopAtOffset, or
// zero if neither is set.
func (l Limits) effectiveDuration() time.Duration {
	switch {
	case l.MaxDuration > 0 && l.StopAtOffset > 0:
		if l.MaxDuration < l.StopAtOffset {
			return l.MaxDuration
		}
		return l.StopAtOffset
	case l.MaxDuration > 0:
		return l.MaxDuration
	case l.StopAtOffset > 0:
		return l.StopAtOffset
	default:
		return 0
	}
}
```

Create `internal/runtime/limits/doc.go`:

```go
// Package limits implements in-process resource limits for triton.
//
// Caveats:
//
//   - MaxMemoryBytes uses runtime/debug.SetMemoryLimit which is a SOFT limit.
//     The GC works harder to stay under it but cannot guarantee. A watchdog
//     goroutine converts catastrophic breaches (>1.5x) into self-SIGKILL so
//     the process exits cleanly rather than being OOM-killed.
//
//   - The watchdog samples runtime.MemStats.Sys, which is the Go runtime's
//     memory footprint, not the kernel's RSS. For CGO_ENABLED=0 builds
//     (triton's default) these are within a few percent. CGO-enabled builds
//     with large C allocations are undercounted.
//
//   - MaxCPUPercent is enforced via GOMAXPROCS. This caps parallelism, not
//     CPU time. A single goroutine in a tight loop can still saturate one
//     core. For hard CPU quotas, use systemd-run or cgroups as a wrapper.
//
//   - Nice is best-effort. On systems with CAP_SYS_NICE restrictions, setting
//     a negative (higher-priority) nice value may silently fail without
//     returning an error on all platforms.
package limits
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/runtime/limits/... -v`
Expected: PASS (3 tests: TestLimitsZeroValueIsDisabled, TestLimitsEnabled with 6 subtests, TestLimitsString).

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/limits/
git commit -m "feat(limits): bootstrap Limits struct with Enabled/String"
```

---

## Task 2: Parse helpers (`ParseSize`, `ParsePercent`, `ParseStopAt`)

**Files:**
- Create: `internal/runtime/limits/parse.go`
- Create: `internal/runtime/limits/parse_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/limits/parse_test.go`:

```go
package limits

import (
	"testing"
	"time"
)

func TestParseSize(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"1024", 1024, false},
		{"1KB", 1 << 10, false},
		{"1MB", 1 << 20, false},
		{"1GB", 1 << 30, false},
		{"2GB", 2 << 30, false},
		{"512MB", 512 << 20, false},
		{"1kb", 1 << 10, false},
		{"1 GB", 1 << 30, false},
		{"  2MB  ", 2 << 20, false},
		{"1TB", 1 << 40, false},
		{"1.5GB", 0, true},   // fractional unsupported — keep it simple
		{"GB", 0, true},
		{"1ZB", 0, true},
		{"-1GB", 0, true},
		{"abc", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseSize(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseSize(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParsePercent(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"50", 50, false},
		{"100", 100, false},
		{"1", 1, false},
		{"101", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
		{"50%", 50, false},  // accept trailing % for human convenience
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParsePercent(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParsePercent(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("ParsePercent(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseStopAt(t *testing.T) {
	// Fixed reference time: 2026-04-17 14:00:00 UTC
	now := time.Date(2026, 4, 17, 14, 0, 0, 0, time.UTC)
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"15:00", 1 * time.Hour, false},                      // later today
		{"14:00", 24 * time.Hour, false},                     // exactly now → tomorrow
		{"13:00", 23 * time.Hour, false},                     // earlier → tomorrow
		{"23:59", 9*time.Hour + 59*time.Minute, false},       // late today
		{"00:00", 10 * time.Hour, false},                     // midnight → tomorrow
		{"25:00", 0, true},
		{"abc", 0, true},
		{"15", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseStopAt(tc.in, now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseStopAt(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("ParseStopAt(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runtime/limits/... -v -run Parse`
Expected: FAIL with "undefined: ParseSize" / "undefined: ParsePercent" / "undefined: ParseStopAt".

- [ ] **Step 3: Write minimal implementation**

Create `internal/runtime/limits/parse.go`:

```go
package limits

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseSize parses a size string like "2GB" into bytes. Supports KB/MB/GB/TB
// suffixes (case-insensitive, optional space). Bare integer is bytes. Empty
// string returns (0, nil). Fractional values are not supported.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	upper := strings.ToUpper(strings.ReplaceAll(s, " ", ""))

	var mult int64 = 1
	for _, suf := range []struct {
		unit string
		val  int64
	}{
		{"TB", 1 << 40},
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"KB", 1 << 10},
	} {
		if strings.HasSuffix(upper, suf.unit) {
			mult = suf.val
			upper = strings.TrimSuffix(upper, suf.unit)
			break
		}
	}
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid size %q: must be non-negative", s)
	}
	return n * mult, nil
}

// ParsePercent parses an integer in [0,100]. Accepts trailing "%" for human
// input. Empty string returns (0, nil).
func ParsePercent(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	s = strings.TrimSuffix(s, "%")
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid percent %q: %w", s, err)
	}
	if n < 0 || n > 100 {
		return 0, fmt.Errorf("invalid percent %q: must be in [0,100]", s)
	}
	return n, nil
}

// ParseStopAt parses a clock time "HH:MM" into a duration from `now` until
// that time today. If the time is at or before `now`, rolls over to tomorrow.
// Empty string returns (0, nil). Uses the local location of `now`.
func ParseStopAt(s string, now time.Time) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	t, err := time.ParseInLocation("15:04", s, now.Location())
	if err != nil {
		return 0, fmt.Errorf("invalid stop-at %q (expect HH:MM): %w", s, err)
	}
	target := time.Date(now.Year(), now.Month(), now.Day(),
		t.Hour(), t.Minute(), 0, 0, now.Location())
	if !target.After(now) {
		target = target.Add(24 * time.Hour)
	}
	return target.Sub(now), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/runtime/limits/... -v -run Parse`
Expected: PASS (3 tests, ~35 subtests total).

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/limits/parse.go internal/runtime/limits/parse_test.go
git commit -m "feat(limits): add ParseSize/ParsePercent/ParseStopAt helpers"
```

---

## Task 3: CPU limit via GOMAXPROCS

**Files:**
- Create: `internal/runtime/limits/cpu.go`
- Create: `internal/runtime/limits/cpu_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/limits/cpu_test.go`:

```go
package limits

import (
	"runtime"
	"testing"
)

func TestApplyCPUPercent(t *testing.T) {
	origProcs := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(origProcs) })

	numCPU := runtime.NumCPU()
	cases := []struct {
		name    string
		percent int
		want    int
	}{
		{"zero disables", 0, origProcs},      // no change
		{"100%", 100, numCPU},
		{"50%", 50, max(1, numCPU*50/100)},
		{"1%", 1, 1},                          // clamped to at least 1
		{"over-range ignored", 200, origProcs}, // no change, no panic
		{"negative ignored", -1, origProcs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GOMAXPROCS(origProcs) // reset
			ApplyCPUPercent(tc.percent)
			got := runtime.GOMAXPROCS(0)
			if got != tc.want {
				t.Errorf("ApplyCPUPercent(%d) → GOMAXPROCS=%d, want %d (numCPU=%d)",
					tc.percent, got, tc.want, numCPU)
			}
		})
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runtime/limits/... -v -run ApplyCPUPercent`
Expected: FAIL with "undefined: ApplyCPUPercent".

- [ ] **Step 3: Write minimal implementation**

Create `internal/runtime/limits/cpu.go`:

```go
package limits

import "runtime"

// ApplyCPUPercent caps GOMAXPROCS to max(1, NumCPU * pct / 100).
// Values outside (0,100] are a silent no-op.
func ApplyCPUPercent(pct int) {
	if pct <= 0 || pct > 100 {
		return
	}
	n := runtime.NumCPU() * pct / 100
	if n < 1 {
		n = 1
	}
	runtime.GOMAXPROCS(n)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/runtime/limits/... -v -run ApplyCPUPercent`
Expected: PASS (1 test, 6 subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/limits/cpu.go internal/runtime/limits/cpu_test.go
git commit -m "feat(limits): cap GOMAXPROCS via ApplyCPUPercent"
```

---

## Task 4: Memory soft-limit + watchdog

**Files:**
- Create: `internal/runtime/limits/memory.go`
- Create: `internal/runtime/limits/memory_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/limits/memory_test.go`:

```go
package limits

import (
	"context"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"
)

func TestApplyMemoryLimitSetsSoftLimit(t *testing.T) {
	orig := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(orig) })

	const want = int64(512 << 20) // 512MB
	ApplyMemoryLimit(want)

	got := debug.SetMemoryLimit(-1)
	if got != want {
		t.Errorf("SetMemoryLimit after ApplyMemoryLimit = %d, want %d", got, want)
	}
}

func TestApplyMemoryLimitZeroIsNoop(t *testing.T) {
	orig := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(orig) })

	ApplyMemoryLimit(0)

	got := debug.SetMemoryLimit(-1)
	if got != orig {
		t.Errorf("ApplyMemoryLimit(0) changed limit from %d to %d (want unchanged)", orig, got)
	}
}

// TestWatchdogTriggersOnBreach verifies the watchdog calls its kill hook when
// the sampler reports memory above the hard cap. We inject a fake sampler
// returning a value above the threshold and a fake kill hook that increments
// a counter. Runs with a short sample interval.
func TestWatchdogTriggersOnBreach(t *testing.T) {
	var killed atomic.Int32
	cfg := watchdogConfig{
		softLimit:     100 << 20,        // 100MB soft
		hardMultiple:  1.5,               // → 150MB hard cap
		sampleEvery:   10 * time.Millisecond,
		sampleMemory:  func() uint64 { return 200 << 20 }, // always report 200MB
		kill:          func() { killed.Add(1) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		watchdogLoop(ctx, cfg)
		close(done)
	}()

	// Give the watchdog a few ticks to notice the breach.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if killed.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if killed.Load() == 0 {
		t.Error("watchdog did not call kill hook after breach")
	}
}

// TestWatchdogDoesNotTriggerUnderLimit verifies no kill when memory is fine.
func TestWatchdogDoesNotTriggerUnderLimit(t *testing.T) {
	var killed atomic.Int32
	cfg := watchdogConfig{
		softLimit:    100 << 20,
		hardMultiple: 1.5,
		sampleEvery:  10 * time.Millisecond,
		sampleMemory: func() uint64 { return 50 << 20 }, // well under
		kill:         func() { killed.Add(1) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchdogLoop(ctx, cfg)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if killed.Load() != 0 {
		t.Errorf("watchdog fired %d time(s) under limit (want 0)", killed.Load())
	}
}

// TestWatchdogStopsOnCancel verifies the goroutine exits when context
// is cancelled.
func TestWatchdogStopsOnCancel(t *testing.T) {
	cfg := watchdogConfig{
		softLimit:    100 << 20,
		hardMultiple: 1.5,
		sampleEvery:  10 * time.Millisecond,
		sampleMemory: func() uint64 { return 0 },
		kill:         func() {},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		watchdogLoop(ctx, cfg)
		close(done)
	}()
	cancel()
	select {
	case <-done:
		// ok
	case <-time.After(200 * time.Millisecond):
		t.Error("watchdog did not exit within 200ms of cancel")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runtime/limits/... -v -run 'Memory|Watchdog'`
Expected: FAIL with "undefined: ApplyMemoryLimit" / "undefined: watchdogConfig" / "undefined: watchdogLoop".

- [ ] **Step 3: Write minimal implementation**

Create `internal/runtime/limits/memory.go`:

```go
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
// Called once by StartMemoryWatchdog; exported at package level only for
// tests.
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/runtime/limits/... -v -run 'Memory|Watchdog' -race`
Expected: PASS (5 tests). Race detector clean.

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/limits/memory.go internal/runtime/limits/memory_test.go
git commit -m "feat(limits): add memory soft limit and hard watchdog"
```

---

## Task 5: Nice/setpriority (Unix-only)

**Files:**
- Create: `internal/runtime/limits/nice_unix.go`
- Create: `internal/runtime/limits/nice_windows.go`
- Create: `internal/runtime/limits/nice_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/runtime/limits/nice_test.go`:

```go
package limits

import "testing"

// ApplyNice must exist on every platform and never panic. On Unix it calls
// setpriority; on Windows it's a no-op. Testing the actual priority change
// requires root on some systems, so we only verify the function is callable
// with representative inputs and that zero is a no-op.
func TestApplyNiceDoesNotPanic(t *testing.T) {
	for _, n := range []int{0, 1, 5, 10, -1} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ApplyNice(%d) panicked: %v", n, r)
				}
			}()
			ApplyNice(n)
		}()
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runtime/limits/... -v -run ApplyNice`
Expected: FAIL with "undefined: ApplyNice".

- [ ] **Step 3: Write minimal implementation**

Create `internal/runtime/limits/nice_unix.go`:

```go
//go:build unix

package limits

import "syscall"

// ApplyNice adjusts the current process's scheduling priority.
// On Unix, wraps setpriority(PRIO_PROCESS, 0, nice). Zero is a no-op.
// Failures are silently ignored: CAP_SYS_NICE may be absent and --nice
// should never be the reason a scan refuses to start.
func ApplyNice(n int) {
	if n == 0 {
		return
	}
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, n)
}
```

Create `internal/runtime/limits/nice_windows.go`:

```go
//go:build windows

package limits

// ApplyNice is a no-op on Windows. A future task may map this to
// SetPriorityClass via golang.org/x/sys/windows; for now --nice on
// Windows does nothing.
func ApplyNice(n int) {}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/runtime/limits/... -v -run ApplyNice`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/limits/nice_unix.go internal/runtime/limits/nice_windows.go internal/runtime/limits/nice_test.go
git commit -m "feat(limits): add ApplyNice wrapper (unix setpriority, windows no-op)"
```

---

## Task 6: Compose everything in `Limits.Apply()`

**Files:**
- Modify: `internal/runtime/limits/limits.go:1` (add Apply method)
- Modify: `internal/runtime/limits/limits_test.go:1` (add composition tests)

- [ ] **Step 1: Write the failing test**

Append to `internal/runtime/limits/limits_test.go`:

```go
import (
	"context"
	"runtime"
	"runtime/debug"
	// keep existing imports
)

func TestApplyZeroIsNoop(t *testing.T) {
	origProcs := runtime.GOMAXPROCS(0)
	origMem := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(origProcs)
		debug.SetMemoryLimit(origMem)
	})

	var l Limits
	ctx := context.Background()
	newCtx, cleanup := l.Apply(ctx)
	defer cleanup()

	if newCtx != ctx {
		t.Error("Apply() with zero Limits must return input ctx unchanged")
	}
	if deadline, ok := newCtx.Deadline(); ok {
		t.Errorf("Apply() with zero Limits must not set a deadline, got %v", deadline)
	}
	if runtime.GOMAXPROCS(0) != origProcs {
		t.Errorf("Apply() with zero Limits changed GOMAXPROCS")
	}
	if debug.SetMemoryLimit(-1) != origMem {
		t.Errorf("Apply() with zero Limits changed memory limit")
	}
}

func TestApplySetsDeadline(t *testing.T) {
	l := Limits{MaxDuration: 100 * time.Millisecond}
	ctx := context.Background()
	newCtx, cleanup := l.Apply(ctx)
	defer cleanup()

	deadline, ok := newCtx.Deadline()
	if !ok {
		t.Fatal("Apply() with MaxDuration must set deadline")
	}
	until := time.Until(deadline)
	if until <= 0 || until > 200*time.Millisecond {
		t.Errorf("deadline %v is not ~100ms from now (got %v)", deadline, until)
	}
}

func TestApplyUsesTighterOfDurationAndStopAt(t *testing.T) {
	l := Limits{
		MaxDuration:  5 * time.Hour,
		StopAtOffset: 30 * time.Minute, // tighter
	}
	ctx := context.Background()
	newCtx, cleanup := l.Apply(ctx)
	defer cleanup()

	deadline, ok := newCtx.Deadline()
	if !ok {
		t.Fatal("Apply() must set deadline when either duration is set")
	}
	until := time.Until(deadline)
	if until > 35*time.Minute || until < 25*time.Minute {
		t.Errorf("deadline %v should be ~30min from now, got %v away", deadline, until)
	}
}

func TestApplyCleanupStopsWatchdog(t *testing.T) {
	// Can't directly observe the watchdog goroutine, but we can verify
	// cleanup() returns promptly and doesn't panic when called twice.
	l := Limits{MaxMemoryBytes: 1 << 30}
	newCtx, cleanup := l.Apply(context.Background())
	_ = newCtx
	cleanup()
	cleanup() // idempotent
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/runtime/limits/... -v -run Apply`
Expected: FAIL with "l.Apply undefined" (the method).

- [ ] **Step 3: Write minimal implementation**

Append to `internal/runtime/limits/limits.go`:

```go
import (
	"context"
	// keep existing imports
)

// Apply installs all configured limits and returns a derived context plus a
// cleanup function the caller must defer. The returned context carries a
// deadline matching effectiveDuration() if positive. Calling cleanup is
// idempotent.
//
// Order of operations:
//  1. runtime/debug.SetMemoryLimit (soft cap)
//  2. runtime.GOMAXPROCS (cpu throttle)
//  3. syscall.Setpriority (nice, unix only)
//  4. context.WithTimeout (deadline)
//  5. start watchdog goroutine (hard memory cap)
//
// Limits are not reversed by cleanup (GOMAXPROCS, GOMEMLIMIT, nice persist
// for the process lifetime). Only the watchdog and context deadline are
// torn down.
func (l Limits) Apply(ctx context.Context) (context.Context, func()) {
	if !l.Enabled() {
		return ctx, func() {}
	}

	ApplyMemoryLimit(l.MaxMemoryBytes)
	ApplyCPUPercent(l.MaxCPUPercent)
	ApplyNice(l.Nice)

	var cancelDeadline context.CancelFunc = func() {}
	if d := l.effectiveDuration(); d > 0 {
		ctx, cancelDeadline = context.WithTimeout(ctx, d)
	}

	stopWatchdog := StartMemoryWatchdog(ctx, l.MaxMemoryBytes)

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			stopWatchdog()
			cancelDeadline()
		})
	}
	return ctx, cleanup
}
```

Also add `"sync"` to the imports block at the top of `limits.go`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/runtime/limits/... -v -race`
Expected: PASS (all ~12 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/runtime/limits/limits.go internal/runtime/limits/limits_test.go
git commit -m "feat(limits): add Limits.Apply() composing all limits"
```

---

## Task 7: Wire flags into `cmd/root.go`

**Files:**
- Modify: `cmd/root.go:151` (init function — add flag definitions)
- Modify: `cmd/root.go:322` (runScan — parse flags, call Apply, use returned ctx)
- Modify: `cmd/root.go:529` (runScanHeadless — pass ctx from runScan instead of creating new)

- [ ] **Step 1: Write the failing test**

Create `cmd/root_limits_test.go`:

```go
package cmd

import (
	"testing"
	"time"
)

// TestBuildLimitsFromFlags verifies the flag-value → Limits struct conversion.
// Does not test Cobra wiring; that's integration territory.
func TestBuildLimitsFromFlags(t *testing.T) {
	cases := []struct {
		name          string
		maxMemory     string
		maxCPUPercent string
		maxDuration   time.Duration
		stopAt        string
		nice          int
		wantMem       int64
		wantCPU       int
		wantDur       time.Duration
		wantStopSet   bool // stop-at should produce non-zero offset when set
		wantNice      int
		wantErr       bool
	}{
		{
			name: "all empty", wantErr: false,
		},
		{
			name:      "memory and cpu",
			maxMemory: "2GB", maxCPUPercent: "50",
			wantMem: 2 << 30, wantCPU: 50,
		},
		{
			name:        "duration",
			maxDuration: 4 * time.Hour,
			wantDur:     4 * time.Hour,
		},
		{
			name: "stop-at at 23:59",
			stopAt: "23:59",
			wantStopSet: true,
		},
		{
			name: "invalid memory",
			maxMemory: "nope",
			wantErr: true,
		},
		{
			name: "invalid percent",
			maxCPUPercent: "200",
			wantErr: true,
		},
		{
			name: "nice",
			nice: 10, wantNice: 10,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildLimits(tc.maxMemory, tc.maxCPUPercent, tc.maxDuration, tc.stopAt, tc.nice)
			if (err != nil) != tc.wantErr {
				t.Fatalf("buildLimits err=%v, wantErr=%v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got.MaxMemoryBytes != tc.wantMem {
				t.Errorf("MaxMemoryBytes=%d want %d", got.MaxMemoryBytes, tc.wantMem)
			}
			if got.MaxCPUPercent != tc.wantCPU {
				t.Errorf("MaxCPUPercent=%d want %d", got.MaxCPUPercent, tc.wantCPU)
			}
			if got.MaxDuration != tc.wantDur {
				t.Errorf("MaxDuration=%v want %v", got.MaxDuration, tc.wantDur)
			}
			if (got.StopAtOffset > 0) != tc.wantStopSet {
				t.Errorf("StopAtOffset=%v wantStopSet=%v", got.StopAtOffset, tc.wantStopSet)
			}
			if got.Nice != tc.wantNice {
				t.Errorf("Nice=%d want %d", got.Nice, tc.wantNice)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/... -v -run BuildLimitsFromFlags`
Expected: FAIL with "undefined: buildLimits".

- [ ] **Step 3: Add `buildLimits` helper**

In `cmd/root.go`, find the line that says `import (` near the top. Add the limits import to that block:

```go
"github.com/amiryahaya/triton/internal/runtime/limits"
```

(Keep it alphabetically sorted among the other triton imports.)

Then add the helper. Put it immediately after `runScanHeadless` (around line 560 after the function ends). Find the `// saveScanResult persists...` comment and insert the new function just before it:

```go
// buildLimits converts raw CLI flag values into a validated Limits struct.
// Returns an error if any flag value is malformed. time.Now() is called
// inline so --stop-at resolves against the actual clock at scan start.
func buildLimits(maxMemory, maxCPUPercent string, maxDuration time.Duration, stopAt string, nice int) (limits.Limits, error) {
	memBytes, err := limits.ParseSize(maxMemory)
	if err != nil {
		return limits.Limits{}, fmt.Errorf("--max-memory: %w", err)
	}
	cpuPct, err := limits.ParsePercent(maxCPUPercent)
	if err != nil {
		return limits.Limits{}, fmt.Errorf("--max-cpu-percent: %w", err)
	}
	stopOffset, err := limits.ParseStopAt(stopAt, time.Now())
	if err != nil {
		return limits.Limits{}, fmt.Errorf("--stop-at: %w", err)
	}
	return limits.Limits{
		MaxMemoryBytes: memBytes,
		MaxCPUPercent:  cpuPct,
		MaxDuration:    maxDuration,
		StopAtOffset:   stopOffset,
		Nice:           nice,
	}, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/... -v -run BuildLimitsFromFlags`
Expected: PASS (1 test, 7 subtests).

- [ ] **Step 5: Add CLI flag definitions**

In `cmd/root.go`, locate the `init()` function (starts at line 151). After the existing pcap flag block (the line `rootCmd.MarkFlagsMutuallyExclusive("pcap-file", "pcap-interface")` at line 202), add a new block:

```go
	// Resource limits (applies to foreground scans, future agent-supervised
	// scans, and future ssh-agentless orchestrator invocations).
	rootCmd.PersistentFlags().String("max-memory", "",
		"soft memory cap (e.g. 2GB, 512MB); hard watchdog triggers self-kill at 1.5x")
	rootCmd.PersistentFlags().String("max-cpu-percent", "",
		"cap GOMAXPROCS to this percentage of NumCPU (1-100; caps parallelism, not CPU time)")
	rootCmd.PersistentFlags().Duration("max-duration", 0,
		"wall-clock budget for the scan (e.g. 4h); scan returns partial results on timeout")
	rootCmd.PersistentFlags().String("stop-at", "",
		"stop the scan at this local clock time (HH:MM); if past, rolls to tomorrow")
	rootCmd.PersistentFlags().Int("nice", 0,
		"scheduling priority adjustment (unix only; higher = lower priority; 0 = no change)")
```

- [ ] **Step 6: Wire `Apply()` into `runScan` (place limits BEFORE the headless-check branch)**

In `cmd/root.go`, locate `runScan` (starts at line 322). The current structure is:

```go
// ...config build, guard checks, eng := scanner.New(cfg), eng.SetStore(...)...

if !term.IsTerminal(int(os.Stdin.Fd())) {                // ← line 470
    return runScanHeadless(eng)
}

progressCh := make(chan scanner.Progress, progressBufferSize)
ctx, cancel := context.WithCancel(context.Background())  // ← line 475
defer cancel()

go eng.Scan(ctx, progressCh)

// ...TUI setup with cancel in scanModel, final drain defer, rest of function...
```

We need limits constructed **before** the headless branch so both paths use them. Edit as follows.

**6a.** Immediately before the `if !term.IsTerminal(int(os.Stdin.Fd())) {` line (around line 470), insert the limits construction block:

```go
	maxMem, _ := cmd.Flags().GetString("max-memory")
	maxCPU, _ := cmd.Flags().GetString("max-cpu-percent")
	maxDur, _ := cmd.Flags().GetDuration("max-duration")
	stopAt, _ := cmd.Flags().GetString("stop-at")
	niceVal, _ := cmd.Flags().GetInt("nice")
	lim, err := buildLimits(maxMem, maxCPU, maxDur, stopAt, niceVal)
	if err != nil {
		return err
	}
	if lim.Enabled() {
		fmt.Printf("Resource %s\n", lim.String())
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())
	defer baseCancel()
	limitedCtx, limitsCleanup := lim.Apply(baseCtx)
	defer limitsCleanup()
```

**6b.** Change the headless-branch call (line 471) from:

```go
return runScanHeadless(eng)
```

to:

```go
return runScanHeadless(eng, limitedCtx)
```

**6c.** Replace the old TUI context setup (original lines 474-476):

```go
progressCh := make(chan scanner.Progress, progressBufferSize)
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

go eng.Scan(ctx, progressCh)
```

with:

```go
	progressCh := make(chan scanner.Progress, progressBufferSize)
	// Preserve `cancel` as a name — the BubbleTea scanModel captures it.
	// Cancelling it cancels baseCtx, which propagates to limitedCtx.
	cancel := baseCancel

	go eng.Scan(limitedCtx, progressCh)
```

The existing `defer func() { cancel(); for range progressCh {} }()` block (originally around line 483) still works unchanged — `cancel` now points to `baseCancel` and triggers the cascade.

- [ ] **Step 7: Update `runScanHeadless` signature to accept the limits-enriched context**

In `cmd/root.go`, locate `runScanHeadless` (line 529). Change its signature from:

```go
func runScanHeadless(eng *scanner.Engine) error {
```

to:

```go
func runScanHeadless(eng *scanner.Engine, parentCtx context.Context) error {
```

Then inside the function, replace:

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
defer stop()
```

with:

```go
ctx, stop := signal.NotifyContext(parentCtx, os.Interrupt)
defer stop()
```

`signal.NotifyContext` now wraps the caller's limits-enriched context rather than a fresh background ctx, so `--max-duration` and `--stop-at` apply to headless runs.

- [ ] **Step 8: Run all tests**

Run: `go build ./... && go test ./... -race`
Expected: All tests pass, no build errors.

- [ ] **Step 9: Smoke-test the CLI**

Run: `go run . scan --help 2>&1 | grep -E "max-(memory|cpu-percent|duration)|stop-at|nice"`
Expected output includes all five flags.

Run: `go run . scan --max-memory nope 2>&1 | head -5`
Expected: error message mentioning `--max-memory` and invalid size.

Run: `go run . scan --max-duration 2s --profile quick -o /tmp/triton-smoke.json 2>&1 | tail -20`
Expected: scan starts, prints "Resource limits: duration=2s", completes normally if quick profile finishes in 2s; if not, scan cancels cleanly with partial results. Either is acceptable.

- [ ] **Step 10: Commit**

```bash
git add cmd/root.go cmd/root_limits_test.go
git commit -m "feat(cmd): add --max-memory/--max-cpu-percent/--max-duration/--stop-at/--nice flags"
```

---

## Task 8: Integration test — flags propagate end-to-end

**Files:**
- Create: `test/integration/resource_limits_test.go`

- [ ] **Step 1: Write the failing test**

Create `test/integration/resource_limits_test.go`:

```go
//go:build integration

package integration

import (
	"context"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/runtime/limits"
)

// TestLimitsApply_EndToEnd applies a realistic bundle of limits and verifies
// each dimension took effect in the process.
func TestLimitsApply_EndToEnd(t *testing.T) {
	origProcs := runtime.GOMAXPROCS(0)
	origMem := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		runtime.GOMAXPROCS(origProcs)
		debug.SetMemoryLimit(origMem)
	})

	l := limits.Limits{
		MaxMemoryBytes: 1 << 30, // 1GB
		MaxCPUPercent:  50,
		MaxDuration:    1 * time.Second,
	}
	ctx, cleanup := l.Apply(context.Background())
	defer cleanup()

	// 1. Memory limit was set.
	if got := debug.SetMemoryLimit(-1); got != 1<<30 {
		t.Errorf("SetMemoryLimit: got %d, want %d", got, 1<<30)
	}
	// 2. GOMAXPROCS was capped.
	wantProcs := runtime.NumCPU() / 2
	if wantProcs < 1 {
		wantProcs = 1
	}
	if got := runtime.GOMAXPROCS(0); got != wantProcs {
		t.Errorf("GOMAXPROCS: got %d, want %d (NumCPU=%d)", got, wantProcs, runtime.NumCPU())
	}
	// 3. Context has deadline within ~1s.
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context missing deadline")
	}
	if until := time.Until(deadline); until > 1200*time.Millisecond || until <= 0 {
		t.Errorf("deadline %v is not ~1s from now", until)
	}
	// 4. Context actually cancels after timeout.
	select {
	case <-ctx.Done():
		// ok
	case <-time.After(1500 * time.Millisecond):
		t.Error("context did not cancel within 1.5s (deadline was 1s)")
	}
}
```

- [ ] **Step 2: Run test to verify it passes**

Run: `go test -tags integration ./test/integration/... -v -run TestLimitsApply_EndToEnd`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add test/integration/resource_limits_test.go
git commit -m "test(integration): end-to-end resource limits propagation"
```

---

## Task 9: Documentation

**Files:**
- Modify: `README.md` (add a "Resource limits" section under Usage)
- Modify: `CLAUDE.md:117` (under Scan profiles, reference that limits are orthogonal to profile)

- [ ] **Step 1: Update README.md**

Find the existing CLI usage section in `README.md` (search for `triton scan` or `--profile`). After that section, add:

```markdown
### Resource limits

Cap a scan's resource footprint with any combination of:

| Flag | Meaning | Example |
|---|---|---|
| `--max-memory` | Soft memory cap (GC pressure); watchdog self-kills at 1.5x | `--max-memory 2GB` |
| `--max-cpu-percent` | Cap GOMAXPROCS to this % of NumCPU | `--max-cpu-percent 50` |
| `--max-duration` | Wall-clock budget; partial results on timeout | `--max-duration 4h` |
| `--stop-at` | Stop at clock time (local TZ, HH:MM) | `--stop-at 03:00` |
| `--nice` | Scheduling priority (unix; higher = nicer) | `--nice 10` |

Limits work identically for foreground scans, agent-supervised scans, and (future) ssh-agentless orchestrator invocations.

**Caveats:**
- `--max-memory` is a soft limit via `GOMEMLIMIT`. The GC pushes hard to stay under it. A hard watchdog self-kills at 1.5x as a safety net for runaway allocations. For kernel-enforced hard limits, wrap with `systemd-run --scope -p MemoryMax=...`.
- `--max-cpu-percent` caps parallelism, not CPU time. A single tight loop still saturates one core.
- `--nice` is a no-op on Windows.
```

- [ ] **Step 2: Update CLAUDE.md**

In `CLAUDE.md`, find the `### Scan profiles` section (around line 109). After that section (before `Worker count is capped by CPU count.` or just after), add:

```markdown
### Resource limits (orthogonal to profile)

The `triton scan` command accepts five resource flags — `--max-memory`, `--max-cpu-percent`, `--max-duration`, `--stop-at`, `--nice` — implemented in `internal/runtime/limits/`. These are in-process limits that work on all platforms without systemd, cgroups, or elevated privileges, so the same flags apply to foreground scans, agent-supervised scans, and ssh-agentless orchestrator invocations. See `internal/runtime/limits/doc.go` for caveats (soft vs hard semantics, platform-specific nice behavior).
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: document resource limit flags"
```

---

## Task 10: Final verification

- [ ] **Step 1: Full build**

Run: `go build ./...`
Expected: No errors.

- [ ] **Step 2: Full test suite**

Run: `go test ./... -race`
Expected: All tests pass.

- [ ] **Step 3: Integration tests**

Run: `TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable" go test -tags integration ./test/integration/... -race -run TestLimitsApply_EndToEnd`
Expected: PASS.

(Other integration tests in this package may require more setup — we only need to verify our new one.)

- [ ] **Step 4: Lint**

Run: `golangci-lint run ./internal/runtime/limits/... ./cmd/...`
Expected: No new lint warnings.

- [ ] **Step 5: Format**

Run: `gofmt -l internal/runtime/limits/ cmd/root.go cmd/root_limits_test.go`
Expected: No output (all files formatted).

- [ ] **Step 6: Help output review**

Run: `go run . scan --help 2>&1 | grep -B1 -A1 "max-\|stop-at\|nice"`
Expected: all five flags appear with readable help text.

- [ ] **Step 7: Coverage check**

Run: `go test -cover ./internal/runtime/limits/...`
Expected: ≥80% coverage (the target per CLAUDE.md's TDD section).

---

## Self-Review Checklist

Before declaring the feature complete, verify:

1. **Zero-value `Limits` is a true no-op.** Calling `Apply()` with an empty struct must return the input context unchanged and must not mutate GOMAXPROCS or GOMEMLIMIT. (Covered by `TestApplyZeroIsNoop`.)

2. **Race detector clean.** The watchdog is a goroutine sharing state with the cleanup func via `sync.Once` + context cancellation. Ran with `-race`.

3. **Flags are PersistentFlags, not local.** This means `triton scan --max-memory 2GB` and any future subcommand (e.g. `triton agent`) can reuse the same flag. Confirm by checking `init()` — uses `rootCmd.PersistentFlags()`.

4. **`--max-duration` and `--stop-at` tighter-wins.** `TestApplyUsesTighterOfDurationAndStopAt` covers this.

5. **Nice is optional.** If the CLI caller has no `CAP_SYS_NICE` capability, `syscall.Setpriority` may return EPERM. We swallow the error — `--nice` should never fail a scan.

6. **runScanHeadless and runScan share one code path for limits.** `runScan` builds `Limits`, calls `Apply`, and threads the resulting ctx to `runScanHeadless`. The headless variant does not re-build limits — that would be a DRY violation.

7. **No placeholder text in the plan.** All code blocks show complete code. No "TODO" or "add error handling" steps.

8. **Consistent naming.** `MaxMemoryBytes` (int64), `MaxCPUPercent` (int), `MaxDuration` (time.Duration), `StopAtOffset` (time.Duration), `Nice` (int) — used identically in tests, struct, flag conversion helper, and `Apply()`.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-04-17-resource-limits-foundation.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
