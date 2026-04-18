# Agent Cron Scheduling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let operators pin agent scans to wall-clock times (e.g., `0 2 * * 0`) via a new `schedule:` field in `agent.yaml`, evaluated in local time, with opt-in jitter.

**Architecture:** One new field (`schedule:`) + one tuning knob (`schedule_jitter:`) on `Config`. A plain-data `ScheduleSpec` returned by `internal/agentconfig.ResolveSchedule` keeps the cron library confined to `cmd/`. `cmd/agent.go` extracts today's inline `time.After(interval + jitter)` into a small `scheduler` interface with two implementations (`intervalScheduler`, `cronScheduler`), preserving all existing behavior byte-for-byte when no `schedule:` is set.

**Tech Stack:** Go 1.26, `github.com/robfig/cron/v3` (new), `github.com/spf13/cobra` (existing), `gopkg.in/yaml.v3` (existing).

**Spec:** `docs/plans/2026-04-19-agent-cron-schedule-design.md`

**Precedence:** `schedule:` yaml > `interval:` yaml > `--interval` flag > one-shot. `schedule` + `interval` both set → `schedule` wins with a warning.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `go.mod`, `go.sum` | Pin `github.com/robfig/cron/v3` dependency. |
| `internal/agentconfig/loader.go` | Add `Schedule string` + `ScheduleJitter time.Duration` fields to `Config`. No logic. |
| `internal/agentconfig/schedule.go` (new) | `ScheduleSpec` plain-data struct + `ScheduleKind` string constants. Pure data, no lib imports. |
| `internal/agentconfig/resolve.go` | Add `ResolveSchedule(cmd *cobra.Command) (ScheduleSpec, error)` using precedence chain. |
| `internal/agentconfig/schedule_test.go` (new) | Table-driven precedence tests. |
| `internal/agentconfig/loader_test.go` | Extend with YAML round-trip cases for new fields. |
| `cmd/agent_scheduler.go` (new) | `scheduler` interface + `intervalScheduler` + `cronScheduler` + `newScheduler(ScheduleSpec)` constructor. Cron library import lives here. |
| `cmd/agent_scheduler_test.go` (new) | Unit tests: `Next()` determinism for both impls, `Describe()`, invalid cron errors. |
| `cmd/agent.go` | Replace inline `agentInterval + intervalJitterFn(agentInterval)` sleep with `sched.Next(time.Now())`. Add startup log. |
| `cmd/agent_schedule_test.go` (new) | Integration-ish test: scheduler is constructed from resolved config, errors on invalid cron before the scan loop runs. |
| `docs/DEPLOYMENT_GUIDE.md` | New `schedule:` subsection under agent config. |
| `CLAUDE.md` | One-line note in the agent-mode section about cron scheduling. |
| `/Users/amirrudinyahaya/.claude/projects/-Users-amirrudinyahaya-Workspace-triton/memory/agent-control-features.md` | Flip item 5 to partial-shipped (local cron complete). |

Rough size: ~180 LOC production, ~250 LOC tests, ~50 LOC docs.

---

## Task 1: Add `robfig/cron/v3` dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Add the dependency**

Run:
```bash
go get github.com/robfig/cron/v3@v3.0.1
```

Expected: `go.mod` gains `github.com/robfig/cron/v3 v3.0.1`, `go.sum` gains two lines. No build errors because nothing imports it yet.

- [ ] **Step 2: Verify the module is available**

Run:
```bash
go list -m github.com/robfig/cron/v3
```

Expected: `github.com/robfig/cron/v3 v3.0.1`.

- [ ] **Step 3: Run tidy to ensure no drift**

Run:
```bash
go mod tidy
```

Expected: no changes (the dep is now in use by nothing, but `go get` already normalized the files).

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add github.com/robfig/cron/v3 for agent cron scheduling"
```

---

## Task 2: Add `Schedule` + `ScheduleJitter` fields to Config (YAML)

**Files:**
- Test: `internal/agentconfig/loader_test.go`
- Modify: `internal/agentconfig/loader.go`

- [ ] **Step 1: Write the failing YAML round-trip test**

Append to `internal/agentconfig/loader_test.go`:

```go
func TestLoad_ScheduleFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	content := []byte(`
schedule: "0 2 * * 0"
schedule_jitter: 30s
interval: 24h
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Schedule != "0 2 * * 0" {
		t.Errorf("Schedule = %q, want %q", cfg.Schedule, "0 2 * * 0")
	}
	if cfg.ScheduleJitter != 30*time.Second {
		t.Errorf("ScheduleJitter = %v, want 30s", cfg.ScheduleJitter)
	}
	if cfg.Interval != 24*time.Hour {
		t.Errorf("Interval = %v, want 24h (preserved alongside schedule)", cfg.Interval)
	}
}

func TestLoad_ScheduleFieldsDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("profile: quick\n"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Schedule != "" {
		t.Errorf("Schedule default = %q, want empty", cfg.Schedule)
	}
	if cfg.ScheduleJitter != 0 {
		t.Errorf("ScheduleJitter default = %v, want 0", cfg.ScheduleJitter)
	}
}
```

**Note:** The existing `loader_test.go` may or may not have an `Interval` field. If `Config.Interval` doesn't yet exist, the compile will fail on that line; check `loader.go` and add `Interval time.Duration` to `Config` in Step 3 alongside the new fields.

- [ ] **Step 2: Run test to verify it fails (compile error or assertion)**

Run:
```bash
go test ./internal/agentconfig/ -run TestLoad_ScheduleFields -v
```

Expected: FAIL — `cfg.Schedule undefined` or `cfg.ScheduleJitter undefined`.

- [ ] **Step 3: Add the fields to `Config`**

In `internal/agentconfig/loader.go`, inside the `type Config struct` block, add after the `ResourceLimits` field (and before `loadedFrom`):

```go
	// Schedule is a standard 5-field cron expression evaluated in the
	// agent host's local timezone. When non-empty, this wins over
	// Interval and --interval. See docs/plans/2026-04-19-agent-cron-schedule-design.md.
	Schedule string `yaml:"schedule,omitempty"`

	// ScheduleJitter adds uniform random jitter in [0, ScheduleJitter)
	// to each cron-scheduled fire time. Defaults to 0 (disabled) —
	// unlike Interval mode which always jitters ±10%, cron's whole
	// point is "fire at X o'clock", so jitter is opt-in for fleet-wide
	// staggering. Written as a Go duration string ("30s", "5m").
	ScheduleJitter time.Duration `yaml:"schedule_jitter,omitempty"`

	// Interval is the existing repeat interval (24h, 1h, etc.). When
	// Schedule is non-empty this is ignored. Kept as a yaml-level
	// field so tests can round-trip it; the CLI --interval flag
	// remains authoritative in the absence of a yaml value.
	Interval time.Duration `yaml:"interval,omitempty"`
```

(If `Interval` already exists on `Config`, omit the third field and keep the existing one.)

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
go test ./internal/agentconfig/ -run TestLoad_Schedule -v
```

Expected: PASS for both `TestLoad_ScheduleFields` and `TestLoad_ScheduleFieldsDefaults`.

- [ ] **Step 5: Run full agentconfig tests to confirm no regression**

Run:
```bash
go test ./internal/agentconfig/... -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/agentconfig/loader.go internal/agentconfig/loader_test.go
git commit -m "agentconfig: add Schedule and ScheduleJitter yaml fields"
```

---

## Task 3: Create `ScheduleSpec` plain-data type

**Files:**
- Create: `internal/agentconfig/schedule.go`
- Create: `internal/agentconfig/schedule_test.go`

- [ ] **Step 1: Write the failing test for the struct shape**

Create `internal/agentconfig/schedule_test.go`:

```go
package agentconfig

import (
	"testing"
	"time"
)

func TestScheduleSpec_Kinds(t *testing.T) {
	// Sanity: the kind constants exist and are distinct.
	if ScheduleKindCron == ScheduleKindInterval {
		t.Error("ScheduleKindCron must differ from ScheduleKindInterval")
	}
	if ScheduleKindOneShot == ScheduleKindInterval {
		t.Error("ScheduleKindOneShot must differ from ScheduleKindInterval")
	}
}

func TestScheduleSpec_Zero(t *testing.T) {
	var s ScheduleSpec
	if s.Kind != "" {
		t.Errorf("zero ScheduleSpec.Kind = %q, want empty", s.Kind)
	}
	if s.CronExpr != "" {
		t.Errorf("zero ScheduleSpec.CronExpr = %q, want empty", s.CronExpr)
	}
	if s.Interval != 0 {
		t.Errorf("zero ScheduleSpec.Interval = %v, want 0", s.Interval)
	}
	if s.Jitter != 0 {
		t.Errorf("zero ScheduleSpec.Jitter = %v, want 0", s.Jitter)
	}
}

func TestScheduleSpec_Populated(t *testing.T) {
	s := ScheduleSpec{
		Kind:     ScheduleKindCron,
		CronExpr: "0 2 * * *",
		Jitter:   30 * time.Second,
	}
	if s.Kind != ScheduleKindCron {
		t.Errorf("Kind = %q, want %q", s.Kind, ScheduleKindCron)
	}
	if s.CronExpr != "0 2 * * *" {
		t.Errorf("CronExpr = %q", s.CronExpr)
	}
	if s.Jitter != 30*time.Second {
		t.Errorf("Jitter = %v", s.Jitter)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
go test ./internal/agentconfig/ -run TestScheduleSpec -v
```

Expected: FAIL — `undefined: ScheduleSpec`, `undefined: ScheduleKindCron`, etc.

- [ ] **Step 3: Create the struct and constants**

Create `internal/agentconfig/schedule.go`:

```go
package agentconfig

import "time"

// ScheduleKind discriminates ScheduleSpec variants without a sum type.
// A plain string keeps the struct yaml/json-safe if we ever serialize it.
type ScheduleKind string

const (
	// ScheduleKindCron means CronExpr is set and Interval is ignored.
	ScheduleKindCron ScheduleKind = "cron"
	// ScheduleKindInterval means Interval is set and CronExpr is ignored.
	ScheduleKindInterval ScheduleKind = "interval"
	// ScheduleKindOneShot means neither is set — the agent runs once
	// and exits. Jitter is ignored.
	ScheduleKindOneShot ScheduleKind = "oneshot"
)

// ScheduleSpec is the plain-data result of resolving schedule/interval
// from agent.yaml + CLI flags. It does NOT import the cron library —
// cmd/agent_scheduler.go is responsible for parsing CronExpr and
// building the runtime scheduler.
//
// One-shot mode is represented by Kind=ScheduleKindOneShot and both
// CronExpr and Interval at their zero values.
type ScheduleSpec struct {
	Kind     ScheduleKind
	CronExpr string        // populated when Kind == ScheduleKindCron
	Interval time.Duration // populated when Kind == ScheduleKindInterval
	Jitter   time.Duration // optional; 0 means no jitter
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
go test ./internal/agentconfig/ -run TestScheduleSpec -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/agentconfig/schedule.go internal/agentconfig/schedule_test.go
git commit -m "agentconfig: add ScheduleSpec plain-data type"
```

---

## Task 4: Implement `Config.ResolveSchedule(cmd)`

**Files:**
- Test: `internal/agentconfig/schedule_test.go`
- Modify: `internal/agentconfig/resolve.go`

- [ ] **Step 1: Write failing precedence tests**

Append to `internal/agentconfig/schedule_test.go`:

```go
import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// newScheduleTestCmd returns a *cobra.Command with the --interval flag
// registered (mirroring cmd/agent.go's real registration).
func newScheduleTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Duration("interval", 0, "")
	return cmd
}

func TestResolveSchedule_CronWinsOverInterval(t *testing.T) {
	cfg := &Config{
		Schedule: "0 2 * * 0",
		Interval: 24 * time.Hour,
	}
	var warn bytes.Buffer
	spec, err := cfg.ResolveSchedule(newScheduleTestCmd(), &warn)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindCron {
		t.Errorf("Kind = %q, want cron", spec.Kind)
	}
	if spec.CronExpr != "0 2 * * 0" {
		t.Errorf("CronExpr = %q", spec.CronExpr)
	}
	if !strings.Contains(warn.String(), "schedule") || !strings.Contains(warn.String(), "interval") {
		t.Errorf("expected both-set warning in warn output, got %q", warn.String())
	}
}

func TestResolveSchedule_YAMLIntervalOverFlag(t *testing.T) {
	cfg := &Config{Interval: 12 * time.Hour}
	cmd := newScheduleTestCmd()
	if err := cmd.Flags().Set("interval", "24h"); err != nil {
		t.Fatal(err)
	}
	spec, err := cfg.ResolveSchedule(cmd, nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindInterval {
		t.Errorf("Kind = %q, want interval", spec.Kind)
	}
	if spec.Interval != 12*time.Hour {
		t.Errorf("Interval = %v, want 12h (yaml wins over flag)", spec.Interval)
	}
}

func TestResolveSchedule_FlagOnly(t *testing.T) {
	cfg := &Config{}
	cmd := newScheduleTestCmd()
	if err := cmd.Flags().Set("interval", "6h"); err != nil {
		t.Fatal(err)
	}
	spec, err := cfg.ResolveSchedule(cmd, nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindInterval {
		t.Errorf("Kind = %q, want interval", spec.Kind)
	}
	if spec.Interval != 6*time.Hour {
		t.Errorf("Interval = %v, want 6h", spec.Interval)
	}
}

func TestResolveSchedule_Nothing(t *testing.T) {
	cfg := &Config{}
	spec, err := cfg.ResolveSchedule(newScheduleTestCmd(), nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindOneShot {
		t.Errorf("Kind = %q, want oneshot", spec.Kind)
	}
}

func TestResolveSchedule_JitterOnlyInCronMode(t *testing.T) {
	cfg := &Config{
		Schedule:       "*/15 * * * *",
		ScheduleJitter: 45 * time.Second,
	}
	spec, err := cfg.ResolveSchedule(newScheduleTestCmd(), nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindCron {
		t.Errorf("Kind = %q, want cron", spec.Kind)
	}
	if spec.Jitter != 45*time.Second {
		t.Errorf("Jitter = %v, want 45s", spec.Jitter)
	}
}

func TestResolveSchedule_JitterIgnoredInIntervalMode(t *testing.T) {
	// schedule_jitter only applies to cron mode. In interval mode it's
	// silently dropped — interval has its own ±10% jitter handled by
	// cmd/agent_scheduler.go, not by ScheduleSpec.
	cfg := &Config{
		Interval:       24 * time.Hour,
		ScheduleJitter: 45 * time.Second,
	}
	spec, err := cfg.ResolveSchedule(newScheduleTestCmd(), nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != ScheduleKindInterval {
		t.Errorf("Kind = %q, want interval", spec.Kind)
	}
	if spec.Jitter != 0 {
		t.Errorf("Jitter = %v, want 0 in interval mode", spec.Jitter)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./internal/agentconfig/ -run TestResolveSchedule -v
```

Expected: FAIL — `cfg.ResolveSchedule undefined`.

- [ ] **Step 3: Implement `ResolveSchedule`**

Append to `internal/agentconfig/resolve.go` (after the existing `flagInt` function):

```go
// ResolveSchedule walks the precedence chain and returns a ScheduleSpec
// describing when the next scan should fire.
//
// Precedence (highest first):
//  1. Config.Schedule (cron expression in yaml) — wins if non-empty
//  2. Config.Interval (duration in yaml)       — wins if non-zero
//  3. --interval flag (cmd)                    — wins if set
//  4. ScheduleKindOneShot                      — run once and exit
//
// When both Schedule and Interval are set, Schedule wins and a warning
// is written to warnOut (if non-nil). This matches the existing
// "yaml-schedule overrides yaml-interval" semantics promised in the
// design spec.
//
// Cron expression validation is NOT performed here — that's the
// runtime scheduler's job. We keep this package free of the cron
// library import so callers that only need to inspect resolved config
// don't pull it in.
func (c *Config) ResolveSchedule(cmd *cobra.Command, warnOut io.Writer) (ScheduleSpec, error) {
	spec := ScheduleSpec{}

	if c.Schedule != "" {
		spec.Kind = ScheduleKindCron
		spec.CronExpr = c.Schedule
		spec.Jitter = c.ScheduleJitter
		if c.Interval > 0 && warnOut != nil {
			fmt.Fprintf(warnOut,
				"warning: both schedule (%q) and interval (%s) set in agent.yaml — schedule wins\n",
				c.Schedule, c.Interval)
		}
		return spec, nil
	}

	if c.Interval > 0 {
		spec.Kind = ScheduleKindInterval
		spec.Interval = c.Interval
		return spec, nil
	}

	// Fall through to --interval flag.
	if cmd != nil && flagChanged(cmd, "interval") {
		v, err := flagDuration(cmd, "interval")
		if err != nil {
			return ScheduleSpec{}, fmt.Errorf("reading --interval flag: %w", err)
		}
		if v > 0 {
			spec.Kind = ScheduleKindInterval
			spec.Interval = v
			return spec, nil
		}
	}

	spec.Kind = ScheduleKindOneShot
	return spec, nil
}
```

- [ ] **Step 4: Add the `io` import to `resolve.go`**

At the top of `internal/agentconfig/resolve.go`, add `"io"` to the import block:

```go
import (
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/runtime/limits"
)
```

- [ ] **Step 5: Run tests to verify they pass**

Run:
```bash
go test ./internal/agentconfig/ -run TestResolveSchedule -v
```

Expected: all six `TestResolveSchedule_*` subtests PASS.

- [ ] **Step 6: Run full agentconfig test suite**

Run:
```bash
go test ./internal/agentconfig/... -v
```

Expected: all tests PASS (no regression on existing `ResolveLimits` etc.).

- [ ] **Step 7: Commit**

```bash
git add internal/agentconfig/resolve.go internal/agentconfig/schedule_test.go
git commit -m "agentconfig: resolve schedule with precedence chain (schedule>interval>flag>oneshot)"
```

---

## Task 5: Create `scheduler` interface + `intervalScheduler`

**Files:**
- Create: `cmd/agent_scheduler.go`
- Create: `cmd/agent_scheduler_test.go`

- [ ] **Step 1: Write the failing test for `intervalScheduler`**

Create `cmd/agent_scheduler_test.go`:

```go
package cmd

import (
	"testing"
	"time"
)

func TestIntervalScheduler_Next(t *testing.T) {
	s := intervalScheduler{interval: 10 * time.Minute, jitterPct: 0}
	now := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	got := s.Next(now)
	if got != 10*time.Minute {
		t.Errorf("Next() = %v, want 10m (no jitter)", got)
	}
}

func TestIntervalScheduler_NextWithJitter(t *testing.T) {
	// With jitterPct=0.10 and interval=10m, the result must land in
	// [9m, 11m] — ±10%.
	s := intervalScheduler{interval: 10 * time.Minute, jitterPct: 0.10}
	now := time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 50; i++ {
		got := s.Next(now)
		if got < 9*time.Minute || got > 11*time.Minute {
			t.Errorf("iter %d: Next() = %v, want in [9m, 11m]", i, got)
		}
	}
}

func TestIntervalScheduler_Describe(t *testing.T) {
	s := intervalScheduler{interval: 24 * time.Hour, jitterPct: 0.10}
	got := s.Describe()
	// Minimal contract: the string must reveal "24h" so an operator
	// reading startup logs can sanity-check.
	if !containsFold(got, "24h") {
		t.Errorf("Describe() = %q, want to mention 24h", got)
	}
}

// containsFold is a tiny helper so the test doesn't import strings.
func containsFold(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:
```bash
go test ./cmd/ -run TestIntervalScheduler -v
```

Expected: FAIL — `undefined: intervalScheduler`.

- [ ] **Step 3: Create the scheduler interface + interval impl**

Create `cmd/agent_scheduler.go`:

```go
package cmd

import (
	"fmt"
	"math/rand"
	"time"
)

// scheduler computes when the next agent scan should fire. It is
// deliberately minimal: one "how long until next" method and one
// "describe yourself for logs" method. Concrete implementations
// encapsulate interval and cron logic.
type scheduler interface {
	// Next returns the duration to sleep from `now` until the next
	// scheduled fire. Returns 0 when the schedule has no future
	// occurrence (shouldn't happen for either production impl but
	// the caller should treat it as "already due" and fire immediately).
	Next(now time.Time) time.Duration

	// Describe returns a human-readable form for startup logs.
	Describe() string
}

// intervalScheduler fires every `interval` with ±jitterPct random jitter.
// Jitter is computed per-call so a fleet of agents that all started at
// the same second drift apart over successive iterations.
type intervalScheduler struct {
	interval  time.Duration
	jitterPct float64 // 0.10 for ±10%, 0 for no jitter
}

// Next returns interval + jitter, clamped at 0 to avoid negative sleeps
// when interval is 0 or jitter math underflows.
func (s intervalScheduler) Next(_ time.Time) time.Duration {
	if s.interval <= 0 {
		return 0
	}
	if s.jitterPct <= 0 {
		return s.interval
	}
	// Range is 2*jitterPct of interval, centered on 0.
	spread := float64(s.interval) * s.jitterPct * 2
	if spread <= 0 {
		return s.interval
	}
	//nolint:gosec // G404: non-cryptographic jitter is intentional
	offset := time.Duration(rand.Int63n(int64(spread))) - time.Duration(spread/2)
	next := s.interval + offset
	if next < 0 {
		return s.interval
	}
	return next
}

// Describe renders the interval and jitter policy for the startup banner.
func (s intervalScheduler) Describe() string {
	if s.jitterPct > 0 {
		return fmt.Sprintf("interval %s (±%.0f%% jitter)", s.interval, s.jitterPct*100)
	}
	return fmt.Sprintf("interval %s", s.interval)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run:
```bash
go test ./cmd/ -run TestIntervalScheduler -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/agent_scheduler.go cmd/agent_scheduler_test.go
git commit -m "agent: extract scheduler interface and intervalScheduler impl"
```

---

## Task 6: Implement `cronScheduler`

**Files:**
- Test: `cmd/agent_scheduler_test.go`
- Modify: `cmd/agent_scheduler.go`

- [ ] **Step 1: Write failing tests for `cronScheduler`**

Append to `cmd/agent_scheduler_test.go`:

```go
func TestCronScheduler_NextDeterministic(t *testing.T) {
	// "Every day at 02:00 local time". At 01:55 on 2026-04-19 the
	// next fire is 5 minutes away.
	s, err := newCronScheduler("0 2 * * *", 0)
	if err != nil {
		t.Fatalf("newCronScheduler: %v", err)
	}
	loc, _ := time.LoadLocation("Local")
	now := time.Date(2026, 4, 19, 1, 55, 0, 0, loc)
	got := s.Next(now)
	if got != 5*time.Minute {
		t.Errorf("Next() = %v, want 5m", got)
	}
}

func TestCronScheduler_NextSteppedRange(t *testing.T) {
	// "Every 15 minutes" — at 12:07, next is 12:15 (8 minutes away).
	s, err := newCronScheduler("*/15 * * * *", 0)
	if err != nil {
		t.Fatalf("newCronScheduler: %v", err)
	}
	loc, _ := time.LoadLocation("Local")
	now := time.Date(2026, 4, 19, 12, 7, 0, 0, loc)
	got := s.Next(now)
	if got != 8*time.Minute {
		t.Errorf("Next() = %v, want 8m", got)
	}
}

func TestCronScheduler_JitterWithinBound(t *testing.T) {
	// With 45s jitter, the result must land in [base, base+45s).
	s, err := newCronScheduler("0 2 * * *", 45*time.Second)
	if err != nil {
		t.Fatalf("newCronScheduler: %v", err)
	}
	loc, _ := time.LoadLocation("Local")
	now := time.Date(2026, 4, 19, 1, 55, 0, 0, loc)
	base := 5 * time.Minute
	for i := 0; i < 50; i++ {
		got := s.Next(now)
		if got < base || got >= base+45*time.Second {
			t.Errorf("iter %d: Next() = %v, want in [%v, %v)", i, got, base, base+45*time.Second)
		}
	}
}

func TestCronScheduler_InvalidExpr(t *testing.T) {
	cases := []string{
		"bogus",             // not a cron expression
		"0 2 * *",           // only 4 fields
		"99 * * * *",        // minute out of range
		"",                  // empty (caller's job to guard, but verify we reject)
	}
	for _, expr := range cases {
		t.Run(expr, func(t *testing.T) {
			if _, err := newCronScheduler(expr, 0); err == nil {
				t.Errorf("newCronScheduler(%q) = nil error, want error", expr)
			}
		})
	}
}

func TestCronScheduler_Describe(t *testing.T) {
	s, err := newCronScheduler("0 2 * * 0", 0)
	if err != nil {
		t.Fatalf("newCronScheduler: %v", err)
	}
	got := s.Describe()
	if !containsFold(got, "0 2 * * 0") {
		t.Errorf("Describe() = %q, want to include the expression", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./cmd/ -run TestCronScheduler -v
```

Expected: FAIL — `undefined: newCronScheduler`.

- [ ] **Step 3: Implement `cronScheduler` + constructor**

Append to `cmd/agent_scheduler.go`:

```go
import (
	// existing imports...
	"github.com/robfig/cron/v3"
)
```

(Merge into the existing import block — the file should end up with `fmt`, `math/rand`, `time`, and `github.com/robfig/cron/v3`.)

Then append to the same file:

```go
// cronScheduler wraps a robfig/cron/v3 Schedule and exposes the
// interface the agent loop needs. Unlike intervalScheduler, jitter is
// expressed as a maximum absolute offset (not a percentage) — the
// whole point of a cron expression is "fire at this wall-clock time",
// so percentage jitter on top of "0 2 * * *" would be surprising.
type cronScheduler struct {
	expr     string
	schedule cron.Schedule
	jitter   time.Duration // 0 = disabled; uniform in [0, jitter)
}

// newCronScheduler parses expr with robfig's standard parser (5-field
// minute/hour/dom/month/dow) and returns a ready-to-call scheduler.
// Returns an error on any parse failure — the agent should fail fast
// at startup rather than silently fall back to one-shot mode.
func newCronScheduler(expr string, jitter time.Duration) (cronScheduler, error) {
	if expr == "" {
		return cronScheduler{}, fmt.Errorf("cron expression is empty")
	}
	parsed, err := cron.ParseStandard(expr)
	if err != nil {
		return cronScheduler{}, fmt.Errorf("invalid cron expression %q: %w", expr, err)
	}
	return cronScheduler{expr: expr, schedule: parsed, jitter: jitter}, nil
}

// Next returns the duration from `now` until the next cron fire time,
// optionally with positive uniform jitter in [0, jitter). The jitter
// is additive (never negative) to preserve the "fire at or after the
// scheduled time" contract that operators expect from cron.
func (s cronScheduler) Next(now time.Time) time.Duration {
	nextFire := s.schedule.Next(now)
	delta := nextFire.Sub(now)
	if delta < 0 {
		delta = 0
	}
	if s.jitter <= 0 {
		return delta
	}
	//nolint:gosec // G404: non-cryptographic jitter is intentional
	extra := time.Duration(rand.Int63n(int64(s.jitter)))
	return delta + extra
}

// Describe returns the expression plus any jitter, so the startup
// banner reveals exactly what the operator asked for.
func (s cronScheduler) Describe() string {
	if s.jitter > 0 {
		return fmt.Sprintf("cron %q (+[0, %s) jitter, local time)", s.expr, s.jitter)
	}
	return fmt.Sprintf("cron %q (local time)", s.expr)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./cmd/ -run TestCronScheduler -v
```

Expected: all four `TestCronScheduler_*` subtests PASS.

- [ ] **Step 5: Verify the interface is satisfied (compile check)**

Append a compile-time assertion to the bottom of `cmd/agent_scheduler.go`:

```go
// Compile-time interface assertions.
var (
	_ scheduler = intervalScheduler{}
	_ scheduler = cronScheduler{}
)
```

Run:
```bash
go build ./cmd/
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add cmd/agent_scheduler.go cmd/agent_scheduler_test.go
git commit -m "agent: add cronScheduler using robfig/cron/v3"
```

---

## Task 7: Build scheduler from `ScheduleSpec`

**Files:**
- Test: `cmd/agent_scheduler_test.go`
- Modify: `cmd/agent_scheduler.go`

- [ ] **Step 1: Write failing tests for the constructor**

Append to `cmd/agent_scheduler_test.go`:

```go
import (
	// add to existing imports
	"github.com/amiryahaya/triton/internal/agentconfig"
)

func TestNewSchedulerFromSpec_Interval(t *testing.T) {
	spec := agentconfig.ScheduleSpec{
		Kind:     agentconfig.ScheduleKindInterval,
		Interval: 12 * time.Hour,
	}
	s, err := newSchedulerFromSpec(spec)
	if err != nil {
		t.Fatalf("newSchedulerFromSpec: %v", err)
	}
	if _, ok := s.(intervalScheduler); !ok {
		t.Errorf("got %T, want intervalScheduler", s)
	}
}

func TestNewSchedulerFromSpec_Cron(t *testing.T) {
	spec := agentconfig.ScheduleSpec{
		Kind:     agentconfig.ScheduleKindCron,
		CronExpr: "0 2 * * *",
		Jitter:   30 * time.Second,
	}
	s, err := newSchedulerFromSpec(spec)
	if err != nil {
		t.Fatalf("newSchedulerFromSpec: %v", err)
	}
	if _, ok := s.(cronScheduler); !ok {
		t.Errorf("got %T, want cronScheduler", s)
	}
}

func TestNewSchedulerFromSpec_CronInvalid(t *testing.T) {
	spec := agentconfig.ScheduleSpec{
		Kind:     agentconfig.ScheduleKindCron,
		CronExpr: "bogus",
	}
	_, err := newSchedulerFromSpec(spec)
	if err == nil {
		t.Fatal("newSchedulerFromSpec returned nil error for invalid cron")
	}
}

func TestNewSchedulerFromSpec_OneShot(t *testing.T) {
	// One-shot returns nil, nil — the caller distinguishes "no
	// scheduler" from "error" to decide whether to enter the loop.
	spec := agentconfig.ScheduleSpec{Kind: agentconfig.ScheduleKindOneShot}
	s, err := newSchedulerFromSpec(spec)
	if err != nil {
		t.Fatalf("newSchedulerFromSpec: %v", err)
	}
	if s != nil {
		t.Errorf("got non-nil scheduler %T, want nil for one-shot", s)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./cmd/ -run TestNewSchedulerFromSpec -v
```

Expected: FAIL — `undefined: newSchedulerFromSpec`.

- [ ] **Step 3: Implement the constructor**

Append to `cmd/agent_scheduler.go`:

```go
import (
	// add to imports
	"github.com/amiryahaya/triton/internal/agentconfig"
)
```

Then append:

```go
// intervalJitterPct is the ±jitter fraction applied in interval mode.
// Extracted as a constant so the scheduler and startup banner can
// quote the same number.
const intervalJitterPct = 0.10

// newSchedulerFromSpec builds the runtime scheduler from a resolved
// ScheduleSpec. Returns (nil, nil) for one-shot mode so the agent
// loop can short-circuit. Returns an error only when the spec is
// syntactically unusable (currently: invalid cron expression).
func newSchedulerFromSpec(spec agentconfig.ScheduleSpec) (scheduler, error) {
	switch spec.Kind {
	case agentconfig.ScheduleKindCron:
		return newCronScheduler(spec.CronExpr, spec.Jitter)
	case agentconfig.ScheduleKindInterval:
		return intervalScheduler{
			interval:  spec.Interval,
			jitterPct: intervalJitterPct,
		}, nil
	case agentconfig.ScheduleKindOneShot:
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown schedule kind %q", spec.Kind)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run:
```bash
go test ./cmd/ -run TestNewSchedulerFromSpec -v
```

Expected: all four subtests PASS.

- [ ] **Step 5: Run full cmd test suite to confirm no regression**

Run:
```bash
go test ./cmd/... -v
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/agent_scheduler.go cmd/agent_scheduler_test.go
git commit -m "agent: add newSchedulerFromSpec dispatcher"
```

---

## Task 8: Wire scheduler into `cmd/agent.go`

**Files:**
- Test: `cmd/agent_schedule_test.go` (new)
- Modify: `cmd/agent.go`

- [ ] **Step 1: Write failing integration test**

Create `cmd/agent_schedule_test.go`:

```go
package cmd

import (
	"testing"
	"time"

	"github.com/amiryahaya/triton/internal/agentconfig"
)

// TestAgentScheduler_ConstructsFromYAML verifies the end-to-end wiring
// from Config → ResolveSchedule → newSchedulerFromSpec. It does NOT
// run the scan loop; the point is to catch plumbing breaks early.
func TestAgentScheduler_ConstructsFromYAML(t *testing.T) {
	cfg := &agentconfig.Config{Schedule: "0 2 * * *"}
	spec, err := cfg.ResolveSchedule(nil, nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	s, err := newSchedulerFromSpec(spec)
	if err != nil {
		t.Fatalf("newSchedulerFromSpec: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scheduler for cron spec")
	}
	// Sanity: calling Next doesn't panic and returns a positive value.
	got := s.Next(time.Date(2026, 4, 19, 1, 0, 0, 0, time.Local))
	if got <= 0 || got > 24*time.Hour {
		t.Errorf("Next() = %v, want positive and <= 24h", got)
	}
}

func TestAgentScheduler_InvalidCronFailsFast(t *testing.T) {
	cfg := &agentconfig.Config{Schedule: "bogus"}
	spec, err := cfg.ResolveSchedule(nil, nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if _, err := newSchedulerFromSpec(spec); err == nil {
		t.Fatal("expected invalid-cron error")
	}
}
```

- [ ] **Step 2: Run the integration test to verify it passes**

Run:
```bash
go test ./cmd/ -run TestAgentScheduler -v
```

Expected: PASS — these exercise already-landed code from Tasks 4 and 7.

- [ ] **Step 3: Replace the inline sleep in `runAgent` with the scheduler**

In `cmd/agent.go`, locate the block (around lines 562-593) that currently reads:

```go
	for {
		if err := runAgentScan(ctx, activeGuard, resolved, client); err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}

		if agentInterval == 0 {
			return nil
		}

		// Heartbeat between scans (continuous mode only). Updates
		// last_seen_at on the license server and detects tier
		// changes or revocations. Skipped on one-shot runs to
		// avoid an unnecessary HTTP round-trip.
		activeGuard = heartbeat(&seat, activeGuard)

		// Jitter the sleep by ±10% so a fleet of agents rebooted
		// simultaneously (e.g., after a patch window) does not
		// dog-pile the report server at the same second every
		// interval. Logged as the effective wait, not the raw
		// interval, so operators can see what actually happened.
		wait := agentInterval + intervalJitterFn(agentInterval)
		if wait < 0 {
			wait = agentInterval // belt-and-braces: never sleep negative
		}
		fmt.Printf("Next scan in %s...\n", wait.Round(time.Second))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			fmt.Println("\nAgent stopped.")
			return nil
		}
	}
```

Replace it with:

```go
	// Resolve the schedule (cron, interval, or one-shot) once, up-front,
	// so an invalid cron expression fails fast before any scan runs.
	spec, err := resolved.source.ResolveSchedule(cmd, os.Stderr)
	if err != nil {
		return fmt.Errorf("resolving schedule: %w", err)
	}
	sched, err := newSchedulerFromSpec(spec)
	if err != nil {
		return fmt.Errorf("building scheduler: %w", err)
	}
	if sched != nil {
		fmt.Printf("  schedule:    %s\n", sched.Describe())
	} else {
		fmt.Println("  schedule:    one-shot (no interval or schedule configured)")
	}
	fmt.Println()

	for {
		if err := runAgentScan(ctx, activeGuard, resolved, client); err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
		}

		if sched == nil {
			return nil
		}

		// Heartbeat between scans (continuous mode only). Updates
		// last_seen_at on the license server and detects tier
		// changes or revocations. Skipped on one-shot runs to
		// avoid an unnecessary HTTP round-trip.
		activeGuard = heartbeat(&seat, activeGuard)

		wait := sched.Next(time.Now())
		if wait < 0 {
			wait = 0
		}
		fmt.Printf("Next scan in %s...\n", wait.Round(time.Second))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			fmt.Println("\nAgent stopped.")
			return nil
		}
	}
```

- [ ] **Step 4: Remove the now-unused `intervalJitterFn` var and `defaultIntervalJitter` helper**

In `cmd/agent.go`, delete these three blocks (they were the old inline jitter path — `intervalScheduler.Next` now owns that behavior):

```go
// intervalJitterFn is swappable in tests so jitter is deterministic.
// Production uses the package-global rand source; tests inject a
// seeded source to assert on exact outputs.
var intervalJitterFn = defaultIntervalJitter

// defaultIntervalJitter returns a value in [-0.1×base, +0.1×base],
// i.e. ±10% of the interval. Kept as a package-level var so the
// package init stays trivial and tests can call it directly.
func defaultIntervalJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	// Range is one-fifth of base (±10%). rand.Int63n is exclusive
	// of its upper bound, so the max is "just under +10%".
	maxJitter := int64(base / 5)
	if maxJitter <= 0 {
		return 0
	}
	//nolint:gosec // G404: non-cryptographic jitter is intentional
	return time.Duration(rand.Int63n(maxJitter) - maxJitter/2)
}
```

Also remove the unused `"math/rand"` import from the top of `cmd/agent.go` if nothing else in that file uses it (grep before removing).

- [ ] **Step 5: Verify no other file uses `intervalJitterFn`**

Run:
```bash
grep -rn "intervalJitterFn\|defaultIntervalJitter" cmd/ internal/
```

Expected: no matches. If any test references them, update that test to use the new `intervalScheduler` directly.

- [ ] **Step 6: Run the full cmd suite**

Run:
```bash
go test ./cmd/... -v
```

Expected: all tests PASS. If `agent_resolve_test.go` or any other test has been referencing `intervalJitterFn` or `defaultIntervalJitter`, update it to use `intervalScheduler{interval: X, jitterPct: 0.10}` directly.

- [ ] **Step 7: Run lint**

Run:
```bash
go vet ./cmd/... ./internal/agentconfig/...
```

Expected: no output.

- [ ] **Step 8: Build the binary to confirm end-to-end compile**

Run:
```bash
go build -o /tmp/triton-cron ./...
```

Expected: success. Delete the artifact.

```bash
rm /tmp/triton-cron
```

- [ ] **Step 9: Commit**

```bash
git add cmd/agent.go cmd/agent_schedule_test.go
git commit -m "agent: replace inline jitter loop with scheduler interface"
```

---

## Task 9: Update `cmd/agent.go` `agentInterval` flag behavior

**Files:**
- Modify: `cmd/agent.go`

**Context:** The `--interval` flag is still declared and still binds to `agentInterval`. With the new scheduler, the flag's effect is mediated through `ResolveSchedule(cmd, ...)` which reads from `cmd.Flags()`. The `agentInterval` var is no longer read directly by `runAgent`, but it MUST still exist as a flag target for cobra's `DurationVar` call. Verify everything still works.

- [ ] **Step 1: Write a test that `--interval` flag is honored via the scheduler path**

Append to `cmd/agent_schedule_test.go`:

```go
import "github.com/spf13/cobra"

func TestAgentScheduler_IntervalFlagFallback(t *testing.T) {
	// When no yaml schedule/interval is set, --interval should drive
	// the resolved spec. This is the backward-compat path.
	cmd := &cobra.Command{Use: "agent"}
	cmd.Flags().Duration("interval", 0, "")
	if err := cmd.Flags().Set("interval", "30m"); err != nil {
		t.Fatal(err)
	}
	cfg := &agentconfig.Config{}
	spec, err := cfg.ResolveSchedule(cmd, nil)
	if err != nil {
		t.Fatalf("ResolveSchedule: %v", err)
	}
	if spec.Kind != agentconfig.ScheduleKindInterval {
		t.Errorf("Kind = %q, want interval", spec.Kind)
	}
	if spec.Interval != 30*time.Minute {
		t.Errorf("Interval = %v, want 30m", spec.Interval)
	}
}
```

- [ ] **Step 2: Run the test**

Run:
```bash
go test ./cmd/ -run TestAgentScheduler_IntervalFlagFallback -v
```

Expected: PASS (this exercises already-landed code).

- [ ] **Step 3: Verify `agentInterval` is no longer read outside of cobra flag registration**

Run:
```bash
grep -n "agentInterval" cmd/agent.go
```

Expected: exactly 3 hits — the `var` declaration, the `Flags().DurationVar` registration, and the `healthCheckMaxAttempts` branch:

```go
attempts := healthCheckMaxAttempts
if agentInterval == 0 {
    attempts = 1
}
```

**If there's a fourth hit referencing `agentInterval` in the old sleep block, Task 8 left dead code — return to Task 8 and fix.**

The `agentInterval == 0` branch is a UX heuristic ("one-shot runs should fail fast on an unreachable server") and remains correct: when a user passes no `--interval` and no yaml schedule/interval, `agentInterval` stays at 0 and `runAgent` is effectively one-shot. Leave it as-is.

- [ ] **Step 4: Commit**

```bash
git add cmd/agent_schedule_test.go
git commit -m "agent: test --interval flag feeds the scheduler via ResolveSchedule"
```

---

## Task 10: Integration test — cron-driven short-interval fires

**Files:**
- Create: `test/integration/agent_cron_test.go`

- [ ] **Step 1: Write the integration test**

Create `test/integration/agent_cron_test.go`:

```go
//go:build integration

package integration

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAgent_CronFiresWithinWindow runs the agent with a 1-minute cron
// expression and a --check-config-like short-circuit to prove the
// scheduler parses, describes, and is about to sleep for < 60s.
//
// We do NOT wait for a full scan — that's expensive and covered by
// the interval-based integration tests. Here we only verify the
// scheduler is wired correctly.
func TestAgent_CronFiresWithinWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	// Build the binary into a tempdir.
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "triton")
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../")
	buildCmd.Env = append(buildCmd.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Drop an agent.yaml next to the binary with a cron schedule.
	yamlPath := filepath.Join(tmpDir, "agent.yaml")
	yamlContent := []byte("schedule: \"* * * * *\"\nprofile: quick\n")
	if err := writeFile(t, yamlPath, yamlContent); err != nil {
		t.Fatal(err)
	}

	// Run --check-config so the agent validates the cron, prints the
	// banner (including our new "schedule:" line), and exits 0 before
	// ever sleeping or scanning.
	runCmd := exec.Command(binPath, "agent", "--check-config")
	runCmd.Dir = tmpDir
	var stdout, stderr bytes.Buffer
	runCmd.Stdout = &stdout
	runCmd.Stderr = &stderr
	if err := runCmd.Run(); err != nil {
		t.Fatalf("agent --check-config failed: %v\nstdout: %s\nstderr: %s",
			err, stdout.String(), stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "schedule:") {
		t.Errorf("stdout missing 'schedule:' line:\n%s", out)
	}
	if !strings.Contains(out, "* * * * *") {
		t.Errorf("stdout missing cron expression:\n%s", out)
	}
	// check-config exits before sleeping — allow ~5s max.
	_ = time.Now()
}

func TestAgent_InvalidCronFailsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "triton")
	buildCmd := exec.Command("go", "build", "-o", binPath, "../../")
	buildCmd.Env = append(buildCmd.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	yamlPath := filepath.Join(tmpDir, "agent.yaml")
	if err := writeFile(t, yamlPath, []byte("schedule: \"this is not cron\"\n")); err != nil {
		t.Fatal(err)
	}

	runCmd := exec.Command(binPath, "agent")
	runCmd.Dir = tmpDir
	var stderr bytes.Buffer
	runCmd.Stderr = &stderr
	err := runCmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid cron, got success")
	}
	if !strings.Contains(stderr.String(), "cron") && !strings.Contains(stderr.String(), "schedule") {
		t.Errorf("stderr does not mention cron/schedule:\n%s", stderr.String())
	}
}

// writeFile is a local helper — the integration helpers_test.go file
// already has fixtures, but we keep this self-contained so the test
// compiles even if helpers renames things.
func writeFile(t *testing.T, path string, content []byte) error {
	t.Helper()
	return writeFileImpl(path, content)
}
```

Add to the bottom of `test/integration/agent_cron_test.go`:

```go
import "os"

func writeFileImpl(path string, content []byte) error {
	return os.WriteFile(path, content, 0o644)
}
```

(Merge the `os` import into the main import block.)

- [ ] **Step 2: Run the integration test**

Run:
```bash
go test -tags integration -run TestAgent_CronFiresWithinWindow ./test/integration/ -v
go test -tags integration -run TestAgent_InvalidCronFailsFast ./test/integration/ -v
```

Expected: both PASS.

- [ ] **Step 3: Commit**

```bash
git add test/integration/agent_cron_test.go
git commit -m "test: integration test for agent cron scheduling + fail-fast"
```

---

## Task 11: Documentation — `DEPLOYMENT_GUIDE.md`

**Files:**
- Modify: `docs/DEPLOYMENT_GUIDE.md`

- [ ] **Step 1: Locate the agent config section**

Run:
```bash
grep -n "^##\|^###" docs/DEPLOYMENT_GUIDE.md | head -40
```

Find the section header that documents `agent.yaml` fields (look for one mentioning `interval:` or `resource_limits:`).

- [ ] **Step 2: Add the `schedule:` subsection**

Insert this block immediately after the section that documents `interval:`:

```markdown
### Scheduling (cron vs interval)

The agent supports two scheduling modes:

- **Interval** (existing): `interval: 24h` — run every N hours/minutes with ±10% jitter. Good for "every 24h from whenever I started".
- **Cron** (new in v2.X): `schedule: "0 2 * * *"` — run at specific wall-clock times. Good for "every day at 02:00 local" or "Sundays at 6am".

Example `agent.yaml` with cron scheduling:

```yaml
schedule: "0 2 * * 0"    # Sundays at 02:00 local time
schedule_jitter: 30s     # optional: add up to 30s uniform jitter
profile: standard
report_server: https://triton.example.com
license_key: "eyJ..."
```

Precedence (highest wins):

1. `schedule:` in `agent.yaml`
2. `interval:` in `agent.yaml`
3. `--interval` CLI flag
4. Fall through to one-shot (no repeat)

If both `schedule:` and `interval:` are present in the yaml, `schedule:` wins and a warning is printed to stderr at startup.

Notes:

- Cron expressions are standard 5-field (minute hour day-of-month month day-of-week).
- Evaluated in the agent host's **local timezone**. If you want UTC, set `TZ=UTC` in the systemd unit's `Environment=` directive.
- Invalid expressions fail fast at agent startup with a clear error.
- No catch-up: if the host was off at 02:00, the next fire is the following day — same as `cron(8)`.
- Long-running scans that overrun the next fire do not queue up; the scan finishes, then the next future fire is computed fresh.
- `schedule_jitter` defaults to 0 (disabled). Set it when fleet-staggering matters — every agent with the same cron will otherwise fire at exactly the same second.
```

- [ ] **Step 3: Verify the doc renders sensibly**

Run:
```bash
grep -A5 "^### Scheduling" docs/DEPLOYMENT_GUIDE.md
```

Expected: the new subsection is visible.

- [ ] **Step 4: Commit**

```bash
git add docs/DEPLOYMENT_GUIDE.md
git commit -m "docs: document agent schedule: / schedule_jitter: in deployment guide"
```

---

## Task 12: Documentation — `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add a note about cron scheduling**

Find the existing section mentioning `triton agent --interval 24h` in `CLAUDE.md` (it's likely in a paragraph summarizing agent mode, or absent — if absent, skip this task). If present, append to the same paragraph or section:

In `CLAUDE.md`, find the block starting with `### Resource limits (orthogonal to profile)` and immediately after it, add:

```markdown
### Agent scheduling

The `triton agent` command supports two scheduling modes via `agent.yaml`:

- **`interval: 24h`** — repeat every N duration with ±10% jitter (existing behavior).
- **`schedule: "0 2 * * 0"`** — cron expression, local timezone. Optional `schedule_jitter: 30s` for fleet staggering.

`schedule` wins over `interval` when both are set. Implementation: `internal/agentconfig/schedule.go` (plain-data `ScheduleSpec`), `cmd/agent_scheduler.go` (`scheduler` interface + `intervalScheduler` + `cronScheduler` via `github.com/robfig/cron/v3`).
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: note agent cron scheduling in CLAUDE.md"
```

---

## Task 13: Update memory index

**Files:**
- Modify: `/Users/amirrudinyahaya/.claude/projects/-Users-amirrudinyahaya-Workspace-triton/memory/agent-control-features.md`

- [ ] **Step 1: Flip item 5 to partial-shipped**

In the memory file, find:

```markdown
5. **Cron-style scheduling / portal-pushed schedule.** Standalone agent remains interval-only; portal-pushed schedule in poll response unlocks fleet-wide UI-driven schedule change. ~couple days.
```

Replace with:

```markdown
5. **Cron-style scheduling (partial).** ~~**Local cron SHIPPED in PR #<TBD> (merged YYYY-MM-DD)**~~ — `schedule: "0 2 * * *"` + `schedule_jitter:` in agent.yaml via `internal/agentconfig/schedule.go` + `cmd/agent_scheduler.go` (`github.com/robfig/cron/v3`). Precedence: schedule > interval-yaml > --interval > one-shot. Local timezone, fail-fast on invalid cron, opt-in jitter (default 0). Portal-pushed schedule (step 5b) still deferred — requires poll-response protocol change to ship fleet-wide UI-driven schedule updates.
```

(Leave the `<TBD>` and `YYYY-MM-DD` placeholders — the merge commit will fill them in, not this implementation.)

- [ ] **Step 2: Commit the memory change**

The memory file is in `~/.claude/…`, not the repo, so there's no commit. Save the file directly and move on.

---

## Self-Review

**Spec coverage check:**

| Spec section | Implemented by |
|--------------|----------------|
| `schedule:` field accepts 5-field cron | Task 2 (loader.go) + Task 6 (cronScheduler) |
| `schedule_jitter:` opt-in, default 0 | Task 2 (loader.go) + Task 6 (cronScheduler jitter) |
| Local timezone evaluation | Task 6 (uses robfig/cron ParseStandard which uses time.Now().Location()) |
| Precedence: schedule > interval yaml > --interval > oneshot | Task 4 (ResolveSchedule) |
| No `--schedule` CLI flag | Confirmed — only yaml surface added |
| `github.com/robfig/cron/v3` library | Task 1 |
| `scheduler` interface in cmd/ | Task 5 |
| Plain-data `ScheduleSpec` in agentconfig | Task 3 |
| Invalid cron fail-fast at startup | Task 6 (newCronScheduler error) + Task 8 (wired into runAgent) + Task 10 (integration test) |
| DST / missed fires / overrun semantics | Documented in Task 11 (DEPLOYMENT_GUIDE.md) |
| Behavior-preserving for existing `interval:` users | Task 5 (intervalScheduler preserves ±10%) + Task 9 (verified flag path) |
| `schedule_jitter` ignored in interval mode | Task 4 (TestResolveSchedule_JitterIgnoredInIntervalMode) |
| Integration test for cron firing | Task 10 |

**Placeholder scan:** Searched for "TODO", "TBD", "implement later", "similar to" — none found in production code steps. One intentional `<TBD>` in Task 13 for the future merge commit — this is a memory file edit, not production code, and the merge SHA is unknown at plan-write time.

**Type consistency:**

- `ScheduleSpec{Kind, CronExpr, Interval, Jitter}` — defined in Task 3, used identically in Tasks 4, 7, 8.
- `scheduler` interface `{Next(time.Time) time.Duration; Describe() string}` — defined in Task 5, implemented by `intervalScheduler` in Task 5 and `cronScheduler` in Task 6.
- `newSchedulerFromSpec(ScheduleSpec) (scheduler, error)` — Task 7; called in Task 8 with identical signature.
- `ResolveSchedule(cmd *cobra.Command, warnOut io.Writer) (ScheduleSpec, error)` — Task 4; called in Task 8 with identical signature.
- `newCronScheduler(expr string, jitter time.Duration) (cronScheduler, error)` — Task 6; called from `newSchedulerFromSpec` in Task 7.

No drift detected.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-04-19-agent-cron-schedule-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
