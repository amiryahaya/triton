# Agent Resource Limits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface PR #71's resource-limit primitives to `triton agent` via a new `resource_limits:` block in `agent.yaml`. Each scan iteration applies the limits before `eng.Scan` runs.

**Architecture:** No new packages. Add a `ResourceLimits` field to `agentconfig.Config`, a `ResolveLimits(cmd)` helper that merges CLI flag overrides with yaml per existing agent precedence rules, and a one-line `lim.Apply(ctx)` call in `runAgentScan` before the scan starts. Each iteration gets a fresh context + watchdog; cleanup tears them down per-iteration.

**Tech Stack:** Go 1.25, `internal/runtime/limits/` (unchanged from PR #71), `internal/agentconfig/` (extended), `cmd/agent.go` (one integration point).

**Spec:** `docs/plans/2026-04-19-agent-resource-limits-design.md` (committed at `7f5ebc4`).

---

## File Structure

**Modify:**
- `internal/agentconfig/loader.go` — add `ResourceLimits *ResourceLimitsConfig` field + `ResourceLimitsConfig` struct with yaml tags
- `internal/agentconfig/loader_test.go` — YAML round-trip test
- `internal/agentconfig/resolve.go` — add `ResolveLimits(cmd *cobra.Command) (limits.Limits, error)` method
- `internal/agentconfig/resolve_test.go` — new tests (create if file doesn't exist)
- `cmd/agent.go`:
  - Add `Limits limits.Limits` field to `resolvedAgentConfig` struct
  - Call `ResolveLimits` in `resolveAgentConfig` to populate the new field
  - In `runAgentScan`, call `lim := r.Limits; ctx, cleanup := lim.Apply(ctx); defer cleanup()` before engine scan
  - Print `Resource <limits.String()>` at iteration start when enabled
- `docs/DEPLOYMENT_GUIDE.md` — add "Kernel-enforced resource limits via systemd unit" subsection under the agent deployment section
- `docs/examples/agent.yaml.example` — add commented `resource_limits:` block (create the file if absent)
- `README.md` — brief mention under agent docs
- `CLAUDE.md` — single-line reference under the existing agent subsection

**Create:** None (no new packages or source files).

---

## Testing Notes for the Implementer

**The agent test fixtures.** `internal/agentconfig/loader_test.go` already has YAML-loading tests. Follow the existing test style (table-driven tests with `t.TempDir()` + `os.WriteFile`). See `TestLoad_NoFileReturnsZeroConfig` for the template.

**`limits.Limits` is from PR #71.** Import as `"github.com/amiryahaya/triton/internal/runtime/limits"`. The struct has `MaxMemoryBytes int64`, `MaxCPUPercent int`, `MaxDuration time.Duration`, `StopAtOffset time.Duration`, `Nice int`. Its `Apply(ctx) (ctx, cleanup)` method is what we call in the agent path. Look at `internal/runtime/limits/limits.go` to confirm before writing wire-up.

**Flag precedence via `cmd.Flags().Changed(name)`.** Cobra distinguishes "flag present with default value" from "operator explicitly set the flag." Use `Changed()` to detect explicit overrides. Match the existing pattern for `--profile` in the same file:

```go
// Existing agent precedence example:
if cmd.Flags().Changed("profile") {
    requestedProfile = profile   // CLI wins
} else if source.Profile != "" {
    requestedProfile = source.Profile  // yaml
} else {
    requestedProfile = "quick"  // default
}
```

Use the same pattern for `max-memory`, `max-cpu-percent`, `max-duration`, `stop-at`, `nice`.

**CLI flags already exist.** The flags `--max-memory`, `--max-cpu-percent`, `--max-duration`, `--stop-at`, `--nice` are registered as **PersistentFlags on `rootCmd`** by PR #71. They inherit down to `triton agent` automatically — we don't re-register them. Just read via `cmd.Flags().GetString("max-memory")` etc.

**Integration test timing.** The integration test uses `max_duration: 2s` + runs `triton agent --interval 1m` as a subprocess. Expected behavior: scan starts, deadline fires at 2s, scan exits with partial/empty results, agent prints error, waits for interval, then we SIGTERM. Give the test `-timeout 60s` and measure the wall-clock of iteration 1 to confirm it's <10s (not hanging).

**Race detector.** The watchdog goroutine from PR #71 already passes `-race`. Our changes add no new concurrency — only plumbing. Should be clean.

---

## Task 1: Add `ResourceLimitsConfig` struct + YAML round-trip

**Files:**
- Modify: `internal/agentconfig/loader.go`
- Modify: `internal/agentconfig/loader_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/agentconfig/loader_test.go`:

```go
func TestLoad_ResourceLimits_YAMLRoundTrip(t *testing.T) {
	yaml := []byte(`
license_key: "test-token"
profile: standard
resource_limits:
  max_memory: 2GB
  max_cpu_percent: 50
  max_duration: 4h
  stop_at: "03:00"
  nice: 10
`)
	tmp := t.TempDir()
	path := filepath.Join(tmp, DefaultFileName)
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadFile(path)
	if err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	if cfg.ResourceLimits == nil {
		t.Fatal("ResourceLimits should be non-nil when yaml block is present")
	}
	if cfg.ResourceLimits.MaxMemory != "2GB" {
		t.Errorf("MaxMemory: got %q, want 2GB", cfg.ResourceLimits.MaxMemory)
	}
	if cfg.ResourceLimits.MaxCPUPercent != 50 {
		t.Errorf("MaxCPUPercent: got %d, want 50", cfg.ResourceLimits.MaxCPUPercent)
	}
	if cfg.ResourceLimits.MaxDuration != 4*time.Hour {
		t.Errorf("MaxDuration: got %v, want 4h", cfg.ResourceLimits.MaxDuration)
	}
	if cfg.ResourceLimits.StopAt != "03:00" {
		t.Errorf("StopAt: got %q, want 03:00", cfg.ResourceLimits.StopAt)
	}
	if cfg.ResourceLimits.Nice != 10 {
		t.Errorf("Nice: got %d, want 10", cfg.ResourceLimits.Nice)
	}
}

func TestLoad_ResourceLimits_AbsentYieldsNil(t *testing.T) {
	yaml := []byte(`
license_key: "test-token"
profile: standard
`)
	tmp := t.TempDir()
	path := filepath.Join(tmp, DefaultFileName)
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ResourceLimits != nil {
		t.Errorf("ResourceLimits should be nil when block absent, got %+v", cfg.ResourceLimits)
	}
}
```

Imports to add (if missing): `"path/filepath"`, `"os"`, `"time"`.

- [ ] **Step 2: Verify red**

Run: `go test ./internal/agentconfig/... -v -run ResourceLimits`
Expected: FAIL — `Config` has no `ResourceLimits` field.

- [ ] **Step 3: Implement**

In `internal/agentconfig/loader.go`, add the new struct AFTER the `Config` struct definition (after the `loadedFrom` field declaration's closing `}`):

```go
// ResourceLimitsConfig is the agent.yaml `resource_limits:` block.
// Every field is optional; zero/empty values mean "no limit" for that
// dimension. Applied per-iteration by cmd/agent.go::runAgentScan via
// internal/runtime/limits.Limits.Apply. See
// docs/plans/2026-04-19-agent-resource-limits-design.md for the full
// model.
type ResourceLimitsConfig struct {
	MaxMemory     string        `yaml:"max_memory,omitempty"`
	MaxCPUPercent int           `yaml:"max_cpu_percent,omitempty"`
	MaxDuration   time.Duration `yaml:"max_duration,omitempty"`
	StopAt        string        `yaml:"stop_at,omitempty"`
	Nice          int           `yaml:"nice,omitempty"`
}
```

And add the field on `Config` — inside the `Config struct { ... }` block, before the `loadedFrom` private field at the bottom:

```go
	// ResourceLimits caps memory, CPU, duration, nice on each scan
	// iteration. Nil means "no limits" (backward compatible). When
	// set, the agent builds a limits.Limits via ResolveLimits and
	// calls lim.Apply(ctx) before eng.Scan.
	ResourceLimits *ResourceLimitsConfig `yaml:"resource_limits,omitempty"`
```

Add `"time"` to the imports if not already present.

- [ ] **Step 4: Verify green**

Run: `go test ./internal/agentconfig/... -v -run ResourceLimits`
Expected: PASS — 2 tests.

- [ ] **Step 5: Verify full package + gofmt + vet**

Run: `go test ./internal/agentconfig/... -race && gofmt -l internal/agentconfig/ && go vet ./internal/agentconfig/...`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add internal/agentconfig/loader.go internal/agentconfig/loader_test.go
git commit -m "feat(agentconfig): add ResourceLimitsConfig yaml block"
```

---

## Task 2: Add `ResolveLimits` method

**Files:**
- Modify: `internal/agentconfig/resolve.go`
- Create: `internal/agentconfig/resolve_test.go` (if absent; else modify)

- [ ] **Step 1: Write the failing test**

Check whether `internal/agentconfig/resolve_test.go` exists:
```bash
ls internal/agentconfig/resolve_test.go 2>&1
```

If absent, create it with this content. If present, append the functions.

```go
package agentconfig

import (
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// newTestCmd returns a *cobra.Command with the 5 resource-limit flags
// registered as PersistentFlags (mirroring root.go's real registration).
// Tests use this to simulate the flag-inheritance that cmd/agent.go sees.
func newTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.PersistentFlags().String("max-memory", "", "")
	cmd.PersistentFlags().String("max-cpu-percent", "", "")
	cmd.PersistentFlags().Duration("max-duration", 0, "")
	cmd.PersistentFlags().String("stop-at", "", "")
	cmd.PersistentFlags().Int("nice", 0, "")
	return cmd
}

func TestResolveLimits_YAMLOnly(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{
			MaxMemory:     "2GB",
			MaxCPUPercent: 50,
			MaxDuration:   4 * time.Hour,
			StopAt:        "03:00",
			Nice:          10,
		},
	}
	cmd := newTestCmd()
	// Flags present but NOT explicitly set — yaml wins.
	lim, err := cfg.ResolveLimits(cmd)
	if err != nil {
		t.Fatalf("ResolveLimits: %v", err)
	}
	if lim.MaxMemoryBytes != 2<<30 {
		t.Errorf("MaxMemoryBytes: got %d, want %d", lim.MaxMemoryBytes, int64(2)<<30)
	}
	if lim.MaxCPUPercent != 50 {
		t.Errorf("MaxCPUPercent: got %d, want 50", lim.MaxCPUPercent)
	}
	if lim.MaxDuration != 4*time.Hour {
		t.Errorf("MaxDuration: got %v, want 4h", lim.MaxDuration)
	}
	if lim.StopAtOffset <= 0 {
		t.Errorf("StopAtOffset should be positive; got %v", lim.StopAtOffset)
	}
	if lim.Nice != 10 {
		t.Errorf("Nice: got %d, want 10", lim.Nice)
	}
}

func TestResolveLimits_FlagOverride_Memory(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{MaxMemory: "2GB"},
	}
	cmd := newTestCmd()
	// Simulate CLI flag explicitly set — overrides yaml.
	_ = cmd.PersistentFlags().Set("max-memory", "4GB")
	lim, err := cfg.ResolveLimits(cmd)
	if err != nil {
		t.Fatalf("ResolveLimits: %v", err)
	}
	if lim.MaxMemoryBytes != 4<<30 {
		t.Errorf("MaxMemoryBytes: got %d, want %d (flag should override yaml)",
			lim.MaxMemoryBytes, int64(4)<<30)
	}
}

func TestResolveLimits_FlagNotChanged_UsesYAML(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{MaxMemory: "2GB"},
	}
	cmd := newTestCmd()
	// Flag not set; yaml should win.
	lim, err := cfg.ResolveLimits(cmd)
	if err != nil {
		t.Fatalf("ResolveLimits: %v", err)
	}
	if lim.MaxMemoryBytes != 2<<30 {
		t.Errorf("MaxMemoryBytes: got %d, want %d", lim.MaxMemoryBytes, int64(2)<<30)
	}
}

func TestResolveLimits_BothUnset_ZeroLimits(t *testing.T) {
	cfg := &Config{} // no ResourceLimits
	cmd := newTestCmd()
	lim, err := cfg.ResolveLimits(cmd)
	if err != nil {
		t.Fatalf("ResolveLimits: %v", err)
	}
	if lim.Enabled() {
		t.Errorf("Enabled() = true; want false (no yaml, no flags)")
	}
}

func TestResolveLimits_InvalidMemoryString_ReturnsError(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{MaxMemory: "bogus"},
	}
	cmd := newTestCmd()
	_, err := cfg.ResolveLimits(cmd)
	if err == nil {
		t.Error("ResolveLimits should fail on invalid max_memory")
	}
}

func TestResolveLimits_InvalidStopAt_ReturnsError(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{StopAt: "25:00"},
	}
	cmd := newTestCmd()
	_, err := cfg.ResolveLimits(cmd)
	if err == nil {
		t.Error("ResolveLimits should fail on invalid stop_at")
	}
}

func TestResolveLimits_NilCmd_UsesYAMLOnly(t *testing.T) {
	cfg := &Config{
		ResourceLimits: &ResourceLimitsConfig{MaxCPUPercent: 25},
	}
	// nil cmd — programmatic use, no flag source.
	lim, err := cfg.ResolveLimits(nil)
	if err != nil {
		t.Fatalf("ResolveLimits(nil): %v", err)
	}
	if lim.MaxCPUPercent != 25 {
		t.Errorf("MaxCPUPercent: got %d, want 25", lim.MaxCPUPercent)
	}
}
```

- [ ] **Step 2: Verify red**

Run: `go test ./internal/agentconfig/... -v -run ResolveLimits`
Expected: FAIL — `ResolveLimits` undefined.

- [ ] **Step 3: Implement**

Read the existing `internal/agentconfig/resolve.go` first to understand its structure:
```bash
cat internal/agentconfig/resolve.go
```

Then append these additions to the file. Add imports for `"github.com/amiryahaya/triton/internal/runtime/limits"` and `"github.com/spf13/cobra"` and `"time"` (use `"time"` if not already imported).

```go
// ResolveLimits merges agent.yaml resource_limits with CLI flag values
// per the precedence rule: CLI flag wins when explicitly set, else
// yaml, else zero. When cmd is nil (programmatic use), only yaml values
// are consulted. Parse errors on malformed yaml values (bad memory
// string, out-of-range percent, bad HH:MM) surface as errors.
func (c *Config) ResolveLimits(cmd *cobra.Command) (limits.Limits, error) {
	// Seed from yaml if present.
	var maxMem, maxCPU, stopAt string
	var maxDur time.Duration
	var nice int
	if c.ResourceLimits != nil {
		maxMem = c.ResourceLimits.MaxMemory
		maxDur = c.ResourceLimits.MaxDuration
		stopAt = c.ResourceLimits.StopAt
		nice = c.ResourceLimits.Nice
		if c.ResourceLimits.MaxCPUPercent > 0 {
			maxCPU = fmtInt(c.ResourceLimits.MaxCPUPercent)
		}
	}
	// Override with CLI flags when explicitly set.
	if cmd != nil {
		if cmd.Flags().Changed("max-memory") {
			if v, err := cmd.Flags().GetString("max-memory"); err == nil {
				maxMem = v
			}
		}
		if cmd.Flags().Changed("max-cpu-percent") {
			if v, err := cmd.Flags().GetString("max-cpu-percent"); err == nil {
				maxCPU = v
			}
		}
		if cmd.Flags().Changed("max-duration") {
			if v, err := cmd.Flags().GetDuration("max-duration"); err == nil {
				maxDur = v
			}
		}
		if cmd.Flags().Changed("stop-at") {
			if v, err := cmd.Flags().GetString("stop-at"); err == nil {
				stopAt = v
			}
		}
		if cmd.Flags().Changed("nice") {
			if v, err := cmd.Flags().GetInt("nice"); err == nil {
				nice = v
			}
		}
	}

	// Parse strings into limits.Limits.
	memBytes, err := limits.ParseSize(maxMem)
	if err != nil {
		return limits.Limits{}, fmt.Errorf("resource_limits.max_memory: %w", err)
	}
	cpuPct, err := limits.ParsePercent(maxCPU)
	if err != nil {
		return limits.Limits{}, fmt.Errorf("resource_limits.max_cpu_percent: %w", err)
	}
	stopOffset, err := limits.ParseStopAt(stopAt, time.Now())
	if err != nil {
		return limits.Limits{}, fmt.Errorf("resource_limits.stop_at: %w", err)
	}
	return limits.Limits{
		MaxMemoryBytes: memBytes,
		MaxCPUPercent:  cpuPct,
		MaxDuration:    maxDur,
		StopAtOffset:   stopOffset,
		Nice:           nice,
	}, nil
}

// fmtInt formats an int to its decimal string. Kept private so we don't
// pull in strconv just for one call site.
func fmtInt(n int) string {
	return fmt.Sprintf("%d", n)
}
```

If `"fmt"` isn't already imported, add it.

- [ ] **Step 4: Verify green + race**

Run: `go test ./internal/agentconfig/... -race -v`
Expected: PASS — all existing tests + 7 new ResolveLimits tests.

- [ ] **Step 5: Verify gofmt + vet + windows**

Run: `gofmt -l internal/agentconfig/ && go vet ./internal/agentconfig/... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add internal/agentconfig/resolve.go internal/agentconfig/resolve_test.go
git commit -m "feat(agentconfig): add ResolveLimits (yaml + CLI flag merge)"
```

---

## Task 3: Plumb limits into `resolvedAgentConfig`

**Files:**
- Modify: `cmd/agent.go` — add `Limits` field, populate in `resolveAgentConfig`

- [ ] **Step 1: Add `Limits` field to struct**

In `cmd/agent.go`, find `type resolvedAgentConfig struct {` (around line 124). Add a new field at the end of the struct, before the closing `}`:

```go
	// Limits captures per-iteration resource caps (memory, CPU, duration,
	// nice) resolved from agent.yaml + CLI flags via
	// agentconfig.Config.ResolveLimits. Zero-value when no limits are
	// configured (Enabled() returns false).
	Limits limits.Limits
```

Add the import `"github.com/amiryahaya/triton/internal/runtime/limits"` at the top of `cmd/agent.go` if not already present.

- [ ] **Step 2: Populate in `resolveAgentConfig`**

Find `func resolveAgentConfig(cmd *cobra.Command) (*resolvedAgentConfig, error) {` (around line 176). At the END of the function (just before `return &resolvedAgentConfig{ ... }`), compute the limits:

```go
	lim, err := source.ResolveLimits(cmd)
	if err != nil {
		return nil, fmt.Errorf("resolving resource limits: %w", err)
	}
```

Then in the `return &resolvedAgentConfig{ ... }` literal (around line 230), add:

```go
		Limits: lim,
```

as the last field.

- [ ] **Step 3: Verify build**

Run: `go build ./... && go test ./cmd/... -race`
Expected: both succeed, existing cmd tests still pass.

- [ ] **Step 4: Commit**

```bash
git add cmd/agent.go
git commit -m "feat(cmd): plumb resolved Limits into resolvedAgentConfig"
```

---

## Task 4: Apply limits in `runAgentScan`

**Files:**
- Modify: `cmd/agent.go` — call `lim.Apply(ctx)` at top of `runAgentScan`

- [ ] **Step 1: Modify `runAgentScan`**

Find `func runAgentScan(ctx context.Context, g *license.Guard, r *resolvedAgentConfig, client *agent.Client) error {` (around line 710). Right after the initial `fmt.Printf("Starting scan (profile: %s)...\n", r.effectiveProfile)` line, insert:

```go
	// Apply resource limits per-iteration. Each scan gets a fresh
	// context with (possibly) a deadline and its own watchdog; cleanup
	// tears them down so the next iteration starts clean.
	if r.Limits.Enabled() {
		fmt.Printf("Resource %s\n", r.Limits.String())
	}
	var cleanup func()
	ctx, cleanup = r.Limits.Apply(ctx)
	defer cleanup()
```

- [ ] **Step 2: Verify build**

Run: `go build ./... && go test ./cmd/... -race`
Expected: clean.

- [ ] **Step 3: Manual smoke test**

Run: `go run . agent --check-config --interval 0 --license-key '' 2>&1 | head -20`
Expected: startup banner prints; exits cleanly (check-config mode). No panic on empty limits.

- [ ] **Step 4: Smoke test with limits**

Write a temp agent.yaml:
```bash
cat > /tmp/test-agent.yaml <<'EOF'
profile: quick
resource_limits:
  max_duration: 5s
EOF
go run . agent --check-config --config /tmp/test-agent.yaml --license-key '' 2>&1 | head -5
```
Expected: banner prints; no error. (We don't actually run a scan in check-config mode, so the limit isn't exercised — but the config resolves cleanly.)

Clean up: `rm /tmp/test-agent.yaml`

- [ ] **Step 5: Verify gofmt + vet + windows**

Run: `gofmt -l cmd/ internal/agentconfig/ && go vet ./... && GOOS=windows GOARCH=amd64 go build ./...`
Expected: all clean.

- [ ] **Step 6: Commit**

```bash
git add cmd/agent.go
git commit -m "feat(cmd): apply resource limits per-iteration in runAgentScan"
```

---

## Task 5: Documentation — example yaml + DEPLOYMENT_GUIDE

**Files:**
- Create/Modify: `docs/examples/agent.yaml.example` — add commented `resource_limits:` block
- Modify: `docs/DEPLOYMENT_GUIDE.md` — add systemd-unit subsection

- [ ] **Step 1: Find existing example location**

Run:
```bash
ls docs/examples/ 2>&1 | grep -i agent
find . -name "agent.yaml*" -not -path "./.git/*" -not -path "./.worktrees/*" 2>&1 | head -5
```

If `docs/examples/agent.yaml.example` exists, open it. If not, create it.

- [ ] **Step 2: Create/extend the example yaml**

If the file doesn't exist, create `docs/examples/agent.yaml.example` with this content:

```yaml
# Example agent.yaml — copy to ~/.triton-agent.yaml or the exe dir.
# Every field is optional; an empty file is valid and uses defaults.

# license_key: "eyJ..."         # Ed25519-signed licence token
# report_server: "https://..."  # when set, results POST'd to the server
# profile: standard              # quick | standard | comprehensive
# interval: 24h                  # continuous mode; 0 or absent = one-shot
# output_dir: ./reports          # local report destination
# formats: [json, html, sarif]   # which formats to write locally

# Per-iteration resource caps (applied via internal/runtime/limits;
# same semantics as `triton --max-memory` etc. CLI flags). Each scan
# iteration gets a fresh budget; unused caps (zero/empty) are no-ops.
#
# For KERNEL-ENFORCED limits (OOM-kill, hard cgroup caps), configure
# the systemd unit file's CPUQuota= / MemoryMax= directives — these
# yaml limits are soft in-process caps (GC pressure + watchdog).
#
# resource_limits:
#   max_memory: 2GB
#   max_cpu_percent: 50
#   max_duration: 4h
#   stop_at: "03:00"
#   nice: 10
```

If the file already exists, append only the `resource_limits:` section (the commented block starting with `# Per-iteration resource caps`).

- [ ] **Step 3: Update DEPLOYMENT_GUIDE.md**

Read `docs/DEPLOYMENT_GUIDE.md` to find the existing agent systemd section. Search for "systemd" or "triton-agent.service":

```bash
grep -n "triton-agent.service\|\[Service\]\|systemd" docs/DEPLOYMENT_GUIDE.md | head -10
```

After the existing agent systemd unit example, add this new subsection (insert before the next `##` heading):

```markdown
### Kernel-enforced resource limits

The `resource_limits:` block in agent.yaml enforces limits *inside* the
agent process via Go runtime mechanisms (`GOMEMLIMIT` for soft memory
pressure, `GOMAXPROCS` for parallelism, `context.WithTimeout` for
duration). These work without any systemd configuration.

For **hard, kernel-enforced** limits (OOM-kill rather than soft GC
pressure), add cgroup directives to the systemd unit file:

```ini
[Service]
Type=simple
User=triton-agent
ExecStart=/usr/local/bin/triton agent

# Kernel-enforced memory cap. Set this ABOVE the yaml max_memory so
# the in-process soft limit trips first (GC pressure, watchdog) and
# the systemd hard limit is the safety net for a truly runaway
# process.
MemoryMax=4G

# Kernel-enforced CPU quota. 50000 / 100000 = 50% of one core.
# A multi-core cap looks like 200% for 2 full cores.
CPUQuota=50%

# Optional: other resource envelopes.
# LimitNOFILE=65536
# TasksMax=512

Restart=on-failure
RestartSec=300s
```

**When to use which:**

| Mechanism | Enforcement | Granularity | Use case |
|---|---|---|---|
| `resource_limits:` yaml | Soft (GC pressure, parallelism, context cancel) | Per-scan | Default; portable across platforms |
| systemd `MemoryMax=`/`CPUQuota=` | Hard (OOM-kill, kernel-enforced) | Per-process | Production agents on Linux with systemd |

Use both together: yaml limits give predictable per-scan behaviour
with partial-results-on-timeout semantics; systemd limits are the
safety net that protects the host from the agent process runaway.
```

- [ ] **Step 4: Verify nothing broke**

Run: `go build ./... && go test ./... -race 2>&1 | grep -E "FAIL|^ok" | tail -5`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add docs/examples/agent.yaml.example docs/DEPLOYMENT_GUIDE.md
git commit -m "docs(agent): document resource_limits yaml + systemd cgroup directives"
```

---

## Task 6: Update README + CLAUDE.md

**Files:**
- Modify: `README.md` — add line about agent resource limits
- Modify: `CLAUDE.md` — single-line reference under agent subsection

- [ ] **Step 1: Update README.md**

Find the existing agent documentation section in `README.md` (grep for "triton agent" or "Agent"):

```bash
grep -n "triton agent\|### Agent\|## Agent" README.md | head -5
```

Add a single paragraph under the existing agent docs (after whatever describes agent.yaml today). If there's no dedicated agent section, add this under the main Usage section:

```markdown
**Agent resource limits:** `agent.yaml` supports a `resource_limits:` block that caps each scan iteration's memory, CPU, duration, and scheduling priority. Fields map 1:1 to the `--max-memory`/`--max-cpu-percent`/`--max-duration`/`--stop-at`/`--nice` CLI flags. See `docs/examples/agent.yaml.example` for the layout and `docs/DEPLOYMENT_GUIDE.md` for kernel-enforced (systemd cgroup) limits.
```

- [ ] **Step 2: Update CLAUDE.md**

Find the existing `### Resource limits (orthogonal to profile)` subsection:

```bash
grep -n "Resource limits" CLAUDE.md
```

At the end of that subsection, append ONE sentence:

```markdown
Agent mode (`triton agent`) reads the same limits from a `resource_limits:` block in `agent.yaml` (CLI flag wins when set); see `internal/agentconfig/resolve.go::ResolveLimits`.
```

- [ ] **Step 3: Verify build + tests**

Run: `go build ./... && go test ./... -race 2>&1 | grep -E "FAIL|^ok" | tail -3`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: reference agent resource_limits in README + CLAUDE.md"
```

---

## Task 7: Final verification

- [ ] **Step 1: Full build all platforms**

```bash
go build ./... && \
  GOOS=windows GOARCH=amd64 go build ./... && \
  GOOS=linux GOARCH=arm64 go build ./... && \
  GOOS=darwin GOARCH=arm64 go build ./...
```
Expected: all succeed.

- [ ] **Step 2: Full test suite with race detector**

```bash
go test ./... -race 2>&1 | grep -E "FAIL|^ok" | tail -20
```
Expected: all ok; no FAIL lines.

- [ ] **Step 3: Lint**

```bash
golangci-lint run ./cmd/... ./internal/agentconfig/... 2>&1 | head -10
```
Expected: no new issues.

- [ ] **Step 4: gofmt**

```bash
gofmt -l cmd/ internal/agentconfig/
```
Expected: no output.

- [ ] **Step 5: Coverage check**

```bash
go test -cover ./internal/agentconfig/... 2>&1 | tail -2
```
Expected: ≥80% (matches the project target).

- [ ] **Step 6: Smoke-test the agent with limits**

```bash
# Write a minimal agent.yaml with a short duration
cat > /tmp/test-agent.yaml <<'EOF'
profile: quick
interval: 0
resource_limits:
  max_memory: 1GB
  max_cpu_percent: 50
  max_duration: 5s
EOF

# Startup banner should mention limits without crashing
go run . agent --check-config --config /tmp/test-agent.yaml --license-key '' 2>&1 | head -10

rm /tmp/test-agent.yaml
```

Expected: banner shows profile + "Resource limits" line when limits are enabled, or at minimum no error. No stack traces.

- [ ] **Step 7: Verify flag override works via --help**

```bash
go run . agent --help 2>&1 | grep -E "max-memory|max-cpu-percent|max-duration|stop-at|nice"
```
Expected: all 5 flags listed (inherited from root).

---

## Self-Review Checklist

**1. Spec coverage:**
- ✅ §agent.yaml schema — Task 1 adds `ResourceLimitsConfig`
- ✅ §CLI flag precedence — Task 2 `ResolveLimits` implements it
- ✅ §Per-iteration application — Task 4 applies `lim.Apply(ctx)` per iteration
- ✅ §Documentation — Task 5 covers DEPLOYMENT_GUIDE + example; Task 6 covers README + CLAUDE.md
- ✅ §Testing — Tasks 1+2 cover YAML round-trip + ResolveLimits precedence
- ⚠️ §Integration test — Spec mentions `TestAgent_ResourceLimits_TimeoutCapsScan`. This plan does NOT include a build-tagged integration test. The manual smoke test in Task 4 Step 3-4 + Task 7 Step 6 covers the operator-facing behavior. A real integration test would require spinning the agent as a subprocess and timing iteration 1; given the scope and the existence of unit tests covering `ResolveLimits` + `Apply` (via PR #71's own tests), the integration-tier test is deferred as a future enhancement. Flagging for the implementer: if coverage feels thin, add an integration test in `test/integration/agent_test.go` but not required for v1.

**2. Placeholder scan:** None found. All test code + implementation code is complete in-line.

**3. Type consistency:**
- `ResourceLimitsConfig` same shape across Task 1 (definition), Task 2 (consumption in ResolveLimits) ✓
- `limits.Limits` field names (`MaxMemoryBytes`, `MaxCPUPercent`, `MaxDuration`, `StopAtOffset`, `Nice`) match PR #71 ✓
- `resolvedAgentConfig.Limits` introduced in Task 3 used in Task 4 ✓

**4. Order dependency sanity:**
- Task 2 depends on Task 1 (needs `ResourceLimitsConfig`). ✓
- Task 3 depends on Task 2 (needs `ResolveLimits` method). ✓
- Task 4 depends on Task 3 (needs `r.Limits` field). ✓
- Tasks 5+6 depend on Task 4 (docs describe working feature). ✓
- Task 7 is the final gate.

---

## Execution Handoff

Plan complete and saved to `docs/plans/2026-04-19-agent-resource-limits-plan.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. 7 tasks (6 implementation + 1 verification).

**2. Inline Execution** — Batch execution with checkpoints at major boundaries.

Which approach?
