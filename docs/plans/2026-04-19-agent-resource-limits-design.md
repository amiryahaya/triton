# Agent Resource Limits — Design Spec

**Date:** 2026-04-19
**Status:** Approved
**Parent roadmap:** `memory/agent-control-features.md` — step 4 of 4 (final)
**Builds on:** PR #71 (resource limits foundation)
**Parallel work:** PRs #72 (detached scans), #74 (fleet-scan)

## Goal

Surface the resource-limit primitives from PR #71 to the agent daemon. The agent currently runs unbounded scans on an `--interval` loop; operators need per-iteration memory/CPU/time caps that match what foreground `triton scan` already accepts. Source: `agent.yaml` (new block) and CLI flag overrides. No new mechanisms — reuse `internal/runtime/limits/` unchanged.

## Non-goals

- Kernel-enforced (cgroup) limits at runtime. Daemons should receive those from their systemd unit file, not by wrapping themselves with `systemd-run`. Documented in the deployment guide as the operator's responsibility.
- `triton agent generate-systemd-unit` subcommand (useful but orthogonal; separate PR)
- Portal-pushed / remote-configurable limits (step 5+ of roadmap)
- Per-iteration limit variation (all iterations share one config for v1)

## Architecture

The agent runs scans **in-process**: `runAgentScan` in `cmd/agent.go` calls `eng.Scan(ctx, progressCh)` directly. Limits are applied at the top of each iteration, before the scanner engine starts:

```
runAgent (outer loop):
  for each interval tick:
    runAgentScan(ctx, ...):
      cfg := scannerconfig.Load(profile)
      lim := resolvedAgentConfig.Limits    ← sourced from yaml + CLI flags
      ctx, cleanup := lim.Apply(ctx)       ← PR #71 machinery
      defer cleanup()
      eng := scanner.New(cfg)
      eng.Scan(ctx, progressCh)            ← ctx carries deadline
```

Key property: each scan iteration gets a fresh context + fresh limit application. `--max-duration 4h` resets every interval. The memory watchdog goroutine lifecycles match the scan, not the agent process. `cleanup()` tears down the deadline + watchdog; next iteration re-applies.

## agent.yaml schema

**New optional block** (backward-compatible — absent = no limits):

```yaml
# Existing fields unchanged:
license_key: "..."
report_server: "https://..."
profile: standard
interval: 24h

# NEW:
resource_limits:
  max_memory: 2GB           # string, parsed via limits.ParseSize (KB/MB/GB/TB)
  max_cpu_percent: 50       # int 1-100; caps GOMAXPROCS to NumCPU*pct/100
  max_duration: 4h          # Go duration string; per-iteration wall-clock budget
  stop_at: "03:00"          # local-TZ HH:MM; resolved at each iteration start
  nice: 10                  # int; unix only (no-op on Windows)
```

All fields optional. Zero/empty values mean "no limit for that dimension". Field names match PR #71 CLI flags (minus `--max-` prefix where applicable) so operators reading `triton --help` recognise them.

### Interaction with `--interval`

`--max-duration` is **per-iteration**, not per-day. An agent with `interval: 24h` and `max_duration: 4h` runs one 4h scan per day with 20h idle. If the scan finishes in 30min, the agent sleeps ~23.5h before the next iteration.

`--stop-at 03:00` resolves to "the next 3am after iteration start." For a nightly scan loop, this means each iteration cuts off at 3am regardless of when it started. If iteration starts 04:00, stop-at is 03:00 *the following day*.

## CLI flag precedence

The CLI flags `--max-memory`, `--max-cpu-percent`, `--max-duration`, `--stop-at`, `--nice` already exist on `rootCmd` as `PersistentFlags` from PR #71. They inherit down to `triton agent`. Precedence rule (existing agent pattern):

```
1. CLI flag (explicitly set)  wins
2. agent.yaml resource_limits value
3. zero (no limit)
```

Uses `cmd.Flags().Changed(name)` to detect "explicitly set" vs "default zero." Matches how `--profile` and `--interval` resolve in the existing agent code.

Example:
```bash
# Base: yaml says max_memory: 2GB
# Override: CLI flag raises to 4GB for this run only
triton agent --max-memory 4GB
```

## File structure

### Modify

- `internal/agentconfig/loader.go` — add `ResourceLimits *ResourceLimitsConfig` field on `Config` + `ResourceLimitsConfig` struct with yaml tags
- `internal/agentconfig/loader_test.go` — YAML round-trip test for the new block
- `internal/agentconfig/resolve.go` — new `ResolveLimits(cmd *cobra.Command) (limits.Limits, error)` that merges CLI flags + yaml per precedence rule above
- `internal/agentconfig/resolve_test.go` (may need to create) — precedence tests
- `cmd/agent.go` — call `agentconfig.ResolveLimits(cmd)` in `runAgent`, thread through `resolvedAgentConfig`; in `runAgentScan` call `lim.Apply(ctx)` + `defer cleanup()` before `eng.Scan`
- `docs/DEPLOYMENT_GUIDE.md` — add "Kernel-enforced resource limits via systemd unit" subsection under the existing agent deployment section
- `docs/examples/agent.yaml.example` (or wherever the existing example lives) — add commented-out `resource_limits:` block with representative values
- `README.md` — brief mention of the new block under agent docs
- `CLAUDE.md` — line reference to the feature

### Create

None. Zero new packages, zero new files apart from documentation if the examples directory doesn't have an agent.yaml.example today.

### `ResourceLimitsConfig` struct

```go
// ResourceLimitsConfig is the agent.yaml resource_limits block.
// Every field optional. Zero/empty = no limit for that dimension.
type ResourceLimitsConfig struct {
    MaxMemory     string        `yaml:"max_memory,omitempty"`      // e.g. "2GB"
    MaxCPUPercent int           `yaml:"max_cpu_percent,omitempty"` // 1-100
    MaxDuration   time.Duration `yaml:"max_duration,omitempty"`    // Go duration
    StopAt        string        `yaml:"stop_at,omitempty"`         // HH:MM
    Nice          int           `yaml:"nice,omitempty"`            // unix only
}
```

### `ResolveLimits` signature

```go
// ResolveLimits merges agent.yaml resource_limits with CLI flag values
// per the precedence rule: CLI flag wins when explicitly set, else yaml,
// else zero. Calling this with cmd==nil (programmatic use) returns only
// the yaml-sourced limits. Parsing errors (bad memory string, HH:MM) are
// surfaced as errors.
func (c *Config) ResolveLimits(cmd *cobra.Command) (limits.Limits, error)
```

`limits.Limits` is the struct from PR #71's `internal/runtime/limits/` — reused unchanged.

## Integration point in `cmd/agent.go`

Inside `runAgentScan` — the per-iteration scan function. Existing structure (simplified):

```go
func runAgentScan(ctx context.Context, g *license.Guard, r *resolvedAgentConfig, client *agent.Client) error {
    cfg := scannerconfig.Load(r.effectiveProfile)
    cfg.DBUrl = scannerconfig.DefaultDBUrl()
    g.FilterConfig(cfg)

    eng := scanner.New(cfg)
    eng.RegisterDefaultModules()

    progressCh := make(chan scanner.Progress, progressBufferSize)
    go eng.Scan(ctx, progressCh)
    // ...
}
```

Modified (one extra call + defer):

```go
func runAgentScan(ctx context.Context, g *license.Guard, r *resolvedAgentConfig, client *agent.Client) error {
    cfg := scannerconfig.Load(r.effectiveProfile)
    cfg.DBUrl = scannerconfig.DefaultDBUrl()
    g.FilterConfig(cfg)

    // NEW: apply resource limits from yaml + CLI flags (PR #71 machinery).
    // Derived context carries deadline; cleanup tears down watchdog +
    // WithTimeout goroutine. Runs per-iteration so each scan gets a
    // fresh budget.
    ctx, cleanup := r.Limits.Apply(ctx)
    defer cleanup()

    if r.Limits.Enabled() {
        fmt.Printf("Resource %s\n", r.Limits.String())
    }

    eng := scanner.New(cfg)
    eng.RegisterDefaultModules()

    progressCh := make(chan scanner.Progress, progressBufferSize)
    go eng.Scan(ctx, progressCh)
    // ...
}
```

`r.Limits` is a new field on `resolvedAgentConfig` populated from `ResolveLimits(cmd)` back in `runAgent`.

## Deployment guide update

Add a subsection to `docs/DEPLOYMENT_GUIDE.md` under the agent systemd example (the existing section shows how to install `triton-agent.service`):

```markdown
### Kernel-enforced resource limits

The `resource_limits:` block in agent.yaml enforces limits *inside* the
agent process via Go runtime mechanisms (GOMEMLIMIT for soft memory
pressure, GOMAXPROCS for parallelism). These are the primary limits and
work without any systemd configuration.

For **hard kernel-enforced** limits (OOM-kill rather than soft GC
pressure), add cgroup directives to the systemd unit file:

```ini
[Service]
Type=simple
User=triton-agent
ExecStart=/usr/local/bin/triton agent

# Kernel-enforced memory cap. Triton's in-process soft limit lives
# below this; if it's breached, systemd OOM-kills the process.
MemoryMax=4G

# Kernel-enforced CPU quota. 50% of one core = 50000 per 100000 period.
CPUQuota=50%

# Optional: IO bandwidth caps, PID limits, etc.
# LimitNOFILE=65536
```

**When to use which:**

| Mechanism | Enforcement | Granularity | Use case |
|---|---|---|---|
| `resource_limits:` yaml | Soft (GC pressure, parallelism) | Per-scan | Default; portable across platforms |
| systemd `MemoryMax=` etc. | Hard (OOM-kill, kernel-enforced) | Per-process | Production agents on Linux with systemd |

Set the yaml values below the systemd values so the soft limits trigger first and bleed off gradually; systemd's hard limit is the safety net for a truly runaway process.
```

## Testing

### Unit tests

- `TestConfig_YAMLRoundTrip_ResourceLimits` — yaml → Config → yaml preserves the block
- `TestConfig_YAMLRoundTrip_NoResourceLimits` — absent block yields nil/zero ResourceLimits (no forced defaults)
- `TestResolveLimits_YAMLOnly` — yaml-configured limits build a correct `limits.Limits` struct
- `TestResolveLimits_FlagOverride_Memory` — CLI `--max-memory 4GB` wins over yaml `max_memory: 2GB`
- `TestResolveLimits_FlagNotChanged_UsesYAML` — flag present but not set by user → yaml wins
- `TestResolveLimits_BothUnset_ZeroLimits` — no yaml + no flag → empty `limits.Limits`
- `TestResolveLimits_InvalidMemoryString_ReturnsError` — `max_memory: "bogus"` surfaces a parse error
- `TestResolveLimits_InvalidStopAt_ReturnsError` — `stop_at: "25:00"` surfaces a parse error

### Integration test

`TestAgent_ResourceLimits_TimeoutCapsScan` — build the triton binary, write an agent.yaml with `resource_limits: {max_duration: 2s}`, run `triton agent --interval 1m` in the background, observe that the first scan iteration exits within ~3s (includes startup overhead) and the agent logs a timeout-related warning. Kill the agent after one iteration.

This test is timing-sensitive; use generous bounds (3s, not 2s exact) and run with `-timeout 60s` to fail-fast if something hangs.

No Docker required for this one — agent runs locally.

## Error handling

| Situation | Behavior |
|---|---|
| `max_memory: "bogus"` in yaml | `ResolveLimits` returns error; agent exits 1 at startup with clear message |
| `max_duration: -1h` in yaml | yaml parse fails (negative duration) OR `Limits.Apply` silently ignores |
| `nice: -20` on Windows | parsed, silently ignored at `ApplyNice` layer (existing behavior) |
| `max_cpu_percent: 0` | no-op (existing behavior — 0 disables) |
| `max_cpu_percent: 150` | `limits.ParsePercent` rejects; startup error |
| CLI flag set but yaml absent | Flag value used |
| Both absent | No limits applied; `r.Limits.Enabled()` is false; startup log skips the resource line |
| Scan exceeds `max_duration` | `ctx.Done()` fires; every module's inner loop returns; partial result (if any) submitted/saved. Already how PR #71's foreground scan handles this. |
| Scan exceeds hard memory watchdog (1.5× soft) | Watchdog self-SIGKILLs. Process exits 137. systemd restarts per `Restart=on-failure` policy. Next iteration starts fresh. |

## Known behaviors / non-concerns

- **Watchdog per-iteration lifecycle**: the memory watchdog goroutine is created by `lim.Apply` and torn down by `cleanup()`. Starting a new watchdog per scan iteration means watchdog overhead adds ~microseconds to each iteration; negligible.
- **GOMEMLIMIT is process-global**: `runtime/debug.SetMemoryLimit` sets a process-global value. Setting it per-iteration works but note that between iterations the limit stays set until the next `cleanup()` fires or the agent exits. Not an issue in practice — the agent only runs scans via this path.
- **`--stop-at` mid-iteration bounds**: if `max_duration` and `stop_at` are both set, the tighter wins (PR #71 existing behavior). Operators who want "stop at 3am each night OR after 4h, whichever comes first" can set both.

## Open items

None. Scope is tight and the mechanism is fully implemented in PR #71 — this PR only wires it into the agent path.
