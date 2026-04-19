# Agent Cron Scheduling — Design Spec

**Status:** Approved 2026-04-19
**Scope:** Step 5a of the agent-control roadmap (local cron scheduling only).
**Out of scope:** Step 5b portal-pushed schedules (requires pull-loop protocol redesign), Step 6 remote control channel.

## Goal

Let an operator pin an agent scan to a wall-clock time — "every Sunday at 02:00", "the 1st of each month at 06:30" — by writing a cron expression in `agent.yaml`, not by juggling `--interval` values. Same binary, same agent loop, one new field.

## Motivation

Today the standalone agent (`cmd/agent.go`) only supports `interval:` with ±10% jitter. Customers running maintenance-window compliance ("must scan before the weekly change freeze") or coordinating fleet scans with off-peak windows are hand-computing offsets from agent start time — fragile, drifts on restart, can't survive a reboot into the target hour. Cron is the lowest-cost fix because:

- it's already the mental model operators use for backup/maintenance jobs;
- it's stateless: the expression itself defines the schedule, so a restart just recomputes `Next()`;
- it's bounded: no new wire protocol, no new daemon state, no license-server round-trip.

Portal-pushed schedules (Step 5b) solve the fleet-UI-driven case. This spec intentionally does not block on that work — an operator with SSH to the host can deploy a new `agent.yaml` today, and that's the v1 UX we're shipping.

## Non-goals

- Cross-host coordination ("stagger 100 agents around 02:00"). Out of scope — that's what `--schedule-jitter` solves, and the fleet-wide version belongs in Step 5b.
- Calendar exceptions ("skip public holidays"). Cron doesn't do this; neither will we.
- Sub-minute granularity. The standard cron spec is minute-resolution; we don't extend it.
- Overlapping run prevention beyond what the current agent already enforces. One scan at a time is already the invariant; cron just changes *when* the next one starts.
- Migrating the in-process detached job runner (PR #72) to cron. That's a separate surface.

## Design

### Config surface

One new field on `agent.yaml` plus one tuning knob:

```yaml
# agent.yaml
schedule: "0 2 * * 0"          # cron expression, local timezone, minute resolution
schedule_jitter: 0s            # Go duration string, default "0s" (disabled); e.g. "30s", "5m"
# existing fields preserved:
interval: 24h                   # ignored if schedule is set
server: https://...
api_key: ...
resource_limits:
  max_memory: 2GB
  max_cpu_percent: 50
```

`schedule` accepts a standard 5-field cron expression evaluated in the agent host's local timezone (not UTC). Rationale: operators write `0 2 * * *` thinking "2 AM here," not "2 AM UTC." If they want UTC, they set `TZ=UTC` on the service unit — same escape hatch systemd users already reach for. The agent logs the resolved next-fire time at startup and after each iteration so the chosen zone is never a mystery.

`schedule_jitter` defaults to `0` (disabled) on cron runs. Unlike interval mode where ±10% jitter is always-on, cron's whole point is "fire at 02:00" — adding random slack by default would be surprising. Operators who want jitter for fleet-wide staggering opt in explicitly.

### Precedence chain

When both fields are present, highest-priority wins:

1. `schedule:` in yaml (if non-empty and valid)
2. `interval:` in yaml (current behavior)
3. `--interval` CLI flag (current behavior)
4. One-shot fallback (current behavior when nothing is set)

The CLI does **not** gain a `--schedule` flag. Cron expressions are multi-token strings that quote awkwardly in shells and systemd `ExecStart=` lines; yaml is the right surface. If a user sets both `schedule` and `interval` in yaml, `schedule` wins and we log a warning at startup — no error, no hard-fail, matches the existing "yaml overrides flag" ethos.

### Library choice

`github.com/robfig/cron/v3`. Rationale:

- Single import, no transitive footprint beyond stdlib.
- Stable v3 API since 2019, used by Kubernetes CronJob, Prometheus Alertmanager, countless operators.
- Exposes `cron.ParseStandard(expr)` returning a `cron.Schedule` with `Next(time.Time) time.Time` — exactly the primitive we need. We do **not** use the `cron.Cron` scheduler wrapper; we just call `Next()` ourselves inside the existing agent loop. That keeps lifecycle, context cancellation, and overlap prevention in our code.
- MIT-licensed, no CLA friction.

We pin to the latest v3 tag at vendoring time and don't track updates unless CVE'd — the parser hasn't meaningfully changed in years.

### Scheduler interface

Today the agent's main loop computes the next sleep duration inline:

```go
// current cmd/agent.go
next := cfg.Interval + jitter(cfg.Interval, 0.10)
select { case <-time.After(next): ... }
```

We refactor that into a small interface so the cron and interval code paths share everything *except* "when is next":

```go
// cmd/agent.go (package cmd, unexported)
type scheduler interface {
    // Next returns the duration to sleep until the next scheduled run,
    // measured from now. Returns 0 or negative if already due.
    Next(now time.Time) time.Duration
    // Describe returns a human-readable form for startup logs.
    Describe() string
}

type intervalScheduler struct {
    interval time.Duration
    jitterPct float64 // 0.10 for ±10%
}

type cronScheduler struct {
    expr     string
    schedule cron.Schedule
    jitter   time.Duration // 0 = disabled
}
```

`intervalScheduler.Next` preserves today's ±10% jitter. `cronScheduler.Next` calls `c.schedule.Next(now)` and subtracts `now`, then adds uniform jitter in `[0, jitter)` if enabled. The agent loop becomes:

```go
for {
    wait := sched.Next(time.Now())
    if wait < 0 { wait = 0 }
    select {
    case <-time.After(wait):
    case <-ctx.Done(): return
    }
    runOnce(ctx, ...)
}
```

No other agent code changes. Resource limits from PR #77 still apply per-iteration (including `stop_at` re-resolution); detached lifecycle, license enforcement, retry-on-OOM — all untouched.

### Failure modes

- **Invalid cron expression at startup.** `cron.ParseStandard` returns an error; the agent exits non-zero with a clear message (`invalid schedule "0 2 * *": expected 5 fields, found 4`). Fail-fast beats silently falling back to interval — operators who meant to set a schedule and typo'd want to know immediately, not a week later when the scan didn't run.
- **Clock jumps (DST, NTP step).** `cron.Schedule.Next(now)` is pure — given a new `now` it recomputes from scratch. A forward DST jump that skips 02:00–03:00 means `0 2 * * *` won't fire that day, matching cron(8) semantics. We document this; we don't paper over it.
- **Missed fires while agent was down.** Cron doesn't backfill. If the host was off at 02:00 and comes up at 02:30, the next fire is tomorrow. This matches `cron(8)` and user expectations; "catch-up" is a feature of anacron, not cron, and its addition would be a separate design.
- **Long-running scan overruns next fire.** The agent loop is serial — one scan at a time. If a scan runs from 02:00 to 02:10 and the next cron fire was 02:05 (`*/5 * * * *`), we don't queue it up; `Next(time.Now())` at 02:10 returns the next future fire (02:15). Matches how operators expect overlap-averse cron to behave; documented.

### What gets tested

- **YAML round-trip** of `schedule` + `schedule_jitter` via the existing agentconfig loader tests. Both present, only schedule present, only jitter present (no effect), both absent.
- **Precedence resolution** in `Config.ResolveSchedule(cmd)` — the new resolver that returns a `scheduler` interface. Table-driven: yaml-schedule-only, yaml-interval-only, flag-interval-only, schedule-plus-interval (warning emitted), nothing-set.
- **`cronScheduler.Next` determinism** — given a frozen `time.Now()`, a known expression returns the expected delta. Covers standard expressions, stepped ranges (`*/15`), day-of-week, and a DST-adjacent timestamp to document behavior.
- **`intervalScheduler.Next`** — jitter stays within ±10%, basic regression coverage so the refactor doesn't break today's agents.
- **Invalid-cron fail-fast** — loading a config with `schedule: "bogus"` errors, and the agent `Run` path exits non-zero before any scan.
- **Integration test** (short) — agent with `schedule: "* * * * *"` fires once within 70s, uses in-process limits from PR #77, commits a result. Gated by the existing integration build tag.

Target ≥85% coverage on the new scheduler files, ≥80% on modified `resolve.go`.

### Documentation

- `docs/DEPLOYMENT_GUIDE.md` §agent config: add `schedule` / `schedule_jitter` subsection next to `interval`. Include a 4-line yaml example, the precedence chain, the timezone note, and the "no catch-up" caveat.
- `docs/AGENT.md` (if present; otherwise inline in the deployment guide): a 5-line "cron vs interval — when to pick which" table.
- `README.md` agent section: one-line mention + link to the deployment guide.
- `CLAUDE.md`: note the new library + config field under Agent.
- `MEMORY.md` `agent-control-features.md`: flip item 5 to partial-shipped (local cron complete, portal-pushed deferred).

No changes to server, store, license server, or web UI.

### Files touched

- `go.mod` / `go.sum` — add `github.com/robfig/cron/v3`.
- `internal/agentconfig/loader.go` — add `Schedule string` and `ScheduleJitter time.Duration` fields to `Config`.
- `internal/agentconfig/resolve.go` — add `ResolveSchedule(cmd) (ScheduleSpec, error)` returning a plain-data struct `{Kind: "cron"|"interval", CronExpr string, Interval, Jitter time.Duration}` using the full precedence chain. `cmd/agent.go` calls this and constructs the runtime `scheduler` interface from the spec. Rationale: keep `internal/agentconfig` pure data (no cron library import), keep runtime wiring in `cmd`. The existing `ResolveInterval` is removed; its only caller (`cmd/agent.go`) switches to `ResolveSchedule`.
- `cmd/agent.go` — extract `scheduler` interface + two impls (new file `cmd/agent_scheduler.go`), swap the inline `time.After(interval+jitter)` for `sched.Next(now)`. Add startup log line `"agent scheduled: <describe>"`.
- `cmd/agent_scheduler_test.go` (new) — unit tests for both scheduler impls.
- `internal/agentconfig/resolve_test.go` — extend with precedence cases.
- `docs/DEPLOYMENT_GUIDE.md` — yaml field docs.
- `CLAUDE.md`, `MEMORY.md` — brief updates.

Rough size: ~180 LOC of production code, ~250 LOC of tests, ~50 LOC of docs.

### Rollout

- No migration. Existing agents with `interval:` keep working byte-for-byte; the scheduler refactor is behavior-preserving (same ±10% jitter, same sleep math).
- No new env vars, no new CLI flags, no container config.
- Agent can be upgraded in place; restart picks up the new `schedule:` field if set, otherwise continues with interval.
- Downgrade path: a pre-cron agent binary reads a yaml with `schedule:` and ignores the unknown field (we use `yaml:"schedule,omitempty"` with the existing unknown-field-tolerant loader — verified during plan execution).

### What we're not doing and why

- **No `--schedule` CLI flag.** Cron strings are shell-hostile. Yaml is the right place. Also keeps the "schedule lives in config, not in ps output" story clean for operators.
- **No custom cron dialect.** Robfig supports `@every`, `@daily`, `@hourly` etc. out of the box via `ParseStandard`; we don't extend it. If someone needs second-precision, they're not the target audience.
- **No per-schedule resource-limit override.** Resource limits are a host property, not a schedule property. Yaml `resource_limits:` applies to every iteration regardless of schedule.
- **No "run now" escape hatch on cron mode.** If an operator needs an ad-hoc scan, they run the CLI directly — same as today. Adding a "skip to next fire" IPC is Step 6 work.
