# Job Runner (Detached Scans) — Design Spec

**Date:** 2026-04-18
**Status:** Approved
**Parent roadmap:** `memory/agent-control-features.md` — step 2 of 4
**Builds on:** PR #71 (resource limits foundation)
**Next step:** `triton ssh-scan` orchestrator (step 3)

## Goal

Add a detached lifecycle to `triton scan` so SSH sessions can disconnect while scans continue. Same binary, same engine, same `Limits.Apply()` surface as PR #71 — the new feature is lifecycle state managed via a work-dir on disk. Six new CLI modes: `--detach`, `--status`, `--collect`, `--cancel`, `--list-jobs`, `--cleanup`.

## Non-goals

- Cron scheduling (step 5 of roadmap)
- Portal-pushed schedules / remote control channel (step 6)
- Agent supervisor resource-limits integration (step 4; uses but doesn't extend the detach lifecycle)
- Cross-host orchestration (step 3 — `triton ssh-scan`)

## Architecture

Three layers; **zero scanner engine changes**.

```
CLI layer (cmd/root.go + new cmd/scan_jobs.go)
  Parses --detach/--status/--collect/--cancel/--list-jobs/--cleanup
  Dispatches to one of:
    • runScanDetached()   — spawn child + return
    • runScanDaemon()     — the re-exec'd child (detected via env sentinel)
    • runJobStatus() / runJobCollect() / runJobCancel() /
      runJobList() / runJobCleanup()
        ↓
Job runner (internal/runtime/jobrunner/)
  Pure functions over the work-dir:
    • Spawn(cfg) → (jobID, pid, err)
    • WriteStatus(jobID, Status) / ReadStatus(jobID) → (Status, err)
    • TouchCancelFlag(jobID) / IsCancelled(jobID) → bool
    • List() → []JobSummary
    • Remove(jobID) / RemoveAll()
    • Detect stale jobs via kill -0 / FindProcess+Signal(0)
  Cross-platform: setsid on unix, DETACHED_PROCESS on windows
        ↓
Existing scan engine (pkg/scanner, unchanged)
  Same eng.Scan(), same progressCh. A new goroutine consumes
  progressCh and writes status.json atomically; the engine
  doesn't know it's detached.
```

### Re-exec flow

```
Parent (user's shell):                  Child (detached daemon):
  triton scan --detach ...              triton scan --profile ...
       │                                  (same CLI args minus --detach,
  fork-exec with:                          plus TRITON_DETACHED=1 env)
    SysProcAttr{Setsid:true}                 │
    TRITON_DETACHED=1                      detects env
    TRITON_JOB_ID=<uuid>                   writes pid file
    TRITON_WORK_DIR=<dir>                  acquires state.lock (flock)
    Cmd.Stdout/Stderr → scan.log           starts status-writer goroutine
       │                                   starts cancel.flag poller
  write pid to work-dir                    calls eng.Scan()
  write initial status.json                on completion: writes final
  print "Detached as <job-id>"             result.json + all reports
  return 0                                 writes terminal status
                                           exits
```

## CLI surface

All flags on the existing `rootCmd`. Lifecycle mode is selected via mutually-exclusive bool flags (enforced with `MarkFlagsMutuallyExclusive`).

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--detach` | bool | false | Lifecycle mode |
| `--status` | bool | false | Lifecycle mode |
| `--collect` | bool | false | Lifecycle mode |
| `--cancel` | bool | false | Lifecycle mode |
| `--list-jobs` | bool | false | Lifecycle mode |
| `--cleanup` | bool | false | Lifecycle mode |
| `--job-id` | string | `""` (auto-UUID for `--detach`) | Required for status/collect/cancel/cleanup-one |
| `--work-dir` | string | `~/.triton/jobs/` | Per-user convention; matches `~/.triton/license.key` |
| `--wait` | bool | false | Only with `--cancel` — blocks until terminal state |
| `--timeout` | duration | 30s | Only with `--cancel --wait` |
| `--keep` | bool | false | Only with `--collect` — opt out of auto-cleanup |
| `--all` | bool | false | Only with `--cleanup` — remove all finished jobs (skips running; cancel them explicitly first) |
| `--json` | bool | false | Only with `--status` / `--list-jobs` — machine-readable |
| `--quiet` | bool | false | Only with `--detach` — print only job-id (for `JOB=$(… --quiet)`) |

**Interaction with PR #71 limit flags:** `--max-memory`/`--max-cpu-percent`/`--max-duration`/`--stop-at`/`--nice` apply to `--detach` (passed through to the daemon re-exec). Ignored for other lifecycle modes (no scan to limit).

**Example flows:**

```bash
# SSH-agentless disposable scanner
JOB=$(ssh host 'sudo /tmp/triton scan --detach --profile standard --max-memory 2GB --quiet')
# disconnect; come back in an hour
ssh host "triton scan --status --job-id $JOB --json" | jq .progress_pct
ssh host "triton scan --collect --job-id $JOB -o -" > scan-$JOB.tar.gz

# Local use: fire off a long scan, check progress occasionally
triton scan --detach --profile comprehensive --max-duration 12h
# 6 hours later:
triton scan --list-jobs
triton scan --collect --job-id <id> -o ./reports
```

**`--list-jobs` output** (plain; `--json` for machine-readable):

```
JOB ID                                STATE     STARTED              DURATION   PROGRESS  FINDINGS
7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e  running   2026-04-18 10:00:00  1h23m      42%       137
b1c2d3e4-5f67-8910-1112-131415161718  done      2026-04-18 08:00:00  2h15m      100%      892
9a8b7c6d-5e4f-3210-9876-fedcba098765  failed    2026-04-17 22:00:00  3m12s      15%       23
```

## Work-dir schema

Layout (`~/.triton/jobs/<job-id>/`):

```
<job-id>/
  pid                   # daemon PID (plain text, one line)
  state.lock            # flock held by daemon; reveals staleness when released
  started_at            # RFC3339 timestamp (plain text)
  config.json           # snapshot of scan config (profile, modules, limits, flags)
  status.json           # live progress — atomically rewritten every 2s
  scan.log              # daemon stdout+stderr
  cancel.flag           # existence == "please cancel"
  reports/              # report files written at scan completion
    triton-report-*.json
    triton-report-*.cdx.json
    triton-report-*.html
    triton-report-*.sarif
    triton-report-*.xlsx
  result.json           # canonical JSON result (for --collect --format json)
```

### `status.json` schema (stable contract)

```json
{
  "job_id": "7a3f9e2c-1b4d-4a8f-9c6e-5d2a1b8c9d0e",
  "pid": 12345,
  "state": "running",
  "started_at": "2026-04-18T10:00:00Z",
  "updated_at": "2026-04-18T10:05:23Z",
  "completed_at": null,
  "progress_pct": 42.5,
  "current_module": "certificate",
  "findings_count": 137,
  "rss_mb": 245,
  "limits": "memory=2147483648 cpu=50% duration=4h0m0s",
  "error": null,
  "host": "prod-web-01",
  "triton_version": "v1.2.3"
}
```

Cancellation is reflected via the `state` transition (`running` → `cancelled`), not a separate boolean — the flag file is the intent channel; `state` is the outcome.

`state` enum: `pending` | `running` | `done` | `failed` | `cancelled`.

### Atomicity

- `status.json` written via `os.WriteFile(tmp) + os.Rename(tmp, status.json)` — POSIX atomic replace; readers never see partial content.
- `result.json` written once at scan end (same pattern).
- `pid` written at daemon startup before `state.lock` grabbed — reader seeing `pid` but no held `state.lock` knows daemon crashed pre-flight.
- `cancel.flag` creation via `os.OpenFile(flag, O_CREATE|O_EXCL, 0600)` — touching is idempotent.

### Stale detection (self-healing)

`--status` / `--list-jobs` reconcile by:

1. Read `status.json`. If `state` is terminal, trust it.
2. If `state == "running"`, try to acquire `state.lock`:
   - Success = daemon is gone → overwrite status: `state=failed, error="daemon vanished (crash or kill)"`.
3. If `state.lock` is held, check PID via `os.FindProcess(pid).Signal(syscall.Signal(0))`:
   - `ESRCH` = zombie → same as case 2 above.

Self-healing on observation — no cleanup daemon needed.

## Daemon lifecycle

### Spawn (parent, `runScanDetached`)

```go
func runScanDetached(cmd *cobra.Command, args []string) error {
    jobID := jobIDFlag
    if jobID == "" {
        jobID = uuid.NewString()
    }
    workDir := resolveWorkDir(workDirFlag)
    jobDir := filepath.Join(workDir, jobID)
    if err := os.MkdirAll(filepath.Join(jobDir, "reports"), 0700); err != nil { ... }

    cfg := captureConfigSnapshot(cmd)
    writeJSON(filepath.Join(jobDir, "config.json"), cfg)

    logFile, _ := os.Create(filepath.Join(jobDir, "scan.log"))
    child := exec.Command(os.Args[0], rebuildArgs(args)...)
    child.Env = append(os.Environ(),
        "TRITON_DETACHED=1",
        "TRITON_JOB_ID="+jobID,
        "TRITON_WORK_DIR="+workDir,
    )
    child.Stdout = logFile
    child.Stderr = logFile
    child.Stdin = nil
    child.SysProcAttr = detachSysProcAttr()

    if err := child.Start(); err != nil {
        return fmt.Errorf("failed to spawn daemon: %w", err)
    }

    writePidFile(jobDir, child.Process.Pid)
    writeInitialStatus(jobDir, child.Process.Pid, cfg)
    child.Process.Release()

    if quietFlag {
        fmt.Println(jobID)
    } else {
        fmt.Printf("Detached as job %s\npid %d, work-dir %s\n",
            jobID, child.Process.Pid, jobDir)
    }
    return nil
}
```

### Platform-specific detach

```go
// detach_unix.go  //go:build unix
func detachSysProcAttr() *syscall.SysProcAttr {
    return &syscall.SysProcAttr{Setsid: true}
}

// detach_windows.go //go:build windows
func detachSysProcAttr() *syscall.SysProcAttr {
    return &syscall.SysProcAttr{
        CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008, // DETACHED_PROCESS
        HideWindow:    true,
    }
}
```

### Child (`runScanDaemon`, activated when `TRITON_DETACHED=1`)

```go
func runScanDaemon(cmd *cobra.Command, args []string) error {
    jobID := os.Getenv("TRITON_JOB_ID")
    workDir := os.Getenv("TRITON_WORK_DIR")
    jobDir := filepath.Join(workDir, jobID)

    lock, err := acquireFileLock(filepath.Join(jobDir, "state.lock"))
    if err != nil {
        return fmt.Errorf("job %s already running", jobID)
    }
    defer lock.Release()

    // Build config, Limits, engine — same as foreground
    cfg, _ := scannerconfig.BuildConfig(...)
    lim, _ := buildLimits(...)
    baseCtx, baseCancel := context.WithCancel(context.Background())
    defer baseCancel()
    ctx, cleanup := lim.Apply(baseCtx)
    defer cleanup()

    eng := scanner.New(cfg)
    eng.RegisterDefaultModules()

    progressCh := make(chan scanner.Progress, progressBufferSize)

    go eng.Scan(ctx, progressCh)
    go writeStatusLoop(ctx, jobDir, progressCh, jobID)
    go cancelFlagPoller(ctx, jobDir, baseCancel)

    var result *model.ScanResult
    for p := range progressCh {
        if p.Complete && p.Result != nil {
            result = p.Result
        }
    }

    switch {
    case ctx.Err() == context.Canceled:
        writeTerminalStatus(jobDir, "cancelled", result, nil)
    case result != nil:
        if err := saveResultAndReports(jobDir, result, cfg); err != nil {
            writeTerminalStatus(jobDir, "failed", result, err)
            return err
        }
        writeTerminalStatus(jobDir, "done", result, nil)
    default:
        writeTerminalStatus(jobDir, "failed", nil, errors.New("scan ended without result"))
    }
    return nil
}
```

### Status writer

Drains `progressCh` (so scan doesn't block) while counting findings, tracking current module, sampling RSS, and rewriting `status.json` atomically every 2s or on completion:

```go
func writeStatusLoop(ctx context.Context, jobDir string, progressCh <-chan scanner.Progress, jobID string) {
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    s := initialStatus(jobID)
    for {
        select {
        case p, ok := <-progressCh:
            if !ok { return }
            s.update(p)
            fmt.Printf("[%3.0f%%] %s\n", p.Percent*100, p.Status)
            if p.Complete { writeStatusAtomic(jobDir, s); return }
        case <-ticker.C:
            s.updateRSS()
            writeStatusAtomic(jobDir, s)
        case <-ctx.Done():
            s.state = "cancelled"
            writeStatusAtomic(jobDir, s)
            return
        }
    }
}
```

### Cancel poller

```go
func cancelFlagPoller(ctx context.Context, jobDir string, cancel context.CancelFunc) {
    flag := filepath.Join(jobDir, "cancel.flag")
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done(): return
        case <-ticker.C:
            if _, err := os.Stat(flag); err == nil {
                cancel()
                return
            }
        }
    }
}
```

### Graceful shutdown ordering

1. `cancel.flag` touched by `--cancel` command
2. `cancelFlagPoller` detects within ≤2s → calls `baseCancel()`
3. `ctx.Done()` fires; every module's `ctx.Done()` check returns
4. `eng.Scan` closes `progressCh`
5. `writeStatusLoop` sees channel close → writes final `status.json` with `state: "cancelled"`
6. Daemon reaches deferred `lock.Release()` + exits

### `--cancel --wait` on caller side

After touching the flag, polls `status.json` every 500ms for a terminal state, with `--timeout 30s` default. Non-zero exit if daemon didn't reach terminal state in time (but the cancel request still stands — daemon will exit).

## Reports + `--collect`

```go
func runJobCollect(jobID, workDir, outputPath, format string, keep bool) error {
    status := readStatus(workDir, jobID)
    if status.State == "running" {
        return errors.New("job still running — use --status to poll, --cancel to stop")
    }
    jobDir := filepath.Join(workDir, jobID)

    switch format {
    case "json":
        copyFile(filepath.Join(jobDir, "result.json"), outputPath)
    case "tar", "all":
        writeTarGz(filepath.Join(jobDir, "reports"), outputPath)
    default:
        picks, _ := filepath.Glob(filepath.Join(jobDir, "reports", "*."+format))
        if len(picks) == 0 { return fmt.Errorf("no %s report found", format) }
        copyFile(picks[0], outputPath)
    }

    if !keep {
        return os.RemoveAll(jobDir)
    }
    return nil
}
```

**`--output-dir` with `--detach`:** ignored; warning emitted. Reports always land in `<workdir>/<jobid>/reports/`. `--collect` is the canonical retrieval path.

## Error handling matrix

| Situation | Behavior |
|---|---|
| `--detach` with duplicate `--job-id` (flock held) | Parent: `job <id> already running (pid N)`, exit 1 |
| `--detach` with duplicate `--job-id` (no flock, stale dir) | Parent: `job <id> work-dir exists; use --cleanup first`, exit 1 |
| `--status --job-id X` where X doesn't exist | `job <id> not found`, exit 1 |
| `--collect` while `state=running` | Actionable error, exit 1 |
| Daemon crashes (SIGKILL, OOM, panic) | Next observation rewrites status as `failed` (self-healing) |
| Disk full during status write | Rename fails; daemon logs + continues; terminal status write is best-effort |
| User edits `status.json` manually | Atomic-replace overwrites on next tick; no read lock |
| `cancel.flag` touched after scan completed | Leftover; next `--cleanup` removes |
| cancel during report generation | Treated as completed (terminal states are sticky) |
| Parent killed between fork-exec and pid write | Daemon writes pid itself as belt-and-suspenders |
| Windows DETACHED_PROCESS edge cases | Daemon opens own handles to scan.log before any stdlib read |

## File structure

```
internal/runtime/jobrunner/           # NEW package
  jobrunner.go           # public API: Spawn, ReadStatus, WriteStatus, List, Remove
  jobrunner_test.go
  status.go              # Status struct + atomic writer
  status_test.go
  lock_unix.go           # //go:build unix — flock-based
  lock_windows.go        # //go:build windows — LockFileEx
  lock_test.go
  detach_unix.go         # //go:build unix — Setsid SysProcAttr
  detach_windows.go      # //go:build windows — DETACHED_PROCESS flag
  stale.go               # stale-job detection (pid alive check + lock reconciliation)
  stale_test.go
  doc.go                 # package doc (platform caveats)

cmd/
  scan_jobs.go           # NEW: runScanDetached + runScanDaemon + runJob{Status,Collect,Cancel,List,Cleanup}
  scan_jobs_test.go      # unit tests for the 6 mode dispatchers
  root.go                # MODIFIED: add lifecycle flags, dispatch switch before runScan

test/integration/
  scan_jobs_test.go      # //go:build integration — end-to-end detach→status→collect flow
```

`cmd/root.go` grows by ~50 lines (flag registration + dispatch).

## Testing strategy

### Unit tests (`internal/runtime/jobrunner/`)
- `status_test.go` — atomic write, schema round-trip, update semantics
- `lock_test.go` — flock held/released; concurrent acquire; Windows LockFileEx
- `stale_test.go` — detect dead PID via inject-mock signal hook (test seam)
- `jobrunner_test.go` — Spawn/List/Remove using a real subprocess that `time.Sleep(1s)` and exits cleanly (no triton scan; isolates job-runner from scanner)

### Unit tests (`cmd/scan_jobs.go`)
- `TestRunJobStatusMissingJob` — error path
- `TestRunJobCollectRunning` — refuse collect
- `TestRunJobCollectJSON` / `TestRunJobCollectTar` — output path variants
- `TestRunJobCancelAsync` / `TestRunJobCancelWait` — timeout + success
- `TestRunJobListJSON` / `TestRunJobListText` — formatting

### Integration (build-tagged)
- Real `triton scan --detach` with `--profile quick` against a fixture directory
- Poll `status.json` until `state=running`
- Touch `cancel.flag` (or use `--cancel --wait`)
- Verify `state=cancelled` + terminal status correct
- Re-run detach → let complete → `--collect` → verify tar contents + work-dir cleaned up
- Stale detection: `kill -9` the daemon, verify next `--status` flips state to `failed`

### Platform gating
- Windows detach tests: `//go:build windows` (CreationFlags verification)
- Unix detach tests: `//go:build unix` (Setsid verification)
- Cross-platform integration test works on all three (cancel via flag, not signal)

### Coverage target
≥80% on `internal/runtime/jobrunner/` (matches PR #71 bar; achieved 92.6% there).

## Open items (deferred to plan / implementation)

- **Log rotation in `scan.log`** — not needed for v1; `--cleanup` removes.
- **Compression of tar in `--collect`** — pick gzip by default, allow `--compression none` later if needed.
- **Max concurrent jobs** — no hard cap; filesystem is the limit.
- **Long-job-id collision** — UUIDv4 collision probability is negligible; no explicit check.

## Dependencies

- No new Go modules (stdlib `os/exec`, `syscall`, `archive/tar`, `compress/gzip`, `crypto/rand` for UUIDs via `github.com/google/uuid` — already a dep per PR #11).
- Builds on PR #71 (`internal/runtime/limits`) for the daemon's limit installation path.
