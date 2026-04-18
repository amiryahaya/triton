# Portal-Pushed Schedule — Design Spec

**Status:** Approved 2026-04-19
**Scope:** Step 5b of the agent-control roadmap — license server pushes a schedule override on the existing `/validate` heartbeat; agent applies it on the next iteration.
**Out of scope:** per-org default, per-activation overrides, pushing non-scheduling config (profile, interval, resource_limits, formats), UI bulk-edit. Those stay step-6 territory.

## Goal

Let a fleet admin change scan schedules across every machine holding a given license by editing one field in the license server's admin UI — no SSH, no `agent.yaml` edit, no restart. The existing step-5a local cron (shipped in PR #79) already lets an operator pin a schedule in `agent.yaml`; this feature makes that schedule *remotely tunable* for licenses bound to a license server.

## Motivation

Customers are running agent fleets and asking "how do we change the schedule for 200 endpoints without walking their SSH?" The two plausible mechanisms are:

- **This design:** piggyback on the existing `/validate` heartbeat the agent already calls between iterations. Additive fields on the response; no new protocol, no new endpoint, no new cache surface.
- **Step 6 (deferred):** full remote-control channel (long-poll or websocket) for schedule + pause + cancel + force-run.

Step 6 is weeks. Step 5b is days, solves the concrete ask today, and lives entirely within the existing license-server surface. We ship 5b now; 5b's presence does not preclude step 6 later (the channel-based surface can eventually supersede the validate-response field).

## Design principles

- **Additive on the wire.** New JSON fields on `ValidateResponse`; old servers don't emit them, old agents don't read them.
- **Server-authoritative for schedule.** When the server pushes a non-empty value, the agent uses it. Local `agent.yaml` is the boot-time default and the fallback-on-parse-error guardrail.
- **Narrow scope.** Schedule + jitter only. No profile, no interval, no resource_limits, no formats. Scope grows only when a concrete ask justifies it.
- **Defense in depth.** Server validates cron on write; agent also defends against parse failure on read — a bad value never silences the fleet.
- **Per-license granularity.** One schedule column per license row. Matches how `tier` and `seats` already work. Per-activation (per-machine) overrides deferred.

## Design

### 1. Storage

Two nullable columns added to `licenses`:

```sql
ALTER TABLE licenses
    ADD COLUMN IF NOT EXISTS schedule        TEXT,
    ADD COLUMN IF NOT EXISTS schedule_jitter INTEGER;  -- seconds
```

- `schedule`: cron expression (`"0 2 * * 0"`). NULL = no server-push, agent keeps yaml.
- `schedule_jitter`: non-negative integer seconds. NULL or 0 = no jitter. Integer (not `interval`) for JSON simplicity — `time.Duration` doesn't JSON-serialize naturally across languages, and seconds is the operator's mental model.

No new tables. No org-level default row. One migration file under `pkg/licensestore/migrations.go`.

Data invariants:
- When `schedule IS NULL`, `schedule_jitter` is also ignored.
- When `schedule IS NOT NULL`, it has already passed `cron.ParseStandard` at admin write time. The DB does not re-validate.

### 2. Wire protocol

Additive fields on the existing `ValidateResponse` (defined in `internal/license/client.go`):

```go
type ValidateResponse struct {
    // ...existing fields...

    // Schedule is the server-pushed cron expression override. Empty means
    // "no override — agent uses its local agent.yaml schedule/interval."
    Schedule string `json:"schedule,omitempty"`

    // ScheduleJitterSeconds is the jitter bound in seconds; 0 disables.
    ScheduleJitterSeconds int `json:"scheduleJitterSeconds,omitempty"`
}
```

Not added to `ActivateResponse`. Activation happens once at startup and the first scan always uses the yaml-derived schedule; the server value first applies on iteration 2's sleep calculation, after iteration 1 completes and the agent heartbeats. This trade-off is deliberate: it keeps `/activate` narrowly scoped to seat management, and the one-iteration lag is acceptable given the existing 24h-ish typical cadence.

Backward compat:
- Old agent, new server: old agent ignores unknown JSON fields — yaml wins forever. No regression.
- New agent, old server: new agent reads empty strings for both fields — yaml wins. No regression.

### 3. Agent integration

Today `cmd/agent.go::heartbeat()` takes a `seat` + current guard, calls `serverClient.Validate`, and returns the updated guard. Extend it to also return an optional schedule override and an optional parse error:

```go
// heartbeat returns:
//   guard    — possibly-updated license.Guard (as today)
//   override — non-nil pointer to ScheduleSpec when the server pushed a
//              non-empty schedule this iteration; nil means "no override"
//   err      — non-nil when the pushed schedule failed to build a scheduler;
//              caller logs and keeps the previous sched
func heartbeat(seat *seatState, currentGuard *license.Guard) (*license.Guard, *agentconfig.ScheduleSpec, error)
```

In `runAgent`'s loop, after `heartbeat` returns:

```go
switch {
case err != nil:
    // Parse error on a server-pushed value. Keep whatever sched we
    // were using (which could be baseSched or a previously-pushed one)
    // so the fleet doesn't silence on a transient bad value.
    fmt.Fprintf(os.Stderr, "warning: server-pushed schedule invalid (%v) — keeping previous schedule\n", err)

case override != nil:
    // Server pushed a non-empty schedule this iteration. Build it and
    // adopt it for the next sleep.
    newSched, nerr := newSchedulerFromSpec(*override)
    if nerr != nil {
        fmt.Fprintf(os.Stderr, "warning: server-pushed schedule build failed (%v) — keeping previous\n", nerr)
    } else {
        sched = newSched
        fmt.Printf("  schedule updated from server: %s\n", sched.Describe())
    }

default:
    // Server returned an empty schedule this iteration. If we were
    // running a previously-pushed override, revert to the yaml-derived
    // baseline so an admin clearing the field in the portal actually
    // restores the operator's local setting.
    if sched != baseSched {
        sched = baseSched
        fmt.Printf("  schedule reverted to local default: %s\n", sched.Describe())
    }
}
wait := sched.Next(time.Now())
```

Reuses `agentconfig.ScheduleSpec` from PR #79 and `newSchedulerFromSpec` from the same commit. No parallel construction path; one source of truth for "what does a scheduler look like."

**Lifecycle invariants:**
- At startup, `runAgent` builds `baseSched` from `resolved.source.ResolveSchedule(cmd, os.Stderr)` + `newSchedulerFromSpec`. This is the yaml-derived (or `--interval` flag-derived) scheduler. It never changes during the process lifetime.
- `sched` starts equal to `baseSched`. On each `heartbeat` that returns a non-nil override, `sched` is replaced. On each `heartbeat` that returns no override, `sched` snaps back to `baseSched` — so "admin clears schedule in portal" reliably restores local yaml.
- On parse-error heartbeat, `sched` is left untouched — the previous "last known good" schedule wins over a bad value.

### 4. Admin API + UI

New fields on the existing admin handlers (`pkg/licenseserver/handlers_admin.go`):

- `POST /api/v1/admin/licenses` — accepts `schedule` + `scheduleJitterSeconds` in the request body; both optional. Server runs `cron.ParseStandard(schedule)` on non-empty input and returns HTTP 400 with the parser error if it fails. `schedule_jitter_seconds < 0` → 400.
- `PATCH /api/v1/admin/licenses/{id}` — same validation. Empty string for `schedule` clears both columns (treated as "remove override"). Null-vs-absent semantics documented: absent = no change; null/empty = clear.
- `GET /api/v1/admin/licenses/{id}` — response body includes the two new fields (empty when unset).
- Audit log entry `license_schedule_updated` with before/after on every change.

Admin UI (`pkg/licenseserver/ui/dist/app.js`):
- **License detail page:** new "Scheduling" section with two inputs. `schedule` is a text input with helper text `"5-field cron expression, e.g. 0 2 * * 0 for Sundays at 02:00"`. `schedule_jitter_seconds` is a number input with helper `"0 disables; typical 30–300 for fleet staggering"`. A "Clear" button removes both.
- **License create form:** same two optional fields.
- Client-side validation: jitter `>= 0`; empty schedule is allowed; do NOT replicate cron validation client-side (single source of truth on the server; keeps the client thin).

No changes to the client-facing `/activate`, `/validate`, `/deactivate` handler *signatures* beyond the additive response body on `/validate`.

### 5. Testing strategy

**Unit** (fast, table-driven where possible):
- `pkg/licensestore/` — round-trip a license with schedule/jitter populated and null; migration idempotency (run twice = no-op); backward-compat with pre-v? license rows.
- `pkg/licenseserver/handlers_admin.go` — POST/PATCH with valid cron (persists + emits audit), invalid cron (400, body not persisted), empty string (clears), negative jitter (400).
- `pkg/licenseserver/handlers_gateway.go` (the `/validate` handler) — populates the new response fields when the license carries them; emits empty strings / 0 when the license doesn't.
- `internal/license/client.go` — `ValidateResponse` deserializes the new fields correctly when present and when absent.
- `cmd/agent.go::heartbeat` — server response with non-empty schedule returns non-nil override and nil err; invalid schedule returns non-nil err; empty response returns nil override. Use a fake `ServerClient` stub.

**Integration** (build-tagged):
- Activate → admin sets schedule → next validate returns the pushed value → agent applies it → reset schedule → agent falls back to yaml baseline.

**E2E browser** (Playwright, `test/e2e/license-admin.spec.js`):
- Edit schedule on license detail, save, reload, field persists.
- Invalid cron input → save button surfaces the server error.
- Clear button empties both fields.

**Coverage target:** ≥85% on new code. Existing suites green.

### 6. Docs

- `docs/DEPLOYMENT_GUIDE.md` §7c-bis — add a "Server-pushed schedule override" subsection:
  - What it does (one paragraph).
  - Precedence clarifier: "when bound to a license server, a non-empty `schedule` on the license overrides `agent.yaml::schedule` from iteration 2 onward."
  - How to disable: "unset on the license, or don't bind the agent to a license server in the first place."
  - Note: no `schedule_lock:` in yaml. If an operator wants to resist portal pushes for a specific deployment, use the offline-token flow (no license server binding).
- `CLAUDE.md` — one-line note in the Agent Scheduling subsection that `/validate` can now push `schedule`.
- `MEMORY.md` pointers: flip item 5 in `agent-control-features.md` to fully shipped (local + portal), keep item 6 (remote control channel) as remaining work.
- No README changes — admin-facing feature.

### 7. Rollout

- Additive migration; zero downtime on deploy.
- Existing licenses: schedule/jitter stay NULL; agents see empty response; yaml wins. Today's behavior.
- Old agent + new server: old agent ignores unknown JSON; yaml wins. OK.
- New agent + old server: new agent sees empty fields; yaml wins. OK.
- No flag, no env var, no operator action.
- Rollback: revert migration drops the two columns — already-returned empty responses caused no harm.

### 8. Known limitations (documented, not addressed here)

- **One-iteration lag.** First scan after restart uses yaml; server-pushed schedule first applies on iteration 2's sleep. Intended trade-off (keeps `/activate` narrow). For 24h schedules this is invisible; for sub-minute testing cron like `* * * * *`, the operator notices. Document.
- **No per-activation overrides.** A single license fans out to N machines; they all share one schedule. If "stagger fleet A vs fleet B" is needed, split into two licenses until step 6's per-activation push lands.
- **No schedule lock.** An operator cannot stamp `schedule_lock: true` in yaml to reject server pushes. Right tool for that is the offline-token flow (no license-server binding). Documented.
- **No bulk edit.** Changing schedule across 50 licenses means 50 API calls or 50 UI clicks today. Admin-facing bulk ops are a separate feature.
- **DST semantics** identical to step 5a (local timezone, no catch-up, no double-fire). Documented by reference.

### 9. Files touched

Production:
- `pkg/licensestore/migrations.go` — new migration entry
- `pkg/licensestore/postgres.go` / `pkg/licensestore/store.go` — new column round-trip in the License struct + CRUD
- `pkg/licensestore/v2_types.go` — `License` struct gains two fields
- `pkg/licenseserver/handlers_admin.go` — request parsing + validation + audit entry
- `pkg/licenseserver/handlers_gateway.go` — populate `ValidateResponse` from License
- `pkg/licenseserver/ui/dist/app.js` (+ `index.html`, `style.css` as needed) — form fields
- `internal/license/client.go` — two new `ValidateResponse` fields
- `cmd/agent.go` — heartbeat signature change + override handling in the loop

Tests:
- `pkg/licensestore/postgres_test.go` — round-trip tests
- `pkg/licenseserver/handlers_admin_test.go` — admin API validation
- `pkg/licenseserver/handlers_test.go` — validate handler response shape
- `cmd/agent_schedule_test.go` — heartbeat override handling
- `test/integration/license_server_test.go` or a new file — full lifecycle
- `test/e2e/license-admin.spec.js` — UI assertions

Docs:
- `docs/DEPLOYMENT_GUIDE.md` — scheduling section
- `CLAUDE.md` — one-line addition
- `docs/plans/2026-04-19-portal-pushed-schedule-plan.md` — next artifact

Rough size: ~300 LOC production, ~400 LOC tests, ~80 LOC UI, ~50 LOC docs.
