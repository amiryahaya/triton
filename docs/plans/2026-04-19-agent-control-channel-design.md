# Agent Remote Control Channel — Design Spec

**Status:** Approved 2026-04-19
**Scope:** Step 6 of the agent-control roadmap — a long-poll channel from the Report Server to each in-host agent, carrying persistent pause state and transient `cancel` / `force_run` commands.
**Out of scope:** Admin UI (deferred — both Manage Portal primary UX and Report Server admin-UI fallback land in separate PRs alongside the respective Vue migrations). Manage Server shell (PR B1 teammate work). Agent self-signed-cert / mTLS for the in-host agent path (engines and Manage keep that story; in-host agents stay on licence-token + machine-fingerprint auth).

## Goal

Let a tenant admin send `cancel` and `force_run` to any single agent in their fleet, and set a time-bounded pause on an agent — without SSH-ing into the host. All interactions go through Report Server using an extension of the existing 30s-long-poll / 1s-check pattern already in use by engines (`pkg/server/{discovery,scanjobs,agentpush,credentials}/handlers_gateway.go`).

## Motivation

Prior roadmap shipped:

- PR #79: local cron schedule in `agent.yaml`.
- PR #80: license-server pushes a per-licence schedule override via `/validate`.

Between them, an admin can **change** when agents scan. They still cannot:

1. **Cancel an in-flight scan.** A 6-hour comprehensive scan hogs resources with no way to reclaim them short of SSH-kill.
2. **Trigger a scan on demand.** Change agents, push a config, want a scan NOW — operator has to wait for the next scheduled fire.
3. **Pause a single agent in a fleet.** License-pushed schedule is per-licence (all agents sharing the licence) — no per-machine surgical pause.

Operationally these add up to "SSH is still required for real control." At fleet sizes past a few dozen, SSH orchestration stops scaling. Step 6 closes the gap.

## Non-goals

- No WebSocket. Long-poll matches the codebase's existing idiom and works through every proxy / NAT operators have deployed.
- No persistent local command queue on the agent side. If the agent crashes between command-dispatch and result-POST, the server sees "dispatched, no result"; operator re-queues. Cancel / force_run are idempotent enough in practice.
- No push to License Server. License Server stays scoped to licensing + schedule policy (PR #80). Report Server is the operations control plane.
- No fleet-wide bulk commands in v1 ("cancel all agents in zone X"). Admin sends N per-agent commands. Bulk is a thin UI layer on top of the same API — belongs in the UX follow-up PR.
- No admin UI in this PR. Buttons needed: pause/unpause, cancel, force_run. Primary home = Manage Portal (when deployed) calling Report's admin API via service-to-service mTLS; fallback = Report's own admin UI. Both deferred until their Vue migrations.

## Architecture

### Control plane at Report Server, not Manage

Two portals, clean split:

- **License Server** (vendor, multi-customer) — owns licence policy and the per-licence `schedule` pushed via `/validate` (PR #80).
- **Report Server** (customer, cloud or on-prem, multi-tenant) — owns per-agent operations: pause toggle and transient commands.

Why not Manage Portal (even though Manage is the fleet-management portal)?

- Manage is **optional**. Many deployments skip it (agents go direct-to-Report). A Manage-only channel leaves those deployments uncontrollable.
- Agents already connect to Report for scan submission; adding a long-poll there is a free new endpoint, not a new connection.
- Cloud/on-prem separation stays intact (Report cloud-friendly multi-tenant, Manage on-prem single-tenant). Confirmed with user 2026-04-19 — do not combine.

UX will live primarily at Manage when present (fleet-ops people use Manage), calling Report's admin API over the service-to-service mTLS channel that already exists from Manage enrolment. Report's own admin UI gets a fallback view for Manage-less customers. Both UIs are out of scope here.

### Persistent state vs transient commands

Two kinds of control payload travel on the channel:

- **Persistent state** — sticky attributes the server re-sends on every poll. Agent snap-syncs on each response. Currently one field: `pausedUntil`.
- **Transient commands** — one-shot imperatives the agent executes once. Two types: `cancel`, `force_run`.

Response shape:

```json
{
  "state": {
    "pausedUntil": "2026-04-20T02:00:00Z"
  },
  "commands": [
    { "id": "cmd-abc", "type": "cancel", "args": {}, "issuedAt": "...", "expiresAt": "..." },
    { "id": "cmd-def", "type": "force_run", "args": {"profile": "quick"}, "issuedAt": "...", "expiresAt": "..." }
  ]
}
```

Empty poll (nothing queued, no state to report) → HTTP 204 No Content. Matches the existing gateway handlers' contract.

### Pause model

One nullable column on the agent record:

```sql
paused_until TIMESTAMPTZ
```

- `NULL` → not paused.
- Future timestamp → paused; agent skips next scan. Server re-sends on every poll.
- Past timestamp → effectively NULL (agent treats as not paused; server auto-expires).
- **Hard cap: 90 days** at admin-API layer — rejects requests with `until > now + 90d`. No infinity sentinel. "Forgotten pauses" become visible in the UI as they approach expiry (UX follow-up can surface warnings).

UX preset durations the UI will ship: 1h, 24h, 7d, 30d, custom ≤90d.

### Command semantics

**cancel**:
- Args: `{ "reason"?: string }` (optional audit context).
- Agent-side: if a scan is in-flight, cancel its context → scan returns early with partial results. If no scan running, reject.
- Result POST: `{status: "executed", meta: {findings: N, percentComplete: P}}` or `{status: "rejected", reason: "no scan running"}`.

**force_run**:
- Args: `{ "profile"?: "quick|standard|comprehensive", "reason"?: string }` — profile override is subject to licence-tier gating; if unset, uses the agent's configured profile.
- Agent-side: if a scan is already in-flight, **reject** with `{status: "rejected", reason: "scan in progress"}`. Admin sends `cancel` first if they really want to interrupt. This keeps cancel and force_run composable rather than implicitly coupled.
- Does **not** reset the schedule clock. A force_run at 14:00 does not change when the next scheduled fire triggers.
- Result POST: `{status: "executed", scanID: "..."}` or the rejection above.

### Agent identity

- Agent sends `X-Triton-License-Token` (existing, tenant + licence).
- Agent sends `X-Triton-Machine-ID: <sha3-256-fingerprint>` (from `license.MachineFingerprint()`, already in the codebase).
- Optional on the first request of a boot: `X-Triton-Hostname`, `X-Triton-Agent-OS`, `X-Triton-Agent-Arch` (hint metadata for the admin fleet view).
- Report Server authenticates token, extracts tenant; keys the agent by `(tenant_id, machine_id)`.
- **First-seen self-registration**: first poll from a new `(tenant, machineID)` creates the `agents` row. No explicit "enrol" step. Hostname/OS/arch captured from the hint headers.
- **Not required**: machine-bound token (the `mid` claim from PR #80's design). That's an orthogonal stricter-binding layer; requiring it here would exclude customers who deliberately share a licence across a fleet.

### Delivery guarantees

- **At-most-once.** On wire-out, server marks each command as `dispatched` (`dispatched_at = NOW()`) in the same transaction that reads it. Subsequent polls from the same agent don't re-see already-dispatched commands.
- **Result POST closes the loop.** Agent POSTs `/commands/{id}/result` with `{status, meta}`. If the agent crashes after dispatch but before result, the command sits in "dispatched, no result" state for the UI to surface; operator decides whether to re-queue.
- **Expiry.** Each command has `expires_at` (default = issued_at + 1h, configurable at enqueue). A dispatched-but-expired command is surfaced in the UI as "abandoned" after a separate background sweep.
- **No ordering guarantees across commands** — commands fan out independently; admins who send `cancel` + `force_run` should expect they may be reordered at the dispatch boundary (Report returns both on one poll, agent processes both in a single goroutine but order is not promised). In practice, the only meaningful ordering — "cancel before force_run when you want a clean force_run" — is enforced on the admin side: admin UI (future PR) will issue cancel, wait for result, then issue force_run.

### Agent-side lifecycle

Startup conditional: when `resolved.reportServer != ""`, `runAgent` spawns one extra goroutine, `commandPollLoop`. Local-only agents (no `reportServer`) do not spawn it — there's no server to poll.

Shared state (mutex-guarded, on `runAgent`'s stack):

```go
type agentControlState struct {
    mu          sync.Mutex
    pausedUntil time.Time          // zero value = not paused
    scanCancel  context.CancelFunc // nil when no scan in flight
}
```

`commandPollLoop`:

- GET `/api/v1/agent/commands/poll` with 30s server-side timeout (matches existing gateway pattern). Client-side HTTP timeout set to 35s so the server's 204 always arrives first.
- On 200 response: acquire mutex, update `pausedUntil` from `state.pausedUntil`, release. For each command:
  - `cancel`: acquire mutex, call `scanCancel()` if non-nil, release; POST `/commands/{id}/result` with executed / rejected status.
  - `force_run`: push command (including optional profile override) onto a 1-slot buffered `forceRunCh`. Main loop picks it up at its next select; when the scan completes, main loop POSTs result.
- On 204: reconnect immediately (same as existing gateway loops).
- On network error: exponential backoff, reusing the existing `healthCheckBackoff` / `healthCheckMaxBackoff` constants (initial 2s, double up to 30s). Logs a warning the first time it fails, stays quiet on subsequent retries.

Main scan loop (extended):

- Before computing sleep: acquire mutex, read `pausedUntil`; if future, target wake-up at `min(pausedUntil, scheduler.Next(now))`.
- Select block gains `case <-forceRunCh:` — receiving triggers an immediate iteration with the command's profile override (still subject to `applyTierFiltering`).
- Around `eng.Scan`: acquire mutex, populate `scanCancel` (context.CancelFunc from `ctx, cancel = context.WithCancel(parent)`), release. Clear under mutex when Scan returns.

Failure modes:

- Report Server down → poll goroutine keeps retrying with backoff; main scan loop keeps running on yaml or licence-server schedule. Commands queue server-side; deliver when connectivity returns (or expire).
- Agent crashes mid-execution → Report sees "dispatched, no result" after TTL; operator re-queues.
- Pause state stale after long disconnect → refreshed on next successful poll; auto-expiry handles the race.
- Race: `cancel` arrives the instant scan finishes → `scanCancel == nil` under mutex → POST `{status: "rejected", reason: "no scan running"}`. Admin sees the race and resends if they still want force_run.

### What is NOT added

- No local persistent command queue on the agent. If the agent crashes between dispatch and result, the command is lost from the agent's view — server-side state tells the operator what to do.
- No heartbeat beyond the long-poll itself. `last_seen_at` on the `agents` row updates on every poll; if it stops updating, that's the "agent is offline" signal for the UI.
- No cross-tenant visibility. An admin on tenant A cannot see or command an agent on tenant B. Enforced at every admin endpoint by the existing tenant middleware.

## Data model

New tables on the Report Server's `pkg/store` schema:

```sql
CREATE TABLE IF NOT EXISTS agents (
    tenant_id     UUID        NOT NULL,
    machine_id    TEXT        NOT NULL,       -- SHA3-256 fingerprint from license.MachineFingerprint()
    hostname      TEXT        NOT NULL DEFAULT '',
    os            TEXT        NOT NULL DEFAULT '',
    arch          TEXT        NOT NULL DEFAULT '',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    paused_until  TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, machine_id)
);

CREATE INDEX IF NOT EXISTS agents_last_seen_idx ON agents (tenant_id, last_seen_at);

CREATE TABLE IF NOT EXISTS agent_commands (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID        NOT NULL,
    machine_id    TEXT        NOT NULL,
    type          TEXT        NOT NULL CHECK (type IN ('cancel', 'force_run')),
    args          JSONB       NOT NULL DEFAULT '{}',
    issued_by     TEXT        NOT NULL,       -- admin user id (or service key name for s2s issuance)
    issued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ NOT NULL,
    dispatched_at TIMESTAMPTZ,                -- set when delivered to agent on poll
    result_status TEXT,                        -- executed | rejected | expired
    result_meta   JSONB,
    resulted_at   TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, machine_id) REFERENCES agents(tenant_id, machine_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS agent_commands_pending_idx
    ON agent_commands (tenant_id, machine_id, issued_at)
    WHERE dispatched_at IS NULL;

CREATE INDEX IF NOT EXISTS agent_commands_history_idx
    ON agent_commands (tenant_id, machine_id, issued_at DESC);
```

Additive migration. Existing data untouched. Zero downtime.

## HTTP surface

Agent-facing (licence-token + machine-ID auth, existing token middleware extended to read the new header):

- `GET /api/v1/agent/commands/poll` — long-poll; 30s server timeout, 1s check interval. On 200 returns `{state, commands}`; on 204 empty; on 5xx the agent retries with backoff. Side effects: upserts `agents` row (creates on first seen, updates `last_seen_at` + hostname/os/arch from hint headers), atomically marks any returned commands as dispatched.
- `POST /api/v1/agent/commands/{id}/result` — body `{status: "executed"|"rejected", meta?: {...}}`. Sets `result_status`, `result_meta`, `resulted_at`. Rejects if the command's `machine_id` doesn't match the caller's fingerprint (cross-agent tampering prevention).

Admin-facing (existing admin auth, tenant-scoped):

- `GET /api/v1/admin/agents` — list agents for the tenant, paginated (`?page=N`), includes `{machineID, hostname, os, arch, firstSeenAt, lastSeenAt, pausedUntil}` and a `status` derivation (`online` if last-seen within 2× poll window, else `offline`).
- `GET /api/v1/admin/agents/{machineID}` — detail, including the last 50 commands (pending + historical).
- `POST /api/v1/admin/agents/{machineID}/commands` — body `{type, args?, expiresInMinutes?}`. Validates type, applies tier gating to `args.profile` for `force_run` (returns 403 if admin's tier can't run that profile — prevents elevating via remote command), writes row; 201 with the command.
- `POST /api/v1/admin/agents/{machineID}/pause` — body `{until: RFC3339}` or `{durationSeconds: N}`. Enforces the 90-day cap (400 if over). Sets `paused_until`. Audit entry `agent_paused`.
- `DELETE /api/v1/admin/agents/{machineID}/pause` — clears `paused_until`. Audit `agent_pause_cleared`.

All admin actions write to the existing audit log. Event names: `agent_command_issued`, `agent_command_resulted`, `agent_paused`, `agent_pause_cleared`. Fields include tenant_id, machine_id, actor, and command args.

## Testing

Unit tests (fast, no DB):

- `pkg/store/agents_test.go` — round-trip agents + commands, paused_until auto-expiry semantics, cascade on tenant delete.
- `pkg/server/handlers_agent_commands_test.go` — poll returns 204 / 200 shape, dispatched marking, machine-id mismatch rejection on result POST.
- `pkg/server/handlers_admin_agents_test.go` — 90-day cap, tier-gate on force_run profile, tenant isolation.
- `cmd/agent.go` — commandPollLoop dispatches cancel → calls shared scanCancel; force_run pushes to forceRunCh; pausedUntil refresh.

Integration tests (real DB + Report Server):

- Full lifecycle: agent polls → empty 204; admin pauses for 1h → agent next poll sees `pausedUntil`; admin issues force_run → agent receives on next poll, runs, POSTs result; admin clears pause.
- Cancel-in-flight: start a slow scan, admin issues cancel, verify scan context cancelled and partial result surfaced.
- Cross-tenant isolation: tenant A cannot see tenant B's agents or commands.
- Expired command: enqueue with expiresInMinutes=0, next poll skips it, sweep marks result_status=expired.

No E2E / Playwright — UI is out of scope.

## Rollout

- Additive migration; zero downtime.
- Existing agents without the new code → don't poll the new endpoint → no commands ever dispatched → no behavioural change. New endpoint's 404 for old agent paths never returns because old agents never call it.
- New agents against old Report Server → poll endpoint returns 404, agent logs "command channel not supported by server" once, stops polling for that process lifetime (doesn't spam logs). On upgrade, agent restart picks up the new endpoint.
- No env var, no flag, no operator action. Spawning the poll goroutine is conditional on `reportServer != ""` which was already the pre-existing gate for all Report interactions.

## File footprint (rough)

Production:

- `pkg/store/migrations.go` — new migration (#25 at time of design — next available slot in the slice) for `agents` + `agent_commands` tables.
- `pkg/store/agents.go` (new) — `AgentRecord`, `AgentCommand` types, store methods `UpsertAgent`, `GetAgent`, `ListAgentsByTenant`, `SetAgentPausedUntil`, `EnqueueAgentCommand`, `ClaimPendingCommandsForAgent`, `SetAgentCommandResult`, `ExpireStaleCommands`.
- `pkg/server/handlers_agent_commands.go` (new) — poll + result handlers.
- `pkg/server/handlers_admin_agents.go` (new) — admin list/detail/command/pause handlers.
- `pkg/server/server.go` — route registration + middleware wiring.
- `pkg/agent/agent.go` or new `pkg/agent/control.go` — `commandPollLoop` + result POST.
- `cmd/agent.go` — wire the goroutine, shared state struct, extend main loop's select + sleep computation.

Tests:

- Unit test files alongside each new production file.
- `test/integration/agent_control_channel_test.go` — full lifecycle.

Docs:

- `docs/DEPLOYMENT_GUIDE.md` — new §7c-quater "Remote control channel".
- `CLAUDE.md` — one paragraph under Agent scheduling referencing the poll loop.

Rough size: ~900 LOC production, ~1200 LOC tests, ~80 LOC docs.

## Known limitations (documented, not addressed here)

- **No admin UI.** Manage Portal is the primary intended home and its UI cut will add pause/unpause/cancel/force-run buttons against the admin API defined here; Report's own admin UI gets a fallback view. Both deferred to future PRs aligned with the respective Vue migrations.
- **No bulk commands.** "Cancel all agents in zone X" requires N sequential admin-API calls. Thin wrapper — belongs in the UX PR.
- **No WebSocket / SSE.** If polling latency (~seconds) is ever a problem, migrating the channel is additive (new transport, same payload shape).
- **Licence + machine binding is advisory.** We don't cryptographically attest the agent's fingerprint. An attacker with a licence token could impersonate an agent and accept commands. Mitigation: tenant admins should bind tokens to machines (PR #78 `mid` claim) for higher-security deployments. Documented in the deployment guide.
- **No cross-portal fleet view.** If a customer has both Manage and Report, they'll see agents in both (different views of the same data, pulled via Report's admin API from Manage's UI). That's intentional — single source of truth on Report, UIs are views.
- **Force-run profile override still clamps to tier.** An admin's PATCH with `profile: "comprehensive"` against a pro-tier licence is rejected at enqueue time, not swallowed silently. Prevents using remote commands as a privilege-escalation vector.
