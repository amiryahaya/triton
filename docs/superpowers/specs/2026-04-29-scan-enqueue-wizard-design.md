# Scan Enqueue Wizard Design

## Goal

Replace the two existing scan-job enqueue modals with a full-page 5-step vertical wizard that supports combined job types (port survey + filesystem), parent/child batch grouping, recurring schedules, per-job resource limits, and a credential-aware summary step.

## Architecture

The enqueue flow moves from modal dialogs to a dedicated page at `/scan-jobs/new`. Enqueueing creates a `manage_scan_batches` parent record plus `manage_scan_jobs` child rows in one atomic transaction. Recurring scans are stored as `manage_scan_schedules` rows; a background goroutine in the manage server fires them on schedule.

**Frontend:** New `EnqueueWizard.vue` page + five step components. `ScanJobs.vue` "New Scan" button navigates to this route instead of opening a dialog.

**Backend:** New `POST /api/v1/admin/scan-batches` endpoint replaces both existing enqueue endpoints. New schedule CRUD endpoints + a schedule runner goroutine.

---

## DB Schema

### Migration v16 — `manage_scan_schedules`

Created first so `manage_scan_batches` can reference it.

```sql
CREATE TABLE manage_scan_schedules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL,
  name            TEXT NOT NULL,
  job_types       TEXT[] NOT NULL,
  host_ids        UUID[] NOT NULL,
  profile         TEXT NOT NULL CHECK (profile IN ('quick','standard','comprehensive')),
  cron_expr       TEXT NOT NULL,
  max_cpu_pct     INTEGER,
  max_memory_mb   INTEGER,
  max_duration_s  INTEGER,
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  last_run_at     TIMESTAMPTZ,
  next_run_at     TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_manage_scan_schedules_next
  ON manage_scan_schedules(next_run_at)
  WHERE enabled = TRUE;
```

`next_run_at` is computed from `cron_expr` on insert and updated after each run. The schedule runner queries `WHERE enabled = TRUE AND next_run_at <= NOW()`.

### Migration v17 — `manage_scan_batches` + `batch_id` on jobs

```sql
CREATE TABLE manage_scan_batches (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL,
  job_types       TEXT[] NOT NULL,
  host_ids        UUID[] NOT NULL,
  profile         TEXT NOT NULL CHECK (profile IN ('quick','standard','comprehensive')),
  credentials_ref UUID,
  max_cpu_pct     INTEGER,
  max_memory_mb   INTEGER,
  max_duration_s  INTEGER,
  schedule_id     UUID REFERENCES manage_scan_schedules(id) ON DELETE SET NULL,
  status          TEXT NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued','running','completed','failed','cancelled')),
  enqueued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at     TIMESTAMPTZ
);

ALTER TABLE manage_scan_jobs
  ADD COLUMN batch_id UUID REFERENCES manage_scan_batches(id) ON DELETE SET NULL;

CREATE INDEX idx_manage_scan_jobs_batch ON manage_scan_jobs(batch_id);
```

**Batch status lifecycle:** The batch status is a rollup of its child jobs, updated by the orchestrator/worker whenever a child job transitions:
- Any child `running` → batch = `running`
- All children terminal (completed/failed/cancelled), at least one `failed` → batch = `failed`
- All children `cancelled` → batch = `cancelled`
- All children `completed` → batch = `completed`

`finished_at` is set on the batch when status transitions to any terminal state.

---

## Backend API

All handlers live in `pkg/manageserver/scanjobs/handlers_admin.go`.

### `POST /api/v1/admin/scan-batches`

Creates a batch + child jobs atomically. Replaces `POST /api/v1/admin/scan-jobs/` and `POST /api/v1/admin/scan-jobs/port-survey`.

**Request:**
```json
{
  "job_types": ["port_survey", "filesystem"],
  "host_ids": ["<uuid>", "<uuid>"],
  "profile": "standard",
  "max_cpu_pct": 50,
  "max_memory_mb": 2048,
  "max_duration_s": 14400
}
```

**Credential resolution per host × job type (server-enforced):**
1. `port_survey` — always create. No credential needed.
2. `filesystem`:
   - Host has `enrolled_agent_id` set → create job (agent handles auth). Enrolled agent supersedes SSH credentials.
   - Host has `credentials_ref` + `ssh_port` set → create job with those fields.
   - Neither → add to `jobs_skipped`, do not create job.

**Response 201:**
```json
{
  "batch_id": "<uuid>",
  "jobs_created": 22,
  "jobs_skipped": [
    { "host_id": "<uuid>", "job_type": "filesystem", "reason": "no_credential" }
  ]
}
```

### `GET /api/v1/admin/scan-batches`

Lists batches with child job count and status rollup (counts of queued/running/completed/failed/cancelled children).

### `POST /api/v1/admin/scan-schedules`

Creates a recurring schedule. Server validates the cron expression and computes `next_run_at` before inserting.

**Request:**
```json
{
  "name": "Weekly infra scan",
  "job_types": ["port_survey", "filesystem"],
  "host_ids": ["<uuid>"],
  "profile": "standard",
  "cron_expr": "0 2 * * 1",
  "max_cpu_pct": 50,
  "max_memory_mb": 2048,
  "max_duration_s": 14400
}
```

### `GET /api/v1/admin/scan-schedules`

Returns all schedules for the tenant: name, cron_expr, next_run_at, last_run_at, enabled, job counts.

### `PATCH /api/v1/admin/scan-schedules/:id`

Toggles `enabled`, updates `name` or `cron_expr`. Recomputes `next_run_at` if cron changes.

### `DELETE /api/v1/admin/scan-schedules/:id`

Deletes the schedule. Does not cancel in-flight batches spawned from it.

---

## Schedule Runner

A goroutine started in `manageserver.New()`, stopped via context cancellation on shutdown.

**Tick loop (every 60 s):**
1. `UPDATE manage_scan_schedules SET last_run_at = NOW(), next_run_at = <next cron tick> WHERE enabled = TRUE AND next_run_at <= NOW() RETURNING *` — claims due schedules atomically, no double-fire.
2. For each returned schedule, call the same batch-creation logic as `POST /api/v1/admin/scan-batches` with `schedule_id` set.
3. Log errors per schedule; one failure does not affect others.

Cron parsing uses `github.com/robfig/cron/v3` (already a dependency via agent scheduler).

---

## Frontend — Wizard

**Route:** `/scan-jobs/new`

**File structure:**
```
web/apps/manage-portal/src/views/
  EnqueueWizard.vue            — page shell, step router, nav sidebar
  enqueue/
    Step1JobType.vue
    Step2Hosts.vue
    Step3Schedule.vue
    Step4Resources.vue
    Step5Summary.vue
web/apps/manage-portal/src/stores/
  scanjobs.ts                  — extended: enqueueBatch(), fetchBatches(),
                                 fetchSchedules(), createSchedule(),
                                 toggleSchedule(), deleteSchedule()
```

### Step 1 — Job Type

Two checkboxes (at least one required to advance):
- Port Survey — maps open ports
- Filesystem (SSH) — crypto asset scan via SSH or enrolled agent

Profile dropdown below: quick / standard / comprehensive (default: standard).

### Step 2 — Hosts

- Search input: client-side filter by hostname or IP.
- Tag filter: multi-select dropdown, narrows list.
- Each host row shows: checkbox, hostname, IP, icon indicator:
  - 🔵 enrolled agent → filesystem will use agent
  - 🟢 SSH credential set → filesystem will use SSH
  - 🟡 no credential, no agent → filesystem will be skipped
- Selected hosts shown as removable chips above the list: *"12 hosts selected"*
- Icon legend below the list.
- Must select at least one host to advance.

### Step 3 — Schedule

Radio group:
- **Run immediately** — `scheduled_at = null`, one-time
- **Run once at** `[datetime-local]` — deferred one-time
- **Hourly** — cron `0 * * * *`
- **Daily at** `[time]` — cron `0 <H> * * *`
- **Weekly on** `[day]` **at** `[time]` — cron `0 <H> * * <DOW>`
- **Monthly on day** `[1–31]` — cron `0 2 <D> * *`

When any recurring option is selected, a **Schedule name** text field appears (required). This maps to `manage_scan_schedules.name`.

### Step 4 — Resource Limits

Three sliders, all default to 0 (unlimited):
- **CPU limit** — 0–100%, step 5. Label: *"0 = unlimited"*
- **Memory limit** — 0–32 GB, step 512 MB. Label: *"Soft cap — watchdog kills at 1.5×. 0 = unlimited"*
- **Max duration** — 0–24 h, step 30 min. Label: *"Wall-clock budget per job. 0 = unlimited"*

### Step 5 — Summary

Compact card for each section with an **Edit** link that jumps back to that step.

Cards:
- Job types: *"Port Survey + Filesystem"*
- Hosts: count + first 4 chips + *"+N more"*
- Schedule: *"Weekly · Monday 02:00"* or *"Immediately"*
- Resources: *"50% CPU · 2 GB · 4 h max"* or *"Unlimited"*

**Credential warning (amber)** — shown when any selected host is 🟡 and Filesystem is selected:

> ⚠ **N filesystem jobs will be skipped**
> These hosts have no SSH credential and no enrolled agent: `mail-01`, `backup-01`
> Port survey will still run for them. ← Go back to fix

The warning is computed client-side from host icons + selected job types. It matches what the server will return in `jobs_skipped`.

**Enqueue button:**
- One-time: *"Enqueue N jobs"*
- Recurring: *"Create schedule + enqueue now"*

On success: navigate to `/scan-jobs` with the new batch pre-selected.

---

## ScanJobs.vue changes

- **"New Scan" button** → navigates to `/scan-jobs/new` (no longer opens a modal)
- **Batch rows** — collapsible parent rows in the jobs table. Expanding a batch shows its child jobs grouped by host.
- **Schedules tab** — new tab alongside the jobs list showing all recurring schedules: name, cron, next run, enabled toggle, delete button.
- Remove `ScanJobEnqueueForm.vue` and `PortSurveyEnqueueForm.vue` (superseded by wizard).

---

## Worker changes

The portscan daemon (`pkg/scanrunner`) reads `max_cpu_pct`, `max_memory_mb`, `max_duration_s` from the job row (populated from the batch) and applies them via `internal/runtime/limits.Limits.Apply()` before starting the scan. Same pattern as `triton scan --max-cpu-percent`.

The manage server orchestrator applies the same limits for filesystem jobs it dispatches to enrolled agents.

---

## Validation rules (server-enforced)

| Condition | Behaviour |
|---|---|
| `job_types` empty | 400 Bad Request |
| `host_ids` empty | 400 Bad Request |
| Invalid `profile` | 400 Bad Request |
| Invalid `cron_expr` | 400 Bad Request |
| `max_cpu_pct` outside 0–100 | 400 Bad Request |
| Filesystem × host with no credential & no agent | Job skipped, returned in `jobs_skipped` |
| Queue saturation > 10,000 pending | 503 |
| License cap exceeded | 403 |

---

## Testing

### Unit tests (`pkg/manageserver/scanjobs/`)

**Credential resolution (`resolveJobs_test.go`):**
- Enrolled agent set → filesystem job created, SSH cred ignored (enrolled agent supersedes)
- SSH cred + ssh_port set, no agent → filesystem job created with cred fields
- Neither set → host appears in `jobs_skipped` with reason `no_credential`
- Port survey always created regardless of credential state
- Host with both agent and cred → enrolled agent wins, cred not used

**Batch status rollup (`batch_status_test.go`):**
- All children completed → batch = `completed`, `finished_at` set
- Any child failed, rest completed → batch = `failed`
- All children cancelled → batch = `cancelled`
- Any child running → batch = `running`
- Mixed running + completed → batch = `running`

**Schedule runner (`schedule_runner_test.go`):**
- Due schedule claimed and `next_run_at` advanced in single transaction (no double-fire under concurrent ticks)
- Non-due schedule not claimed
- Disabled schedule not claimed even if `next_run_at` is past
- `next_run_at` advanced to correct next cron tick after each run
- Runner failure on one schedule does not prevent other schedules from running

**Cron validation (`handlers_admin_test.go`):**
- Valid expressions accepted: `0 2 * * 1`, `0 * * * *`, `0 2 1 * *`
- Invalid expressions return 400: `not-a-cron`, `60 * * * *`, empty string
- `max_cpu_pct` outside 0–100 returns 400
- `max_memory_mb` negative returns 400

### Integration tests (`test/integration/`)

**Batch enqueue (`scan_batch_test.go`, build tag `integration`):**
- `POST /api/v1/admin/scan-batches` with both job types → correct number of child jobs in DB, all with `batch_id` set
- Child jobs for port survey created for all hosts
- Child jobs for filesystem created only for hosts with enrolled agent or SSH cred
- Skipped hosts returned in response `jobs_skipped`, not inserted into `manage_scan_jobs`
- Empty `job_types` returns 400; empty `host_ids` returns 400
- Queue saturation guard: stub > 10,000 pending rows → 503
- Batch `status` starts as `queued`; transitions to `running` when first child claimed; transitions to `completed` when all children complete

**Recurring schedules (`scan_schedule_test.go`):**
- `POST /api/v1/admin/scan-schedules` inserts row with correct `next_run_at`
- `GET /api/v1/admin/scan-schedules` returns schedule with accurate fields
- `PATCH` with `enabled: false` disables schedule; runner skips it
- `DELETE` removes schedule; `schedule_id` on existing batches set to NULL
- Schedule runner tick: due schedule spawns batch + child jobs; `last_run_at` and `next_run_at` updated
- Concurrent ticks do not double-fire the same schedule (serializable transaction test)

**Resource limits propagation (`scan_resources_test.go`):**
- Batch created with `max_cpu_pct=50`, `max_memory_mb=1024`, `max_duration_s=3600` → child jobs inherit those values
- Worker claims job and receives limit fields in response

### E2E tests (`test/e2e/scan-enqueue.spec.js`, new file)

Uses the existing manage E2E test server (`test/e2e/cmd/managetestserver/`) with seeded hosts covering all three credential states: enrolled agent 🔵, SSH credential 🟢, unconfigured 🟡.

**Wizard navigation:**
- "New Scan" button navigates to `/scan-jobs/new`
- Sidebar shows 5 steps; active step is highlighted
- "Next" disabled until step is valid (Step 1: at least one job type; Step 2: at least one host)
- "Back" returns to previous step preserving selections
- Edit link in summary jumps directly to that step

**Step 1 — Job type:**
- Selecting "Port Survey" only → summary shows "Port Survey"
- Selecting "Filesystem" only → summary shows "Filesystem (SSH)"
- Selecting both → summary shows "Port Survey + Filesystem"
- Deselecting both → Next button disabled

**Step 2 — Hosts:**
- Search input filters list by hostname and IP
- Tag filter narrows list to tagged hosts
- 🔵 icon shown for host with enrolled agent, 🟢 for SSH cred, 🟡 for neither
- Selecting a host adds it to the chips area with an ✕ remove button
- Removing chip via ✕ deselects it from the list
- Chip area shows correct count: *"3 hosts selected"*

**Step 5 — Summary credential warning:**
- Select both job types + include a 🟡 host → amber warning shown listing that host
- Warning count matches: *"1 filesystem job will be skipped"*
- Enqueue button says *"Enqueue N jobs anyway"* with N excluding skipped jobs
- Warning not shown when only Port Survey selected (no credential needed)
- Warning not shown when all selected hosts are 🔵 or 🟢

**Full enqueue (one-time, immediately):**
- Complete all 5 steps → click Enqueue → navigates to `/scan-jobs`
- New batch row visible in jobs table
- Expanding batch row shows child jobs grouped by host
- Child count matches summary count

**Recurring schedule:**
- Select "Weekly on Monday at 02:00" → Schedule name field appears
- Enter name, complete wizard → Schedules tab shows new schedule with correct next run time
- Toggle enabled/disabled via switch in Schedules tab
- Delete button removes schedule from list

**ScanJobs page — Schedules tab:**
- Tab visible alongside jobs list
- Lists all recurring schedules: name, cron description, next run, status toggle
- Delete confirms and removes schedule

---

## Out of scope

- Per-host resource limit overrides (all hosts in a batch share the same limits)
- Email/webhook notification on batch completion
- Batch retry (failed child jobs must be re-enqueued manually)
