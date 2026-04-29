# Network Discovery — Design Spec

## Goal

Add a network discovery feature to the Manage Portal that lets admins scan a CIDR range for hosts with an SSH port open, resolve reverse DNS, review discovered candidates, and import selected candidates into the host inventory as SSH-managed hosts.

**Scope:** Discovery finds hosts that Triton can reach via SSH. Hosts without an open SSH port are not importable — without SSH (or an installed agent), Triton cannot scan them. Agent-managed hosts enter inventory via self-registration, not via network discovery.

## Architecture

Discovery is a new bounded context at `pkg/manageserver/discovery/`, composed of four units:

- **Scanner** — pure Go: expands a CIDR, probes TCP ports concurrently, resolves reverse DNS on live IPs, emits `Candidate` values
- **Worker** — runs the scanner in a background goroutine; writes progress and candidates to the DB incrementally; respects a cancel signal
- **Store** — two DB tables: `manage_discovery_jobs` (singleton job row) + `manage_discovery_candidates` (one row per discovered IP)
- **HTTP handlers** — Start, Status/Results, Cancel, Import; mounted under `/v1/admin/discovery`

The frontend is a new `Discovery.vue` view backed by a `discovery.ts` Pinia store, added to the Inventory nav section.

**Singleton enforcement:** At the application layer. `POST /v1/admin/discovery` returns 409 if a job is already `queued` or `running`. Starting a new scan when the current job is `completed`, `failed`, or `cancelled` replaces the old job and deletes old candidates in a single transaction.

**Import** delegates to the existing `hosts.BulkCreate` + `hosts.Store.SetTags` path — no new host persistence logic.

## Data Model

Migration v10 adds two tables:

```sql
CREATE TABLE manage_discovery_jobs (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES manage_orgs(id) ON DELETE CASCADE,
  cidr             text NOT NULL,
  ssh_port         int  NOT NULL DEFAULT 22,       -- SSH port to probe; determines which hosts are importable
  status           text NOT NULL DEFAULT 'queued', -- queued|running|completed|failed|cancelled
  total_ips        int  NOT NULL DEFAULT 0,
  scanned_ips      int  NOT NULL DEFAULT 0,
  found_ips        int  NOT NULL DEFAULT 0,        -- hosts with ssh_port open
  cancel_requested boolean NOT NULL DEFAULT false,
  started_at       timestamptz,
  finished_at      timestamptz,
  error_message    text NOT NULL DEFAULT '',
  created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE manage_discovery_candidates (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id           uuid NOT NULL REFERENCES manage_discovery_jobs(id) ON DELETE CASCADE,
  ip               text NOT NULL,
  hostname         text,                           -- null if reverse DNS failed
  existing_host_id uuid REFERENCES manage_hosts(id) ON DELETE SET NULL,
  created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON manage_discovery_candidates(job_id);
```

Only hosts with `ssh_port` open are inserted as candidates. Hosts that don't respond on that port are counted in `scanned_ips` but not stored — they are not importable.

## API

All routes under `/api/v1/admin/discovery`, authenticated (JWT + `injectInstanceOrg`), admin-or-engineer role.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v1/admin/discovery` | Start a scan. Body: `{cidr, ssh_port?}`. Returns `Job`. 409 if already running. |
| `GET` | `/v1/admin/discovery` | Current job + all candidates so far. Returns `{job: Job, candidates: Candidate[]}`. 404 if no job exists yet. |
| `POST` | `/v1/admin/discovery/cancel` | Set `cancel_requested=true`. Returns 204. 409 if no active job. |
| `POST` | `/v1/admin/discovery/import` | Import selected candidates. Body: `{candidates: [{id, hostname}]}`. Returns `{imported, skipped, errors}`. |

### Types

```typescript
interface DiscoveryJob {
  id: string;
  cidr: string;
  ssh_port: number;                // SSH port that was probed (default 22)
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  total_ips: number;
  scanned_ips: number;
  found_ips: number;               // candidates with ssh_port open
  started_at?: string;
  finished_at?: string;
  error_message: string;
  created_at: string;
}

interface DiscoveryCandidate {
  id: string;
  ip: string;
  hostname: string | null;         // null = reverse DNS failed; user must supply one to import
  existing_host_id: string | null; // non-null = already in host inventory
}

interface ImportReq {
  candidates: { id: string; hostname: string }[];
}

interface ImportResp {
  imported: number;
  skipped: number;   // candidates whose existing_host_id was set (already in inventory)
  errors: { ip: string; reason: string }[];
}
```

## Scanner Internals

1. **CIDR validation** — handler rejects CIDRs larger than /16 (> 65 536 IPs) with 400. `/16` itself is accepted.
2. **CIDR expansion** — `net.ParseCIDR` + iterate; skip network address and broadcast address.
3. **SSH port probe** — concurrent TCP dials to `ip:ssh_port` via a semaphore (200 goroutines max). Per-dial timeout: 1.5 s. A host is a candidate only if this single port accepts a connection. Hosts that don't respond are counted in `scanned_ips` but not stored.
4. **Reverse DNS** — `net.LookupAddr` on SSH-open IPs only. Timeout: 3 s per lookup. Failure sets `hostname = null`; not treated as a scan error.
5. **Existing host detection** — for each candidate IP, query `manage_hosts` for a matching `ip` column. Match → set `existing_host_id`.
6. **Progress** — every 50 IPs scanned, worker UPDATEs `scanned_ips` and `found_ips` on the job row. Candidates are INSERTed as found so the GET endpoint returns live partial results.
7. **Cancellation** — worker checks `cancel_requested` flag every 50-IP batch. Handler sets the flag; worker exits within ~1 s and writes `status = cancelled`. Partial candidates are preserved.
8. **Fatal errors** — unrecoverable errors (e.g. DB unavailable) set `status = failed` + `error_message`. Partial candidates are kept.

## Import Path

1. Handler receives `{candidates: [{id, hostname}]}`.
2. Load candidate rows. Skip any where `existing_host_id IS NOT NULL` (count → `skipped`).
3. Validate: all remaining candidates must have a non-empty `hostname` in the request body. Missing hostname → 400.
4. Check licence host cap (same guard as `hosts.Create`): `current_count + len(to_import) > cap` → 403.
5. Call `hosts.Store.BulkCreate` with `[]hosts.Host` — each host gets `connection_type = 'ssh'`, `ssh_port = job.ssh_port` (from the discovery job), hostname + ip from the candidate.
6. Return `{imported, skipped, errors}`.

## Frontend

### Files

| File | Role |
|------|------|
| `web/apps/manage-portal/src/views/Discovery.vue` | Main view — form, progress, results table |
| `web/apps/manage-portal/src/stores/discovery.ts` | Pinia store — job state, candidates, poll loop |
| `web/packages/api-client/src/manageServer.types.ts` | Add `DiscoveryJob`, `DiscoveryCandidate`, `ImportReq`, `ImportResp` |
| `web/packages/api-client/src/manageServer.ts` | Add `startDiscovery`, `getDiscovery`, `cancelDiscovery`, `importDiscovery` |
| `web/apps/manage-portal/src/nav.ts` | Add "Discover" entry under Inventory |
| `web/apps/manage-portal/src/router.ts` | Add `/inventory/discover` route |

### Page States

**Empty** (no job exists): form only — CIDR input, SSH Port field (default: `22`), Start button. A note below the form explains: "Only hosts with this SSH port open will appear in results."

**Running**: form fields go read-only, Start button replaced by Stop Scan. Progress bar: `scanned_ips / total_ips`. Sub-label: "X hosts found with SSH port open". Results table grows as candidates stream in (poll every 2 s).

**Completed / Cancelled**: form becomes editable again with a "New Scan" button. Results table persists. Import bar shows selected count and blocks import if any selected candidate is missing a hostname.

**Failed**: error message banner + "Retry" button. Partial results shown.

### Results Table Columns

| Column | Notes |
|--------|-------|
| Checkbox | Unchecked for "Already in inventory" rows; those rows are also non-interactive |
| IP Address | Monospace, read-only |
| Hostname | Inline editable `<input>` — pre-filled from reverse DNS if available; placeholder "enter hostname…" if null; locked (read-only + dimmed) for "Already in inventory" rows |
| Status | `New` badge (blue) or `Already in inventory` badge (grey) |

All candidates in the table already have the SSH port open — that is the filter condition. No "Open Ports" column needed.

### Import Bar

Shown once the job reaches `completed` or `cancelled`. Displays selected count. Import button disabled if any selected candidate has no hostname in its input. On success, shows a toast and redirects to `/inventory/hosts`.

### Poll Loop

Store starts polling `GET /v1/admin/discovery` every 2 s when `job.status === 'running'`. Stops when status transitions to `completed`, `failed`, or `cancelled`. Restarted automatically on page load if the persisted job is still running (survives refresh).

## File Structure

```
pkg/manageserver/discovery/
  types.go              -- Job, Candidate, EnqueueReq, ImportReq, ImportResult
  store.go              -- Store interface
  postgres.go           -- PostgresStore
  postgres_test.go
  handlers_admin.go     -- Start, Get, Cancel, Import
  handlers_admin_test.go
  routes.go             -- MountAdminRoutes
  scanner.go            -- CIDR expansion, TCP probe, DNS lookup (interfaces for testing)
  scanner_test.go
  worker.go             -- background goroutine, progress updates, cancel polling
  worker_test.go
```

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| CIDR > /16 | 400 Bad Request |
| Invalid CIDR syntax | 400 Bad Request |
| Second POST while job running/queued | 409 Conflict |
| Cancel with no active job | 409 Conflict |
| GET with no job ever created | 404 Not Found |
| Import candidate missing hostname | 400 Bad Request |
| Import candidate already in inventory | Silently skipped, counted in `skipped` |
| Licence host cap exceeded on import | 403 Forbidden |
| DB error during scan | Candidate skipped, scan continues; fatal DB errors set status=failed |

## Testing

### Unit Tests

**`scanner_test.go`** — mock TCP dialer + mock DNS resolver via interfaces:
- Live host detected when any port connects
- Dead host (all ports refused) not emitted as candidate
- Reverse DNS failure sets hostname to null, does not abort scan
- Network and broadcast addresses skipped
- Progress counter increments every 50 IPs

**`handlers_admin_test.go`** — `httptest` + fake Store:
- 409 on concurrent start attempt
- 404 on GET with no job
- 404 on cancel with no active job
- Import skips candidates with `existing_host_id` set
- Import returns 400 when a selected candidate has no hostname
- CIDR larger than /16 rejected with 400

**`worker_test.go`**:
- Cancel flag checked; worker exits cleanly and sets `status=cancelled`
- Partial candidates preserved after cancellation
- DB write failure on candidate insert is logged and skipped

### Integration Tests (build-tagged `integration`)

- Full cycle: start → poll until completed → verify candidates in DB
- Full cycle with import: imported candidates appear in `manage_hosts`
- Singleton: second POST while running → 409; existing job unaffected
- New scan replaces old job + candidates atomically
- Cancel mid-scan: status = cancelled, partial candidates readable

### E2E (Playwright)

Test server returns stubbed discovery responses (no live network required). Coverage:

- Start scan form → running state (progress bar visible, Stop button replaces Start)
- Poll resolves → results table renders with New/Exists badges and correct row count
- Inline hostname edit on a null-hostname row unblocks Import button
- Import flow → Hosts page host count increases by imported count
- Stop mid-scan → status badge flips to Cancelled, partial results preserved
