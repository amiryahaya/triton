# Analytics Phase 4B: Remediation & Exception Management — Design Spec

**Date:** 2026-04-13
**Branch:** `feat/analytics-phase-4b`
**Status:** Approved
**Depends on:** Phase 4A (ETL pipeline, host_summary, org_snapshot)

## Problem

The analytics dashboard shows "perpetual" findings — there's no way to mark a finding as fixed or accepted risk. Management can't track migration progress because resolved items keep counting against readiness. The gap between "reporting tool" and "migration tracking platform" is the absence of finding lifecycle management.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Data model | Separate `finding_status` table (append-only) | Clean audit trail; findings table stays immutable; survives rebuild |
| Status values | open, in_progress, resolved, accepted | Full lifecycle; in_progress signals "working on it" to management |
| Reopen policy | Auto-reopen resolved, keep accepted | Prevents false progress; risk acceptance persists across scans |
| Permissions | org_admin only (Phase 4B) | Simple RBAC; can relax to org_user in follow-up |
| Finding identity | finding_key = SHA256(org+host+algo+keysize+module) | Stable across scans (finding IDs change per scan) |

## Data Model

### `finding_status` table (append-only)

Every status change is a new row. Current status = latest row per `finding_key` by `changed_at DESC`.

```sql
CREATE TABLE finding_status (
    id          BIGSERIAL PRIMARY KEY,
    finding_key TEXT NOT NULL,
    org_id      UUID NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('open','in_progress','resolved','accepted')),
    reason      TEXT NOT NULL DEFAULT '',
    changed_by  TEXT NOT NULL,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ
);

CREATE INDEX idx_finding_status_key ON finding_status(finding_key, changed_at DESC);
CREATE INDEX idx_finding_status_org ON finding_status(org_id);
```

### `finding_key` computation

Stable identifier for a crypto finding across scans:

```
finding_key = hex(SHA256(org_id || hostname || algorithm || key_size || module))
```

Computed in Go with `crypto/sha256` before INSERT. Computed in SQL for T2 JOINs:

```sql
encode(sha256(
  (f.org_id::text || f.hostname || f.algorithm || f.key_size::text || f.module)::bytea
), 'hex')
```

### `host_summary` gains two columns (migration v14)

```sql
ALTER TABLE host_summary ADD COLUMN resolved_count INT NOT NULL DEFAULT 0;
ALTER TABLE host_summary ADD COLUMN accepted_count INT NOT NULL DEFAULT 0;
```

These let the UI show "45 findings (3 resolved, 2 accepted risk)" without re-querying.

## Pipeline Integration (T2 changes)

### Modified readiness calculation

The T2 query changes to exclude resolved and non-expired accepted findings:

```sql
WITH latest_status AS (
  SELECT DISTINCT ON (finding_key) finding_key, status, expires_at
  FROM finding_status
  WHERE org_id = $1
  ORDER BY finding_key, changed_at DESC
)
SELECT f.pqc_status, COUNT(*)
FROM findings f
LEFT JOIN latest_status ls ON ls.finding_key =
  encode(sha256(
    (f.org_id::text || f.hostname || f.algorithm || f.key_size::text || f.module)::bytea
  ), 'hex')
WHERE f.scan_id = $2
  AND (ls.status IS NULL
       OR ls.status IN ('open', 'in_progress')
       OR (ls.status = 'accepted' AND ls.expires_at IS NOT NULL AND ls.expires_at < NOW()))
GROUP BY f.pqc_status
```

Excluded from readiness count:
- `resolved` — finding has been fixed
- `accepted` (non-expired) — risk accepted
- Included: `open`, `in_progress`, expired `accepted`, no status (default open)

### Separate counts for resolved/accepted

T2 also queries:

```sql
SELECT
  COUNT(*) FILTER (WHERE ls.status = 'resolved') AS resolved_count,
  COUNT(*) FILTER (WHERE ls.status = 'accepted'
    AND (ls.expires_at IS NULL OR ls.expires_at >= NOW())) AS accepted_count
FROM findings f
JOIN latest_status ls ON ls.finding_key = encode(sha256(...), 'hex')
WHERE f.scan_id = $1
```

Stored in `host_summary.resolved_count` and `host_summary.accepted_count`.

### Auto-reopen logic

During T2, after computing finding keys for the latest scan:

```
FOR EACH finding in latest scan:
  compute finding_key
  look up latest status
  IF status = 'resolved' AND finding still present:
    INSERT INTO finding_status (finding_key, org_id, 'open', 'finding reappeared in scan', 'system', NOW(), NULL)
```

This prevents false progress — if someone marks RSA-1024 as resolved but the next scan still finds it, it auto-reverts to open.

`accepted` findings are NOT auto-reopened — the risk acceptance decision persists across scans.

### T3 impact

No direct changes to T3. It reads from `host_summary` which already reflects remediation exclusions from T2. The `resolved_count` and `accepted_count` columns are summed into `org_snapshot` (new columns there too).

## API Endpoints

### New endpoints

```
POST /api/v1/findings/{id}/status
  Auth: RequireScanAdmin (org_admin only)
  Body: {
    "status": "in_progress" | "resolved" | "accepted",
    "reason": "Migrated to AES-256 on 2026-04-10",
    "expiresAt": "2027-01-01T00:00:00Z"  // optional, only for accepted
  }
  Response: 200 { "findingKey": "abc123...", "status": "resolved", "changedAt": "..." }

  Steps:
  1. Look up finding by ID in findings table (scoped to org)
  2. Compute finding_key from the finding's fields
  3. INSERT INTO finding_status
  4. Write audit event: "finding.status_change"
  5. Enqueue pipeline job for the finding's hostname
  6. Return 200

POST /api/v1/findings/{id}/revert
  Auth: RequireScanAdmin (org_admin only)
  Body: { "reason": "Need to re-evaluate" }  // optional
  Response: 200 { "findingKey": "abc123...", "status": "open", "changedAt": "..." }

  Reverts any status back to open. Same steps as above with status = "open".

GET /api/v1/findings/{id}/history
  Auth: RequireTenant (any authenticated user)
  Response: [{ "status": "resolved", "reason": "...", "changedBy": "user-name", "changedAt": "...", "expiresAt": null }, ...]
  Sorted by changedAt DESC

GET /api/v1/remediation/summary
  Auth: RequireTenant
  Response: { "open": 142, "inProgress": 8, "resolved": 23, "accepted": 11, "total": 184 }

GET /api/v1/remediation?status=open&hostname=X&pqc_status=Y
  Auth: RequireTenant
  Response: { "data": [RemediationRow...], "dataAsOf": "..." }
  Each row: finding ID, hostname, algorithm, key_size, pqc_status, module, priority, current status, last changed, last changed by
  Default sort: priority DESC
  Filters: status, hostname, pqc_status (all optional)
```

## UI View: Remediation Tracker (`#/remediation`)

```
┌──────────────────────────────────────────────────────────────┐
│  Remediation Tracker                               [Filter ▼] │
│                                                               │
│  ┌───────┐ ┌───────────┐ ┌──────────┐ ┌──────────┐         │
│  │  142   │ │    8      │ │   23     │ │   11     │         │
│  │  Open  │ │In Progress│ │ Resolved │ │ Accepted │         │
│  └───────┘ └───────────┘ └──────────┘ └──────────┘         │
│                                                               │
│  ┌──────────┬──────────┬────────┬────────┬────────┬────────┐│
│  │ Host     │Algorithm │Status  │Priority│Changed │ Action ││
│  │──────────│──────────│────────│────────│────────│────────││
│  │ web-srv1 │RSA-1024  │  open  │  92    │  -     │[▼ Act] ││
│  │ web-srv1 │SHA-1     │  wip   │  78    │ 2d ago │[▼ Act] ││
│  │ db-main  │3DES      │resolved│  85    │ 5d ago │[Revert]││
│  │ legacy-1 │RC4       │accepted│  90    │ 1w ago │[Revert]││
│  └──────────┴──────────┴────────┴────────┴────────┴────────┘│
│                                                               │
│  Action dropdown: In Progress / Resolved / Accept Risk...    │
│  Accept Risk opens modal: reason (required) + expiry (opt)   │
│  Revert button on resolved/accepted → sets back to open      │
│  Click hostname → drill to #/inventory?hostname=X            │
│  Action column visible to org_admin only                      │
└──────────────────────────────────────────────────────────────┘
```

**Status summary cards** at top are clickable — filter the table to that status.

**Action dropdown** per open/in-progress row:
- Mark In Progress
- Mark Resolved
- Accept Risk... (opens modal)

**Accept Risk modal:**
- Reason textarea (required)
- Expiry date picker (optional, defaults to 1 year from now)
- Submit button

**Revert button** on resolved/accepted rows → confirms, then POSTs to `/findings/{id}/revert`.

**Staleness bar** reused from Phase 4A.

**org_admin only:** Action column and buttons hidden for org_user (they see status as read-only).

## Component Changes

| File | Action | Responsibility |
|---|---|---|
| `pkg/store/migrations.go` | Modify | v13: finding_status table; v14: resolved_count + accepted_count on host_summary |
| `pkg/store/types.go` | Modify | FindingStatusEntry, RemediationRow, RemediationSummary types |
| `pkg/store/store.go` | Modify | Add remediation methods to Store interface |
| `pkg/store/remediation.go` | Create | SetFindingStatus, RevertFinding, GetFindingHistory, GetRemediationSummary, ListRemediationFindings, ComputeFindingKey |
| `pkg/store/host_summary.go` | Modify | T2: LEFT JOIN finding_status, exclude resolved/accepted, auto-reopen, populate resolved_count/accepted_count |
| `pkg/server/handlers_remediation.go` | Create | handleSetFindingStatus, handleRevertFinding, handleFindingHistory, handleRemediationSummary, handleListRemediation |
| `pkg/server/server.go` | Modify | Wire routes (mutations under RequireScanAdmin, reads under RequireTenant) |
| `pkg/server/ui/dist/views/remediation.js` | Create | Remediation tracker view |
| `pkg/server/ui/dist/index.html` | Modify | Nav link + script tag |
| `pkg/server/ui/dist/style.css` | Modify | Status badges, action dropdown, modal styles |

## What Does NOT Change

- `findings` table (immutable read-model, rebuilt from scan blobs)
- `org_snapshot.go` T3 logic (reads from host_summary which already reflects remediation)
- Pipeline worker/queue infrastructure (reused from Phase 4A)
- Existing analytics views (inventory, certificates, priority)
- Phase 4A views (systems, trends) — these read from host_summary which auto-updates

## Test Plan

### Unit tests
- `pkg/store/remediation_test.go`: ComputeFindingKey determinism, SetFindingStatus inserts row, GetFindingHistory returns chronological order
- `pkg/store/host_summary_test.go`: T2 with remediation — resolved findings excluded from readiness, accepted excluded, expired accepted included, auto-reopen on reappearance

### Integration tests
- Full lifecycle: submit scan → mark finding resolved → submit new scan with same finding → verify auto-reopened → readiness reflects the reopen
- Accept risk with expiry: accept finding → T2 excludes it → expiry passes → T2 includes it again
- Pipeline integration: status change → pipeline job enqueued → host_summary + org_snapshot refreshed

### E2E tests
- Remediation view renders table with correct status badges
- Action dropdown changes status → table refreshes → summary cards update
- Accept Risk modal with reason + expiry → finding excluded from readiness
- Revert button → finding returns to open

## Rollback

All changes are additive:
- `finding_status` table can be `TRUNCATE`d — all findings revert to open
- `resolved_count`/`accepted_count` columns have defaults of 0
- T2 query falls back gracefully when `finding_status` is empty (LEFT JOIN produces NULLs → all findings counted)
