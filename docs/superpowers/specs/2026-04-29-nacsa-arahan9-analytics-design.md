# NACSA Arahan 9 Analytics — Report Portal Phase 3 Design

## Overview

Add a NACSA Arahan 9 compliance dashboard to the Report Portal. The dashboard is tenant-scoped (each organisation sees only their own data), uses a 5-tab Power BI-style layout with drill-down navigation from Manage Servers → Hosts → Scan Modules → Crypto Asset Results, and surfaces readiness, CBOM inventory, risk register, and migration progress in a single view.

## Context

- **NACSA Arahan 9** is a Malaysian government directive mandating PQC-readiness by 2030 (target: 80% of cryptographic assets at SAFE or PQC-READY status).
- Data flows: `triton-agent` / `triton-portscan` / `triton-sshagent` → Manage Server gateway → outbox drain → Report Server `POST /api/v1/scans`.
- The Report Server currently has no `manage_server_id` on scan rows. This spec adds it.
- The existing `scans` and `findings` tables (with `org_id`, `hostname`, `pqc_status`, etc.) are the source of truth. No new scan data model is introduced.

---

## 1. Backend Changes

### 1.1 `model.ScanMetadata` — new fields

Add to `pkg/model/types.go` `ScanMetadata` struct:

```go
ManageServerID   string `json:"manageServerID,omitempty"`
ManageServerName string `json:"manageServerName,omitempty"`
```

These are stamped by the Manage Server gateway before enqueuing; they are empty for scans submitted directly by legacy agents.

### 1.2 Manage Server gateway — stamp manage server identity

In `pkg/manageserver/agents/handlers_gateway.go` `IngestScan`, after unmarshalling the scan body and before calling `Enqueue`, stamp:

```go
scan.Metadata.ManageServerID   = manageInstanceID   // UUID string of this Manage Server
scan.Metadata.ManageServerName = manageInstanceName  // human-readable name from setup state
```

`manageInstanceID` and `manageInstanceName` are read from the setup state (already available in `GatewayHandlers` via the server config or a new `InstanceInfo` field).

### 1.3 Report Server schema migration

Add a new migration version to `pkg/store/migrations.go`:

```sql
ALTER TABLE scans
  ADD COLUMN IF NOT EXISTS manage_server_id   TEXT,
  ADD COLUMN IF NOT EXISTS manage_server_name TEXT;

ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS manage_server_id TEXT;

CREATE INDEX IF NOT EXISTS idx_scans_manage_server
  ON scans (org_id, manage_server_id)
  WHERE manage_server_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_findings_manage_server
  ON findings (org_id, manage_server_id)
  WHERE manage_server_id IS NOT NULL;
```

### 1.4 Report Server store — persist new columns

Update `SaveScanWithFindings` in `pkg/store/findings.go` to INSERT `manage_server_id` and `manage_server_name` from `result.Metadata.ManageServerID` / `ManageServerName`. Update the findings INSERT to propagate `manage_server_id` to each finding row.

### 1.5 New NACSA API endpoints

Mount under `/api/v1/nacsa` in `pkg/server/server.go`. All endpoints are tenant-scoped (require JWT auth; use `TenantFromContext`). Breadcrumb drill scope is passed as query parameters.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/nacsa/summary` | Tenant-level readiness %, stat counts, top blockers, migration progress |
| GET | `/api/v1/nacsa/servers` | List of Manage Servers for this tenant with readiness % and host count |
| GET | `/api/v1/nacsa/servers/{serverID}/hosts` | Hosts under a specific Manage Server |
| GET | `/api/v1/nacsa/hosts/{hostname}/cbom` | CBOM inventory for a host (filterable by pqc_status) |
| GET | `/api/v1/nacsa/hosts/{hostname}/risk` | Risk register for a host, sortable by score/impact/system |
| GET | `/api/v1/nacsa/migration` | Fasa 1–3 progress, activity list, budget summary |

All endpoints accept optional `?manage_server_id=` and `?hostname=` query params to narrow scope (breadcrumb filtering).

#### Response shapes (abbreviated)

**`/nacsa/summary`**
```json
{
  "readiness_percent": 6.1,
  "target_percent": 80,
  "target_year": 2030,
  "compliant": 607,
  "transitional": 8741,
  "non_compliant": 576,
  "safe": 91,
  "top_blockers": [
    { "algorithm": "RSA-1024", "system": "PTPKM", "severity": "CRITICAL", "asset_count": 7 }
  ],
  "migration_phases": [
    { "phase": 1, "name": "Fasa 1", "status": "complete", "progress_percent": 100 },
    { "phase": 2, "name": "Fasa 2", "status": "in_progress", "progress_percent": 40 },
    { "phase": 3, "name": "Fasa 3", "status": "not_started", "progress_percent": 0 }
  ]
}
```

**`/nacsa/servers`**
```json
{
  "servers": [
    { "id": "uuid", "name": "HQ Server", "host_count": 8, "readiness_percent": 12.4, "last_scan_at": "..." }
  ]
}
```

**`/nacsa/hosts/{hostname}/cbom`** (supports `?status=UNSAFE,TRANSITIONAL`)
```json
{
  "hostname": "ptpkm-srv-01",
  "algorithms": [
    { "algorithm": "RSA-1024", "key_size": 1024, "pqc_status": "UNSAFE", "asset_count": 7, "module": "certificates" }
  ]
}
```

**`/nacsa/hosts/{hostname}/risk`** (supports `?sort=score|impact|system`)
```json
{
  "hostname": "ptpkm-srv-01",
  "risks": [
    {
      "algorithm": "RSA-1024", "system": "PTPKM", "impact": 5, "likelihood": 4,
      "score": 20, "risk_band": "CRITICAL",
      "mitigation": "Upgrade to RSA-4096 or ML-KEM-768", "due_date": "2026-09-30",
      "asset_count": 7
    }
  ]
}
```

**`/nacsa/migration`**
```json
{
  "phases": [
    {
      "phase": 2, "name": "Fasa 2", "status": "in_progress", "progress_percent": 40,
      "period": "2025–2027",
      "activities": [
        { "name": "Inventori kripto lengkap", "status": "done", "budget_rm": 200000 },
        { "name": "Penilaian risiko", "status": "active", "budget_rm": 400000 },
        { "name": "Pelan migrasi PQC", "status": "pending", "budget_rm": 600000 }
      ],
      "budget_total_rm": 1200000,
      "budget_spent_rm": 400000
    }
  ]
}
```

**Risk score calculation**: `score = impact × likelihood` (both 1–5). Risk band: ≥20 = CRITICAL, 10–19 = HIGH, 5–9 = MEDIUM, <5 = LOW. Risk data is derived from the existing `findings` table using PQC status and migration priority as proxies for impact/likelihood, with the following mapping:

| PQC Status | Default Impact | Default Likelihood |
|------------|---------------|-------------------|
| UNSAFE | 5 | 4 |
| TRANSITIONAL | 3 | 3 |
| DEPRECATED | 4 | 2 |
| SAFE | 1 | 1 |

Migration priority field overrides likelihood when present (higher priority = higher likelihood).

**Note**: Migration phase data (Fasa progress, activities, Sumber) is not yet in the scan data model. For Phase 3, this is served from a new `nacsa_migration_phases` table populated manually by admins via a future admin API (out of scope for this spec). When the table is empty (no rows inserted yet), `GET /nacsa/migration` returns an empty `phases` array — the frontend renders a "No migration data configured" notice in place of the Gantt bars.

---

## 2. Frontend Changes

### 2.1 New route

Add `#/nacsa` route to the embedded SPA (`pkg/server/ui/dist/`). The Vite source lives in `pkg/server/ui/src/` (to be built and embedded).

### 2.2 Component structure

```
NacsaDashboard.vue
├── BreadcrumbBar.vue          — persistent across all tabs, drives drill scope
├── TabStrip.vue               — Summary | Inventory | CBOM | Risk | Migration
├── tabs/
│   ├── SummaryTab.vue         — hero bar + 4 stat cards + donut + risk bar + blockers + migration mini
│   ├── InventoryTab.vue       — Manage Servers table → Hosts table → Modules list (drill rows)
│   ├── CbomTab.vue            — filter chips + status-coloured table
│   ├── RiskTab.vue            — sortable register table with expand rows
│   └── MigrationTab.vue       — Gantt progress bars + active phase activity checklist + budget
```

### 2.3 Breadcrumb and drill state

A shared `drillScope` reactive object holds `{ manageServerId, manageServerName, hostname, module }`. All tabs read from `drillScope` and re-fetch when it changes. The BreadcrumbBar renders the current path and provides "click to go up" navigation.

### 2.4 Summary tab

- **Hero readiness bar**: large `%` figure (green), labelled "NACSA Arahan 9 Readiness", progress bar from 0–100 with "Target: 80% by 2030" annotation.
- **4 stat cards**: Compliant (blue) / Transitional (orange) / Non-Compliant (red) / Safe (green).
- **Compliance donut**: Chart.js doughnut, 4 segments.
- **Risk level bar chart**: horizontal bars for CRITICAL/HIGH/MEDIUM/LOW counts.
- **Top blockers**: 2–3 rows showing algorithm + system + severity badge.
- **Migration mini**: compact Fasa 1–3 progress bars (read-only, links to Migration tab).

### 2.5 Inventory tab

Three-level drill:
1. **Manage Servers table** — columns: Name, Hosts, Readiness %, Last Scan. Click row → sets `drillScope.manageServerId`, shows Hosts table.
2. **Hosts table** — columns: Hostname, OS, Scan Profile, Readiness %, Last Scan, Modules. Click row → sets `drillScope.hostname`.
3. **Modules list** — read-only list of modules run on that host with finding counts.

### 2.6 CBOM tab

- Filter chips at top: one per PQC status (Unsafe / Transitional / Safe / PQC-Ready). Active chips = included statuses.
- Table columns: Algorithm · Key Length · Status (badge) · Asset Count · Systems (link). Left-border colour matches status band.
- Sorted by severity descending by default. Clicking "Systems" column link drills into that system in Inventory tab.

### 2.7 Risk tab

- Sortable table: sort toggle buttons (Score ↓ / Impact / System).
- Columns: Algorithm · System · Impact · Likelihood · Score · Plan. Left-border colour = risk band.
- Row click expands an inline panel showing: full mitigation description, due date, asset list.

### 2.8 Migration tab

- Three horizontal progress bars (Fasa 1 / 2 / 3) with % fill, coloured by status (green = done, orange = in progress, grey = not started).
- Active phase section expands below the bars showing:
  - Activity checklist: each row has name, status icon (✓ / → / ○), and budget (RM).
  - Budget summary: Budget total / Spent / Remaining in 3 coloured chips.
- Inactive phases collapse to summary line only.

---

## 3. Navigation sidebar entry

Add "NACSA Arahan 9" under an "Analytics" nav section label in the sidebar (same pattern as existing analytics links).

---

## 4. Data Sources and Derivations

| Dashboard field | Source |
|----------------|--------|
| Readiness % | `AVG` of per-scan `nacsa_readiness_percent` from `scans` summary JSON, filtered to latest scan per host |
| Compliant / Transitional / Non-Compliant / Safe counts | Aggregate from `findings` table `pqc_status` column |
| Top blockers | `findings` grouped by algorithm + hostname, filtered `pqc_status = 'UNSAFE'`, ordered by count desc |
| CBOM inventory | `findings` grouped by algorithm + key_size + pqc_status, filtered by scope |
| Risk scores | Derived from `pqc_status` + `migration_priority` mapping (see §1.5) |
| Manage Server drill | `scans.manage_server_id` / `manage_server_name` (new columns, §1.3) |
| Migration phases | `nacsa_migration_phases` table (new, admin-managed) |

---

## 5. Out of Scope (Phase 3)

- Admin API to edit migration phase activities and budget (Fasa data entry UI)
- Export to Excel / PDF
- Comparison between two scan dates (diff view for NACSA readiness)
- Risk exemption management from this tab (defer to Risk portal)
- Playwright E2E tests for the NACSA dashboard (to be added in Phase 4)

---

## 6. Files Affected

**New:**
- `pkg/server/handlers_nacsa.go` — all 6 NACSA API handlers
- `pkg/server/ui/src/views/NacsaDashboard.vue` (and child components)
- `pkg/store/nacsa.go` — query helpers for NACSA endpoints

**Modified:**
- `pkg/model/types.go` — add `ManageServerID`, `ManageServerName` to `ScanMetadata`
- `pkg/manageserver/agents/handlers_gateway.go` — stamp manage server identity on `IngestScan`
- `pkg/manageserver/agents/handlers_gateway.go` — add `InstanceInfo` field to `GatewayHandlers` (consolidates with the IngestScan change above)
- `pkg/store/migrations.go` — new migration version (manage_server columns + nacsa_migration_phases table)
- `pkg/store/findings.go` — persist `manage_server_id` in `SaveScanWithFindings`
- `pkg/server/server.go` — mount `/api/v1/nacsa/*` routes
- `pkg/server/ui/dist/` — rebuilt SPA with new NACSA route and components
