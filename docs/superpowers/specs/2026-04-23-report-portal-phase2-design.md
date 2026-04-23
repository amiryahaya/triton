# Report Portal Migration — Phase 2 Design

## Overview

Phase 2 of the Report Portal Vue migration ports the three core data views (Overview, Machines, Scans) from stub placeholders to fully functional Vue 3 components backed by real API data. It also adds all data endpoints to the `@triton/api-client` package in one shot — Phases 3 and 4 consume those types and methods without touching api-client again.

**Scope:**
- `web/packages/api-client/src/reportServer.ts` — all data types + methods for Phases 2–4
- `web/apps/report-portal/src/stores/overview.ts` — new
- `web/apps/report-portal/src/stores/machines.ts` — new
- `web/apps/report-portal/src/stores/scans.ts` — new
- `web/apps/report-portal/src/views/Overview.vue` — replace stub
- `web/apps/report-portal/src/views/Machines.vue` — replace stub (handles list + detail)
- `web/apps/report-portal/src/views/Scans.vue` — replace stub (handles list + detail)
- `web/apps/report-portal/tests/views/Overview.spec.ts` — new
- `web/apps/report-portal/tests/views/Machines.spec.ts` — new
- `web/apps/report-portal/tests/views/Scans.spec.ts` — new

**Out of scope (Phase 3):** Inventory, Certificates, Priority, NACSA Arahan 9, MigrationTrend, ScanDiff.
**Out of scope (Phase 4):** Users admin, AuditLog, Playwright E2E rewrites.
**Out of scope (Spec B):** Tenants management, portal setup wizard.

---

## 1. Architecture

### 1.1 Routing — list + detail in one file

The router already maps both list and detail routes to the same view component:

```
/machines              → Machines.vue
/machines/:hostname    → Machines.vue

/scans                 → Scans.vue
/scans/:id             → Scans.vue
```

Each view uses `useRoute().params` to determine mode. A `watch` on the param triggers store fetches when the user navigates between detail pages without unmounting the component.

### 1.2 Crumb bar

`App.vue` already handles detail crumbs generically: `labels['machines']` → "Machines" as the parent link, the route param becomes the leaf label. No App.vue changes needed for Phase 2.

### 1.3 Store pattern

All stores follow the setup-syntax pattern from `manage-portal/src/stores/zones.ts`:

```ts
export const useFooStore = defineStore('foo', () => {
  const items = ref<T[]>([]);
  const loading = ref(false);
  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listFoo(); }
    catch (e) { useToast().error({ title: 'Failed to load foo', description: String(e) }); }
    finally { loading.value = false; }
  }
  return { items, loading, fetch };
});
```

### 1.4 Component library

All views use components from `@triton/ui`:
- `TStatCard` — key metric tiles
- `TDataTable` — tabular data with typed rows (`T extends Record<string, unknown>`)
- `TLineChart` — line chart (`labels: string[], values: number[]`)
- `TBarChart` — bar chart (same props)
- `TPill` — status badges (pqc status, trend direction)
- `TPanel` — card containers

> **TDataTable typing note:** Row types must include `[key: string]: unknown` index signature to satisfy `T extends Record<string, unknown>` in vue-tsc. Use double cast `row as unknown as ConcreteType` when accessing typed fields inside cell slots.

---

## 2. api-client additions

All changes in `web/packages/api-client/src/reportServer.ts`. Types use snake_case to match Go JSON output directly.

### 2.1 New types

```ts
export interface ScanSummary {
  id: string;
  hostname: string;
  org_id: string;
  created_at: string;
  finding_count: number;
  pqc_safe: number;
  pqc_transitional: number;
  pqc_deprecated: number;
  pqc_unsafe: number;
  readiness_pct: number;
}

export interface ScanDetail extends ScanSummary {
  result: Record<string, unknown>;
}

export interface Finding {
  id: string;
  scan_id: string;
  finding_index: number;
  subject: string;
  algorithm: string;
  key_size: number;
  pqc_status: 'SAFE' | 'TRANSITIONAL' | 'DEPRECATED' | 'UNSAFE';
  file_path: string;
  category: string;
  migration_priority: number;
  not_after?: string;
}

export interface SparklinePoint {
  month: string;
  readiness_pct: number;
}

export interface HostSummary {
  hostname: string;
  readiness_pct: number;
  safe_count: number;
  transitional_count: number;
  deprecated_count: number;
  unsafe_count: number;
  sparkline: SparklinePoint[];
  trend_direction: 'improving' | 'declining' | 'stable' | 'insufficient';
  trend_delta_pct: number;
  refreshed_at: string;
}

export interface PolicyVerdictSummary {
  policy_name: string;
  policy_label: string;
  verdict: 'PASS' | 'WARN' | 'FAIL';
  violation_count: number;
  findings_checked: number;
}

export interface MachineHealthTiers {
  red: number;
  yellow: number;
  green: number;
}

export interface TrendMonthPoint {
  month: string;
  readiness_pct: number;
  safe_count: number;
  unsafe_count: number;
}

export interface TrendSummary {
  monthly_points: TrendMonthPoint[];
  direction: 'improving' | 'declining' | 'stable' | 'insufficient';
  delta_pct: number;
}

export interface ProjectionSummary {
  target_pct: number;
  deadline_year: number;
  est_completion_year: number | null;
  on_track: boolean;
}

export interface ReadinessSummary {
  readiness_pct: number;
  safe_count: number;
  transitional_count: number;
  deprecated_count: number;
  unsafe_count: number;
  total_findings: number;
  machine_count: number;
}

export interface PriorityRow {
  subject: string;
  hostname: string;
  algorithm: string;
  pqc_status: 'SAFE' | 'TRANSITIONAL' | 'DEPRECATED' | 'UNSAFE';
  migration_priority: number;
  file_path: string;
  category: string;
}

export interface ExecutiveSummary {
  readiness: ReadinessSummary;
  trend: TrendSummary;
  projection: ProjectionSummary;
  policy_verdicts: PolicyVerdictSummary[];
  top_blockers: PriorityRow[];
  machine_health: MachineHealthTiers;
}

export interface InventoryRow {
  algorithm: string;
  key_size: number;
  pqc_status: 'SAFE' | 'TRANSITIONAL' | 'DEPRECATED' | 'UNSAFE';
  instance_count: number;
  machine_count: number;
  max_priority: number;
}

export interface ExpiringCertRow {
  subject: string;
  hostname: string;
  algorithm: string;
  not_after: string;
  days_remaining: number;
  pqc_status: 'SAFE' | 'TRANSITIONAL' | 'DEPRECATED' | 'UNSAFE';
}

export interface FilterOptions {
  hostnames: string[];
  algorithms: string[];
  pqc_statuses: string[];
}

export interface DiffSummary {
  added: number;
  removed: number;
  changed: number;
}

export interface DiffResult {
  base_id: string;
  compare_id: string;
  added: Finding[];
  removed: Finding[];
  changed: Finding[];
  summary: DiffSummary;
}

export interface OrgTrendResult {
  monthly_points: TrendMonthPoint[];
  direction: string;
  delta_pct: number;
  data_as_of?: string;
  pipeline_lag?: number;
}

export interface AuditEvent {
  id: string;
  org_id: string;
  actor_id: string;
  actor_email: string;
  action: string;
  target_type: string;
  target_id: string;
  created_at: string;
  detail: Record<string, unknown>;
}

export interface User {
  id: string;
  org_id: string;
  email: string;
  name: string;
  role: 'super_admin' | 'org_admin' | 'viewer';
  must_change_password: boolean;
  created_at: string;
}

export interface UserCreate {
  email: string;
  name: string;
  role: 'super_admin' | 'org_admin' | 'viewer';
  temp_password: string;
}

export interface UserUpdate {
  name?: string;
  role?: 'super_admin' | 'org_admin' | 'viewer';
}
```

### 2.2 New methods on `ReportServerApi`

```ts
// Scans
listScans(filter?: { hostname?: string; limit?: number; offset?: number }): Promise<ScanSummary[]>
getScan(id: string): Promise<ScanDetail>
getFindings(id: string): Promise<Finding[]>

// Machines
listMachines(): Promise<HostSummary[]>          // GET /api/v1/systems
getMachineHistory(hostname: string): Promise<ScanSummary[]>  // GET /api/v1/machines/:hostname

// Overview
executive(): Promise<ExecutiveSummary>           // GET /api/v1/executive

// Analytics (used by Phases 3+)
inventory(p?: { hostname?: string; pqc_status?: string }): Promise<InventoryRow[]>
expiringCerts(p?: { within?: number | 'all'; hostname?: string; algorithm?: string }): Promise<ExpiringCertRow[]>
priority(p?: { limit?: number; hostname?: string; pqc_status?: string }): Promise<PriorityRow[]>
filters(): Promise<FilterOptions>

// Trend & diff (used by Phase 3)
orgTrend(hostname?: string): Promise<OrgTrendResult>   // GET /api/v1/trends
diff(base: string, compare: string): Promise<DiffResult>  // GET /api/v1/diff

// Export (used by Phase 3 NACSA view)
exportXlsx(): Promise<Blob>   // GET /api/v1/export/xlsx — returns raw Blob; view creates Blob URL + triggers <a download>

// Admin users (used by Phase 4)
listAdminUsers(): Promise<User[]>
createAdminUser(req: UserCreate): Promise<User>
updateAdminUser(id: string, req: UserUpdate): Promise<User>
deleteAdminUser(id: string): Promise<void>
resendInvite(id: string): Promise<void>

// Admin audit (used by Phase 4)
listAudit(filter?: { limit?: number; offset?: number; actor_id?: string }): Promise<AuditEvent[]>
```

`exportXlsxUrl()` is a pure URL builder (not a fetch call) — it returns the absolute URL with the auth token as a query param or relies on the browser sending the cookie. The caller opens it via `window.open()` to trigger the browser download.

---

## 3. Stores

### 3.1 `stores/overview.ts`

```ts
const summary = ref<ExecutiveSummary | null>(null);
const loading = ref(false);

async function fetch(): Promise<void>  // GET /api/v1/executive
```

Auto-refresh: called on mount and on a 60-second interval (cleared on unmount via `onUnmounted`).

### 3.2 `stores/machines.ts`

```ts
const items = ref<HostSummary[]>([]);         // systems list
const history = ref<ScanSummary[]>([]);       // selected host's scan history
const loading = ref(false);
const historyLoading = ref(false);

async function fetch(): Promise<void>                       // GET /api/v1/systems
async function fetchHistory(hostname: string): Promise<void> // GET /api/v1/machines/:hostname
```

`fetch()` populates `items` (machine list). `fetchHistory()` populates `history` (detail page). The view calls `fetchHistory` on mount when `params.hostname` is set, and watches `params.hostname` for changes.

### 3.3 `stores/scans.ts`

```ts
const items = ref<ScanSummary[]>([]);
const detail = ref<ScanDetail | null>(null);
const findings = ref<Finding[]>([]);
const loading = ref(false);
const detailLoading = ref(false);

async function fetch(): Promise<void>          // GET /api/v1/scans
async function fetchDetail(id: string): Promise<void>  // GET /api/v1/scans/:id + /findings
```

`fetchDetail` fires both `getScan` and `getFindings` in parallel via `Promise.all`.

---

## 4. Views

### 4.1 Overview.vue

```
┌─────────────────────────────────────────────────────────┐
│  Readiness  XX%    [NACSA-2030: PASS]  [CNSA-2.0: WARN] │  exec summary bar
├──────────┬──────────┬──────────┬───────────┬────────────┤
│   Safe   │  Trans.  │  Depr.   │   Unsafe  │  Machines  │  TStatCard × 5
├──────────┴──────────┴──────────┴───────────┴────────────┤
│  PQC Readiness trend  (TLineChart, monthly readiness%)  │
├─────────────────────────────────────────────────────────┤
│  Top priority blockers  [subject | algo | host] … →     │  TDataTable (5 rows max)
│                                          View all →      │  links to #/priority
└─────────────────────────────────────────────────────────┘
```

**Data mapping:**
- Readiness %: `summary.readiness.readiness_pct`
- Policy chips: `summary.policy_verdicts[]` — `TPill` variant: PASS=`success`, WARN=`warn`, FAIL=`danger`
- Stat cards: `summary.machine_health` (red/yellow/green tiers) + `summary.readiness` counts
- Trend chart: `summary.trend.monthly_points` → `labels: point.month[]`, `values: point.readiness_pct[]`
- Blockers strip: `summary.top_blockers` (max 5), link to `#/priority`
- Loading: full-page spinner while `loading` is true
- Empty: "No data yet — submit a scan to see results" when `summary` is null after load

### 4.2 Machines.vue

**List mode** (no `params.hostname`): calls `store.fetch()` on mount.

```
TDataTable columns:
  hostname (link → /machines/:hostname) | readiness% | safe | trans | depr | unsafe
  | trend (TPill: improving=green, declining=red, stable=muted, insufficient=muted)
  | last scan (formatted date from refreshed_at)

Row type:
  interface MachineRow {
    hostname: string; readiness_pct: number;
    safe_count: number; transitional_count: number;
    deprecated_count: number; unsafe_count: number;
    trend_direction: string; refreshed_at: string;
    [key: string]: unknown;
  }

Row click: router.push(`/machines/${row.hostname}`)
Default sort: readiness_pct ASC (worst first)
```

**Detail mode** (`params.hostname` set): calls `store.fetchHistory(hostname)` on mount + watches param.

```
┌──────────┬──────────┬──────────┬──────────┐
│   Safe   │  Trans.  │  Depr.   │  Unsafe  │   TStatCard × 4 (from latest history entry)
└──────────┴──────────┴──────────┴──────────┘
TLineChart: readiness over time
  labels: history[].created_at (formatted as date)
  values: history[].readiness_pct

TDataTable — scan history:
  date | findings | safe | trans | depr | unsafe | readiness%
  Row click: router.push(`/scans/${row.id}`)
```

### 4.3 Scans.vue

**List mode** (no `params.id`): calls `store.fetch()` on mount.

```
TDataTable columns:
  date (created_at) | hostname | findings | safe | trans | depr | unsafe | readiness%
  Row click: router.push(`/scans/${row.id}`)

Row type:
  interface ScanRow extends ScanSummary { [key: string]: unknown }
```

**Detail mode** (`params.id` set): calls `store.fetchDetail(id)` on mount + watches param.

```
┌──────────┬──────────┬──────────┬──────────┐
│   Safe   │  Trans.  │  Depr.   │  Unsafe  │   TStatCard × 4
└──────────┴──────────┴──────────┴──────────┘
TDataTable — findings:
  subject | algorithm | key_size | pqc_status (TPill) | category | file_path | priority
  Default sort: migration_priority DESC

Finding row type:
  interface FindingRow {
    id: string; subject: string; algorithm: string; key_size: number;
    pqc_status: string; category: string; file_path: string;
    migration_priority: number;
    [key: string]: unknown;
  }

TPill variant map: SAFE=success, TRANSITIONAL=warn, DEPRECATED=danger, UNSAFE=danger
```

---

## 5. Tests

### 5.1 `tests/views/Overview.spec.ts`

Uses `createTestingPinia({ createSpy: vi.fn, stubActions: true, initialState: { overview: { summary, loading: false } } })`.

| # | Test |
|---|------|
| 1 | renders readiness % and policy verdict chips from stubbed summary |
| 2 | renders 5 stat cards with correct values from machine_health |
| 3 | renders "No data yet" empty state when summary is null |

### 5.2 `tests/views/Machines.spec.ts`

| # | Test |
|---|------|
| 1 | list mode: renders hostname rows from stubbed items |
| 2 | list mode: row click pushes `/machines/:hostname` to router |
| 3 | detail mode: renders 4 stat cards from stubbed history |
| 4 | detail mode: calls fetchHistory on mount with correct hostname |

### 5.3 `tests/views/Scans.spec.ts`

| # | Test |
|---|------|
| 1 | list mode: renders scan rows from stubbed items |
| 2 | list mode: row click pushes `/scans/:id` to router |
| 3 | detail mode: renders findings table from stubbed findings |
| 4 | detail mode: calls fetchDetail on mount with correct scan id |

---

## 6. Non-obvious decisions

- **`exportXlsx()` returns a Blob:** The export endpoint is behind JWT auth — `window.open(url)` cannot send the Authorization header. The view fetches the Blob, creates a temporary `URL.createObjectURL` anchor, clicks it, then revokes the URL. The `Http` interface needs a `getBlob(path)` method (or raw `fetch` call with the stored token) to support this.
- **`getMachineHistory` maps to `/api/v1/machines/:hostname`** (returns `ScanSummary[]`) not `/api/v1/systems` (returns `HostSummary[]`). The systems endpoint is for the list; the machines/:hostname endpoint is for the per-host scan history.
- **`listMachines` maps to `/api/v1/systems`** not `/api/v1/machines`. The `/machines` endpoint returns scan history, not the host summary list. Naming intentionally differs from the URL to be semantically clear.
- **No detail route files created:** The router already points detail paths to the same view files. Creating `MachineDetail.vue` and `ScanDetail.vue` would duplicate the shell and make crumb wiring harder.
- **`fetchDetail` uses `Promise.all`** for `getScan` + `getFindings` — these are independent reads, parallelising them halves the perceived latency on the detail page.
