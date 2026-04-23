# Report Portal Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port three core Report Portal views (Overview, Machines list+detail, Scans list+detail) from stub placeholders to fully functional Vue 3 components, and add all data-API types + methods to `@triton/api-client` in one shot.

**Architecture:** Pinia stores wrap the extended `@triton/api-client`; Vue views consume stores; both list and detail routes point to the same `.vue` file and switch on `useRoute().params`. Vitest component tests drive view development TDD-style.

**Tech Stack:** Vue 3 (Composition API, setup syntax) · Pinia (setup stores) · vue-router 4 (hash history) · @triton/ui (TStatCard, TDataTable, TLineChart, TPill) · @triton/api-client (typed REST wrapper) · Vitest + @pinia/testing + @vue/test-utils · TypeScript / vue-tsc.

**Spec:** `docs/superpowers/specs/2026-04-23-report-portal-phase2-design.md`

---

## File structure

**Create:**
- `web/apps/report-portal/vitest.config.ts`
- `web/apps/report-portal/tests/views/Overview.spec.ts`
- `web/apps/report-portal/tests/views/Machines.spec.ts`
- `web/apps/report-portal/tests/views/Scans.spec.ts`
- `web/apps/report-portal/src/stores/overview.ts`
- `web/apps/report-portal/src/stores/machines.ts`
- `web/apps/report-portal/src/stores/scans.ts`

**Modify:**
- `web/apps/report-portal/package.json` — add `@pinia/testing` devDep
- `web/packages/api-client/src/reportServer.ts` — add types + methods
- `web/apps/report-portal/src/views/Overview.vue` — replace stub
- `web/apps/report-portal/src/views/Machines.vue` — replace stub
- `web/apps/report-portal/src/views/Scans.vue` — replace stub

---

## Task 0: Set up worktree

Use the `superpowers:using-git-worktrees` skill to create a worktree at `.worktrees/report-portal-phase2` on branch `feat/report-portal-phase-2` from `main`.

- [ ] **Step 1: Create worktree + install deps**

```bash
git worktree add .worktrees/report-portal-phase2 -b feat/report-portal-phase-2
cd .worktrees/report-portal-phase2/web
pnpm install
```

- [ ] **Step 2: Verify baseline tests pass**

```bash
cd .worktrees/report-portal-phase2/web
pnpm test
```
Expected: all existing tests pass (manage-portal, api-client, auth, ui). Report portal has no tests yet — the `--passWithNoTests` flag is set in its package.json.

All subsequent tasks are run from `.worktrees/report-portal-phase2/`.

---

## Task 1: Add vitest config + @pinia/testing dep to report-portal

**Files:**
- Create: `web/apps/report-portal/vitest.config.ts`
- Modify: `web/apps/report-portal/package.json`

- [ ] **Step 1: Create vitest.config.ts**

Create `web/apps/report-portal/vitest.config.ts`:

```ts
import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['tests/**/*.spec.ts', 'src/**/*.spec.ts'],
  },
});
```

- [ ] **Step 2: Add @pinia/testing dep**

Edit `web/apps/report-portal/package.json` — add to `devDependencies`:

```json
"@pinia/testing": "^0.1.7",
```

Resulting devDependencies block:
```json
"devDependencies": {
  "@pinia/testing": "^0.1.7",
  "@vitejs/plugin-vue": "^5.2.1",
  "@vue/test-utils": "^2.4.6",
  "jsdom": "^25.0.1",
  "vite": "^5.4.11",
  "vitest": "^2.1.8",
  "vue-tsc": "^2.1.10"
}
```

- [ ] **Step 3: Install the new dep**

```bash
cd web && pnpm install
```
Expected: lockfile updates, no errors.

- [ ] **Step 4: Verify the workspace picks up the new vitest.config.ts**

```bash
cd web && pnpm test
```
Expected: workspace picks up report-portal tests dir (none yet) and reports "no tests" for report-portal — the other packages' tests still pass.

- [ ] **Step 5: Commit**

```bash
cd .worktrees/report-portal-phase2
git add web/apps/report-portal/vitest.config.ts web/apps/report-portal/package.json web/pnpm-lock.yaml
git commit -m "test(report-portal): add vitest config and @pinia/testing dep

Report Portal Phase 2 prep — enables component tests."
```

---

## Task 2: api-client — add Phase 2-4 types

**Files:**
- Modify: `web/packages/api-client/src/reportServer.ts`

- [ ] **Step 1: Open reportServer.ts and add all type definitions before `createReportApi`**

Insert this block immediately after the existing `ChangePasswordResponse` interface (around line 28) and before the JSDoc comment for `createReportApi`:

```ts
// ===== Data types (Phase 2-4) =====

export type PqcStatus = 'SAFE' | 'TRANSITIONAL' | 'DEPRECATED' | 'UNSAFE';
export type TrendDirection = 'improving' | 'declining' | 'stable' | 'insufficient';
export type UserRole = 'super_admin' | 'org_admin' | 'viewer';

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
  pqc_status: PqcStatus;
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
  trend_direction: TrendDirection;
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
  direction: TrendDirection;
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
  pqc_status: PqcStatus;
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
  pqc_status: PqcStatus;
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
  pqc_status: PqcStatus;
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

export interface ReportUser {
  id: string;
  org_id: string;
  email: string;
  name: string;
  role: UserRole;
  must_change_password: boolean;
  created_at: string;
}

export interface ReportUserCreate {
  email: string;
  name: string;
  role: UserRole;
  temp_password: string;
}

export interface ReportUserUpdate {
  name?: string;
  role?: UserRole;
}
```

Note the `Report` prefix on `ReportUser*` types — avoids collision with the pre-existing `User` type in `@triton/api-client` that belongs to the manage-portal domain.

- [ ] **Step 2: Type-check the package**

```bash
cd web && pnpm --filter @triton/api-client exec tsc --noEmit
```
Expected: no errors. Types compile cleanly.

- [ ] **Step 3: Commit**

```bash
cd .worktrees/report-portal-phase2
git add web/packages/api-client/src/reportServer.ts
git commit -m "feat(api-client): add Report Server data types

Phase 2 of the Report Portal migration — types for scans,
machines, findings, executive summary, inventory, certs,
priority, diff, trend, audit, admin users."
```

---

## Task 3: api-client — add Phase 2-4 methods

**Files:**
- Modify: `web/packages/api-client/src/reportServer.ts`

- [ ] **Step 1: Extend createReportApi with all method implementations**

Replace the existing `createReportApi` return object with the expanded surface. Find:

```ts
export function createReportApi(http: Http) {
  return {
    login: (req: LoginRequest) => http.post<LoginResponse>('/v1/auth/login', req),
    logout: () => http.post<{ status: string }>('/v1/auth/logout', {}),
    refresh: () => http.post<RefreshResponse>('/v1/auth/refresh', {}),
    changePassword: (req: ChangePasswordRequest) =>
      http.post<ChangePasswordResponse>('/v1/auth/change-password', req),
  };
}
```

Replace with:

```ts
export function createReportApi(http: Http) {
  return {
    // Auth (Phase 1 — unchanged)
    login: (req: LoginRequest) => http.post<LoginResponse>('/v1/auth/login', req),
    logout: () => http.post<{ status: string }>('/v1/auth/logout', {}),
    refresh: () => http.post<RefreshResponse>('/v1/auth/refresh', {}),
    changePassword: (req: ChangePasswordRequest) =>
      http.post<ChangePasswordResponse>('/v1/auth/change-password', req),

    // Scans (Phase 2)
    listScans: (filter?: { hostname?: string; limit?: number; offset?: number }) => {
      const qs = buildQS(filter);
      return http.get<ScanSummary[]>(`/v1/scans${qs}`);
    },
    getScan: (id: string) => http.get<ScanDetail>(`/v1/scans/${encodeURIComponent(id)}`),
    getFindings: (id: string) =>
      http.get<Finding[]>(`/v1/scans/${encodeURIComponent(id)}/findings`),

    // Machines (Phase 2)
    listMachines: () => http.get<HostSummary[]>('/v1/systems'),
    getMachineHistory: (hostname: string) =>
      http.get<ScanSummary[]>(`/v1/machines/${encodeURIComponent(hostname)}`),

    // Overview (Phase 2)
    executive: () => http.get<ExecutiveSummary>('/v1/executive'),
    aggregate: () => http.get<Record<string, number>>('/v1/aggregate'),

    // Analytics (Phase 3)
    inventory: (p?: { hostname?: string; pqc_status?: string }) =>
      http.get<InventoryRow[]>(`/v1/inventory${buildQS(p)}`),
    expiringCerts: (p?: { within?: number | 'all'; hostname?: string; algorithm?: string }) =>
      http.get<ExpiringCertRow[]>(`/v1/certificates/expiring${buildQS(p)}`),
    priority: (p?: { limit?: number; hostname?: string; pqc_status?: string }) =>
      http.get<PriorityRow[]>(`/v1/priority${buildQS(p)}`),
    filters: () => http.get<FilterOptions>('/v1/filters'),
    orgTrend: (hostname?: string) =>
      http.get<OrgTrendResult>(`/v1/trends${hostname ? `?hostname=${encodeURIComponent(hostname)}` : ''}`),
    diff: (base: string, compare: string) =>
      http.get<DiffResult>(
        `/v1/diff?base=${encodeURIComponent(base)}&compare=${encodeURIComponent(compare)}`,
      ),

    // Admin users (Phase 4)
    listAdminUsers: () => http.get<ReportUser[]>('/v1/admin/users/'),
    createAdminUser: (req: ReportUserCreate) =>
      http.post<ReportUser>('/v1/admin/users/', req),
    updateAdminUser: (id: string, req: ReportUserUpdate) =>
      http.put<ReportUser>(`/v1/admin/users/${encodeURIComponent(id)}`, req),
    deleteAdminUser: (id: string) =>
      http.del<{ status: string }>(`/v1/admin/users/${encodeURIComponent(id)}`),
    resendInvite: (id: string) =>
      http.post<{ status: string }>(`/v1/admin/users/${encodeURIComponent(id)}/resend-invite`, {}),

    // Admin audit (Phase 4)
    listAudit: (filter?: { limit?: number; offset?: number; actor_id?: string }) =>
      http.get<AuditEvent[]>(`/v1/admin/audit/${buildQS(filter)}`),
  };
}

// buildQS serialises a flat record into a leading-`?` query string.
// Undefined / empty values are skipped so callers can pass partial
// filter objects without conditional URL construction at call sites.
function buildQS(params?: Record<string, string | number | boolean | undefined>): string {
  if (!params) return '';
  const pairs: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    pairs.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
  }
  return pairs.length ? `?${pairs.join('&')}` : '';
}
```

- [ ] **Step 2: Type-check**

```bash
cd web && pnpm --filter @triton/api-client exec tsc --noEmit
```
Expected: no errors.

- [ ] **Step 3: Verify report-portal also type-checks (consumer side)**

```bash
cd web && pnpm --filter report-portal exec vue-tsc --noEmit
```
Expected: no errors — the views are still stubs that don't reference the new types yet.

- [ ] **Step 4: Commit**

```bash
cd .worktrees/report-portal-phase2
git add web/packages/api-client/src/reportServer.ts
git commit -m "feat(api-client): add Report Server data methods

Phase 2 of the Report Portal migration — methods for scans,
machines, executive, inventory, certs, priority, diff, trend,
audit, admin users. Query strings built via buildQS helper."
```

---

## Task 4: Overview store

**Files:**
- Create: `web/apps/report-portal/src/stores/overview.ts`

- [ ] **Step 1: Write the store**

Create `web/apps/report-portal/src/stores/overview.ts`:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { ExecutiveSummary } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useOverviewStore = defineStore('overview', () => {
  const summary = ref<ExecutiveSummary | null>(null);
  const loading = ref(false);

  async function fetch(): Promise<void> {
    const api = useApiClient().get();
    loading.value = true;
    try {
      summary.value = await api.executive();
    } catch (e) {
      useToast().error({
        title: 'Failed to load overview',
        description: String(e),
      });
    } finally {
      loading.value = false;
    }
  }

  return { summary, loading, fetch };
});
```

- [ ] **Step 2: Type-check**

```bash
cd web && pnpm --filter report-portal exec vue-tsc --noEmit
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
cd .worktrees/report-portal-phase2
git add web/apps/report-portal/src/stores/overview.ts
git commit -m "feat(report-portal): add overview store

Wraps /v1/executive with Pinia state + toast error handling."
```

---

## Task 5: Overview view (TDD)

**Files:**
- Create: `web/apps/report-portal/tests/views/Overview.spec.ts`
- Modify: `web/apps/report-portal/src/views/Overview.vue`

- [ ] **Step 1: Write the failing component test**

Create `web/apps/report-portal/tests/views/Overview.spec.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Overview from '../../src/views/Overview.vue';
import { useOverviewStore } from '../../src/stores/overview';

beforeEach(() => {
  vi.clearAllMocks();
});

const SUMMARY = {
  readiness: {
    readiness_pct: 67,
    safe_count: 120,
    transitional_count: 45,
    deprecated_count: 18,
    unsafe_count: 7,
    total_findings: 190,
    machine_count: 12,
  },
  trend: {
    monthly_points: [
      { month: '2026-01', readiness_pct: 55, safe_count: 90, unsafe_count: 10 },
      { month: '2026-02', readiness_pct: 60, safe_count: 100, unsafe_count: 9 },
      { month: '2026-03', readiness_pct: 67, safe_count: 120, unsafe_count: 7 },
    ],
    direction: 'improving',
    delta_pct: 12,
  },
  projection: {
    target_pct: 80,
    deadline_year: 2030,
    est_completion_year: 2029,
    on_track: true,
  },
  policy_verdicts: [
    { policy_name: 'nacsa-2030', policy_label: 'NACSA-2030', verdict: 'PASS', violation_count: 0, findings_checked: 190 },
    { policy_name: 'cnsa-2.0',   policy_label: 'CNSA-2.0',   verdict: 'WARN', violation_count: 3, findings_checked: 190 },
  ],
  top_blockers: [
    { subject: 'rsa-1024-key', hostname: 'app01', algorithm: 'RSA-1024', pqc_status: 'UNSAFE', migration_priority: 95, file_path: '/etc/ssl/old.key', category: 'key' },
  ],
  machine_health: { red: 2, yellow: 4, green: 6 },
};

function mountWithSummary(summary: typeof SUMMARY | null = SUMMARY) {
  return mount(Overview, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          stubActions: true,
          initialState: { overview: { summary, loading: false } },
        }),
      ],
      stubs: { TLineChart: true, TDataTable: true },
    },
  });
}

describe('Overview view', () => {
  it('calls fetch on mount and renders readiness + policy verdict chips', async () => {
    const wrapper = mountWithSummary();
    const store = useOverviewStore();
    await flushPromises();

    expect(store.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('67');        // readiness_pct
    expect(html).toContain('NACSA-2030');
    expect(html).toContain('CNSA-2.0');
    wrapper.unmount();
  });

  it('renders stat cards with machine_health + readiness counts', async () => {
    const wrapper = mountWithSummary();
    await flushPromises();

    const html = wrapper.html();
    expect(html).toContain('120'); // safe_count
    expect(html).toContain('45');  // transitional_count
    expect(html).toContain('18');  // deprecated_count
    expect(html).toContain('7');   // unsafe_count
    expect(html).toContain('12');  // machine_count
    wrapper.unmount();
  });

  it('renders empty state when summary is null', async () => {
    const wrapper = mountWithSummary(null);
    await flushPromises();

    const html = wrapper.html();
    expect(html).toMatch(/no data/i);
    wrapper.unmount();
  });
});
```

- [ ] **Step 2: Run the tests to confirm they fail**

```bash
cd web && pnpm --filter report-portal test
```
Expected: 3 failures — the Overview stub just renders `<h1>Overview</h1>` and doesn't call `fetch`.

- [ ] **Step 3: Implement Overview.vue**

Replace `web/apps/report-portal/src/views/Overview.vue` contents with:

```vue
<script setup lang="ts">
import { computed, onMounted } from 'vue';
import { TStatCard, TPill, TLineChart } from '@triton/ui';
import type { PillVariant } from '@triton/ui';
import type { PolicyVerdictSummary } from '@triton/api-client';
import { useOverviewStore } from '../stores/overview';

const overview = useOverviewStore();

onMounted(() => { void overview.fetch(); });

const readinessPct = computed(() => overview.summary?.readiness.readiness_pct ?? 0);
const readiness = computed(() => overview.summary?.readiness);
const health = computed(() => overview.summary?.machine_health);
const verdicts = computed<PolicyVerdictSummary[]>(() => overview.summary?.policy_verdicts ?? []);
const blockers = computed(() => (overview.summary?.top_blockers ?? []).slice(0, 5));

const trendLabels = computed(() =>
  (overview.summary?.trend.monthly_points ?? []).map((p) => p.month),
);
const trendValues = computed(() =>
  (overview.summary?.trend.monthly_points ?? []).map((p) => p.readiness_pct),
);

function verdictVariant(v: PolicyVerdictSummary['verdict']): PillVariant {
  if (v === 'PASS') return 'safe';
  if (v === 'WARN') return 'warn';
  return 'unsafe';
}
</script>

<template>
  <section class="overview-view">
    <div v-if="!overview.summary" class="overview-empty">
      <p>No data yet — submit a scan to see results.</p>
    </div>

    <template v-else>
      <header class="exec-bar">
        <div class="exec-readiness">
          <span class="exec-label">Readiness</span>
          <span class="exec-value">{{ readinessPct }}%</span>
        </div>
        <div class="exec-chips">
          <TPill
            v-for="v in verdicts"
            :key="v.policy_name"
            :variant="verdictVariant(v.verdict)"
          >
            {{ v.policy_label }}: {{ v.verdict }}
          </TPill>
        </div>
      </header>

      <div class="stat-row">
        <TStatCard label="Safe" :value="readiness?.safe_count ?? 0" />
        <TStatCard label="Transitional" :value="readiness?.transitional_count ?? 0" />
        <TStatCard label="Deprecated" :value="readiness?.deprecated_count ?? 0" />
        <TStatCard label="Unsafe" :value="readiness?.unsafe_count ?? 0" />
        <TStatCard
          label="Machines"
          :value="readiness?.machine_count ?? 0"
          :delta="health ? `${health.green} green · ${health.yellow} warn · ${health.red} critical` : undefined"
        />
      </div>

      <section class="panel">
        <h2>PQC readiness trend</h2>
        <TLineChart :labels="trendLabels" :values="trendValues" />
      </section>

      <section class="panel">
        <div class="panel-head">
          <h2>Top priority blockers</h2>
          <a href="#/priority" class="view-all">View all →</a>
        </div>
        <ul v-if="blockers.length" class="blockers">
          <li v-for="b in blockers" :key="`${b.hostname}|${b.subject}`">
            <span class="b-host">{{ b.hostname }}</span>
            <span class="b-algo">{{ b.algorithm }}</span>
            <span class="b-subject">{{ b.subject }}</span>
            <span class="b-prio">{{ b.migration_priority }}</span>
          </li>
        </ul>
        <p v-else class="blockers-empty">No blockers at the moment.</p>
      </section>
    </template>
  </section>
</template>

<style scoped>
.overview-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.overview-empty {
  padding: var(--space-6);
  text-align: center;
  color: var(--text-muted);
}
.exec-bar {
  display: flex;
  align-items: center;
  gap: var(--space-4);
  padding: var(--space-3) var(--space-4);
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
}
.exec-readiness { display: flex; align-items: baseline; gap: var(--space-2); }
.exec-label {
  font-size: 0.58rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text-subtle);
}
.exec-value {
  font-family: var(--font-display);
  font-size: 1.85rem;
  font-weight: 600;
  color: var(--text-primary);
}
.exec-chips { display: flex; gap: var(--space-2); margin-left: auto; }
.stat-row {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: var(--space-3);
}
.panel {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: var(--space-4);
}
.panel h2 {
  margin: 0 0 var(--space-3);
  font-family: var(--font-display);
  font-size: 1rem;
  font-weight: 500;
}
.panel-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  margin-bottom: var(--space-3);
}
.panel-head h2 { margin: 0; }
.view-all {
  font-size: 0.72rem;
  color: var(--accent-strong);
  text-decoration: none;
}
.blockers {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}
.blockers li {
  display: grid;
  grid-template-columns: 1.2fr 1fr 2fr 60px;
  gap: var(--space-3);
  align-items: center;
  padding: var(--space-2);
  background: var(--bg-elevated);
  border-radius: var(--radius-sm);
  font-size: 0.76rem;
}
.b-host { color: var(--text-primary); font-weight: 500; }
.b-algo { color: var(--text-secondary); }
.b-subject { color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; }
.b-prio {
  text-align: right;
  font-family: var(--font-display);
  font-variant-numeric: tabular-nums;
  color: var(--accent-strong);
}
.blockers-empty { color: var(--text-muted); font-size: 0.78rem; }
</style>
```

- [ ] **Step 4: Verify TPill exports `PillVariant`**

```bash
cd web && grep -n "PillVariant" packages/ui/src/index.ts packages/ui/src/atoms/TPill.vue
```
Expected: `PillVariant` is declared in `TPill.vue` and must be re-exported from `packages/ui/src/index.ts`. If it's not re-exported, add it.

- [ ] **Step 5: Re-export PillVariant if missing**

Open `web/packages/ui/src/index.ts`. Find the TPill export line (likely `export { default as TPill } from './atoms/TPill.vue';`). Directly below, add:

```ts
export type { PillVariant } from './atoms/TPill.vue';
```

Skip this step if the type re-export already exists.

- [ ] **Step 6: Run the tests**

```bash
cd web && pnpm --filter report-portal test
```
Expected: 3 passing tests.

- [ ] **Step 7: vue-tsc sanity check**

```bash
cd web && pnpm --filter report-portal exec vue-tsc --noEmit
```
Expected: no errors.

- [ ] **Step 8: Commit**

```bash
cd .worktrees/report-portal-phase2
git add web/apps/report-portal/src/views/Overview.vue \
        web/apps/report-portal/tests/views/Overview.spec.ts \
        web/packages/ui/src/index.ts
git commit -m "feat(report-portal): implement Overview view

Renders executive summary bar (readiness + policy verdict chips),
5 stat cards (safe/trans/depr/unsafe/machines), readiness trend
line chart, and top-5 priority blockers strip with link to
#/priority. Empty state when summary is null.

3 Vitest component tests covering render, counts, empty state."
```

---

## Task 6: Machines store

**Files:**
- Create: `web/apps/report-portal/src/stores/machines.ts`

- [ ] **Step 1: Write the store**

Create `web/apps/report-portal/src/stores/machines.ts`:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { HostSummary, ScanSummary } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useMachinesStore = defineStore('machines', () => {
  const items = ref<HostSummary[]>([]);
  const history = ref<ScanSummary[]>([]);
  const loading = ref(false);
  const historyLoading = ref(false);

  async function fetch(): Promise<void> {
    const api = useApiClient().get();
    loading.value = true;
    try {
      items.value = await api.listMachines();
    } catch (e) {
      useToast().error({
        title: 'Failed to load machines',
        description: String(e),
      });
    } finally {
      loading.value = false;
    }
  }

  async function fetchHistory(hostname: string): Promise<void> {
    const api = useApiClient().get();
    historyLoading.value = true;
    try {
      history.value = await api.getMachineHistory(hostname);
    } catch (e) {
      useToast().error({
        title: `Failed to load history for ${hostname}`,
        description: String(e),
      });
    } finally {
      historyLoading.value = false;
    }
  }

  return { items, history, loading, historyLoading, fetch, fetchHistory };
});
```

- [ ] **Step 2: Type-check**

```bash
cd web && pnpm --filter report-portal exec vue-tsc --noEmit
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
cd .worktrees/report-portal-phase2
git add web/apps/report-portal/src/stores/machines.ts
git commit -m "feat(report-portal): add machines store

Combines /v1/systems (list) and /v1/machines/:hostname (scan
history per host) into a single store with separate loading
flags — the detail view can fetch history without re-fetching
the full list."
```

---

## Task 7: Machines view (TDD, list + detail)

**Files:**
- Create: `web/apps/report-portal/tests/views/Machines.spec.ts`
- Modify: `web/apps/report-portal/src/views/Machines.vue`

- [ ] **Step 1: Write the failing component tests**

Create `web/apps/report-portal/tests/views/Machines.spec.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';
import Machines from '../../src/views/Machines.vue';
import { useMachinesStore } from '../../src/stores/machines';

beforeEach(() => {
  vi.clearAllMocks();
});

const HOST_A = {
  hostname: 'app01', readiness_pct: 72,
  safe_count: 40, transitional_count: 10, deprecated_count: 4, unsafe_count: 2,
  sparkline: [], trend_direction: 'improving', trend_delta_pct: 5,
  refreshed_at: '2026-04-22T10:00:00Z',
};
const HOST_B = {
  hostname: 'db01', readiness_pct: 45,
  safe_count: 20, transitional_count: 18, deprecated_count: 12, unsafe_count: 5,
  sparkline: [], trend_direction: 'declining', trend_delta_pct: -3,
  refreshed_at: '2026-04-22T10:05:00Z',
};
const SCAN_1 = {
  id: 'scan-1', hostname: 'app01', org_id: 'o1', created_at: '2026-04-20T10:00:00Z',
  finding_count: 56, pqc_safe: 40, pqc_transitional: 10, pqc_deprecated: 4, pqc_unsafe: 2, readiness_pct: 72,
};

function makeRouter(path: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/machines', name: 'machines', component: { template: '<div/>' } },
      { path: '/machines/:hostname', name: 'machine', component: { template: '<div/>' } },
      { path: '/scans/:id', name: 'scan', component: { template: '<div/>' } },
      { path: '/', component: { template: '<div/>' } },
    ],
  });
  router.push(path);
  return router;
}

async function mountAt(path: string, state: { items?: unknown[]; history?: unknown[] } = {}) {
  const router = makeRouter(path);
  await router.isReady();
  return mount(Machines, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          stubActions: true,
          initialState: {
            machines: {
              items: state.items ?? [],
              history: state.history ?? [],
              loading: false,
              historyLoading: false,
            },
          },
        }),
        router,
      ],
      stubs: { TLineChart: true },
    },
  });
}

describe('Machines view — list mode', () => {
  it('calls fetch on mount and renders hostname rows', async () => {
    const wrapper = await mountAt('/machines', { items: [HOST_A, HOST_B] });
    const store = useMachinesStore();
    await flushPromises();

    expect(store.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('app01');
    expect(html).toContain('db01');
    expect(html).toContain('72');  // readiness_pct
    wrapper.unmount();
  });

  it('clicking a row navigates to /machines/:hostname', async () => {
    const wrapper = await mountAt('/machines', { items: [HOST_A] });
    await flushPromises();

    const row = wrapper.find('[data-test="machine-row-app01"]');
    expect(row.exists()).toBe(true);
    await row.trigger('click');
    await flushPromises();

    expect(wrapper.vm.$route.path).toBe('/machines/app01');
    wrapper.unmount();
  });
});

describe('Machines view — detail mode', () => {
  it('calls fetchHistory on mount with hostname from route param', async () => {
    const wrapper = await mountAt('/machines/app01', { history: [SCAN_1] });
    const store = useMachinesStore();
    await flushPromises();

    expect(store.fetchHistory).toHaveBeenCalledWith('app01');
    wrapper.unmount();
  });

  it('renders stat cards + findings from latest history entry', async () => {
    const wrapper = await mountAt('/machines/app01', { history: [SCAN_1] });
    await flushPromises();

    const html = wrapper.html();
    expect(html).toContain('40'); // safe
    expect(html).toContain('10'); // transitional
    expect(html).toContain('4');  // deprecated
    expect(html).toContain('2');  // unsafe
    wrapper.unmount();
  });
});
```

- [ ] **Step 2: Run the tests to confirm they fail**

```bash
cd web && pnpm --filter report-portal test -- tests/views/Machines.spec.ts
```
Expected: 4 failures.

- [ ] **Step 3: Implement Machines.vue**

Replace `web/apps/report-portal/src/views/Machines.vue`:

```vue
<script setup lang="ts">
import { computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  TStatCard,
  TDataTable,
  TLineChart,
  TPill,
  type Column,
  type PillVariant,
} from '@triton/ui';
import type { TrendDirection } from '@triton/api-client';
import { useMachinesStore } from '../stores/machines';

const route = useRoute();
const router = useRouter();
const store = useMachinesStore();

const hostname = computed(() =>
  typeof route.params.hostname === 'string' ? route.params.hostname : '',
);
const isDetail = computed(() => hostname.value.length > 0);

interface MachineRow {
  hostname: string;
  readiness_pct: number;
  safe_count: number;
  transitional_count: number;
  deprecated_count: number;
  unsafe_count: number;
  trend_direction: TrendDirection;
  refreshed_at: string;
  [key: string]: unknown;
}

const rows = computed<MachineRow[]>(() =>
  [...store.items]
    .sort((a, b) => a.readiness_pct - b.readiness_pct)
    .map((m) => ({
      hostname: m.hostname,
      readiness_pct: m.readiness_pct,
      safe_count: m.safe_count,
      transitional_count: m.transitional_count,
      deprecated_count: m.deprecated_count,
      unsafe_count: m.unsafe_count,
      trend_direction: m.trend_direction,
      refreshed_at: m.refreshed_at,
    })),
);

const columns: Column<MachineRow>[] = [
  { key: 'hostname', label: 'Host' },
  { key: 'readiness_pct', label: 'Readiness %', numeric: true, align: 'right' },
  { key: 'safe_count', label: 'Safe', numeric: true, align: 'right' },
  { key: 'transitional_count', label: 'Trans.', numeric: true, align: 'right' },
  { key: 'deprecated_count', label: 'Depr.', numeric: true, align: 'right' },
  { key: 'unsafe_count', label: 'Unsafe', numeric: true, align: 'right' },
  { key: 'trend_direction', label: 'Trend' },
  { key: 'refreshed_at', label: 'Last refresh' },
];

function trendVariant(d: TrendDirection): PillVariant {
  if (d === 'improving') return 'safe';
  if (d === 'declining') return 'unsafe';
  return 'neutral';
}

function onRowClick(row: Record<string, unknown>) {
  void router.push(`/machines/${String(row.hostname)}`);
}

interface HistoryRow {
  id: string;
  created_at: string;
  finding_count: number;
  pqc_safe: number;
  pqc_transitional: number;
  pqc_deprecated: number;
  pqc_unsafe: number;
  readiness_pct: number;
  [key: string]: unknown;
}

const historyRows = computed<HistoryRow[]>(() =>
  store.history.map((s) => ({
    id: s.id,
    created_at: s.created_at,
    finding_count: s.finding_count,
    pqc_safe: s.pqc_safe,
    pqc_transitional: s.pqc_transitional,
    pqc_deprecated: s.pqc_deprecated,
    pqc_unsafe: s.pqc_unsafe,
    readiness_pct: s.readiness_pct,
  })),
);

const historyColumns: Column<HistoryRow>[] = [
  { key: 'created_at', label: 'Date' },
  { key: 'finding_count', label: 'Findings', numeric: true, align: 'right' },
  { key: 'pqc_safe', label: 'Safe', numeric: true, align: 'right' },
  { key: 'pqc_transitional', label: 'Trans.', numeric: true, align: 'right' },
  { key: 'pqc_deprecated', label: 'Depr.', numeric: true, align: 'right' },
  { key: 'pqc_unsafe', label: 'Unsafe', numeric: true, align: 'right' },
  { key: 'readiness_pct', label: 'Readiness %', numeric: true, align: 'right' },
];

const latest = computed(() => store.history[0] ?? null);

const trendLabels = computed(() =>
  [...store.history].reverse().map((s) => new Date(s.created_at).toLocaleDateString()),
);
const trendValues = computed(() =>
  [...store.history].reverse().map((s) => s.readiness_pct),
);

onMounted(() => {
  if (isDetail.value) void store.fetchHistory(hostname.value);
  else void store.fetch();
});

watch(hostname, (h, prev) => {
  if (h && h !== prev) void store.fetchHistory(h);
  else if (!h) void store.fetch();
});

function onHistoryRowClick(row: Record<string, unknown>) {
  void router.push(`/scans/${String(row.id)}`);
}
</script>

<template>
  <section class="machines-view">
    <template v-if="!isDetail">
      <header class="machines-head">
        <h1>Machines</h1>
        <p class="sub">Per-host readiness — worst first.</p>
      </header>

      <TDataTable
        :columns="columns"
        :rows="rows"
        row-key="hostname"
        :empty-text="store.loading ? 'Loading…' : 'No machines yet.'"
        @row-click="onRowClick"
      >
        <template #[`cell:hostname`]="{ row }">
          <span :data-test="`machine-row-${String(row.hostname)}`">{{ row.hostname }}</span>
        </template>
        <template #[`cell:trend_direction`]="{ row }">
          <TPill :variant="trendVariant(row.trend_direction as TrendDirection)">
            {{ String(row.trend_direction) }}
          </TPill>
        </template>
        <template #[`cell:refreshed_at`]="{ row }">
          {{ new Date(String(row.refreshed_at)).toLocaleString() }}
        </template>
      </TDataTable>
    </template>

    <template v-else>
      <header class="machines-head">
        <h1>{{ hostname }}</h1>
        <p class="sub">Scan history + trend.</p>
      </header>

      <div v-if="latest" class="stat-row">
        <TStatCard label="Safe" :value="latest.pqc_safe" />
        <TStatCard label="Transitional" :value="latest.pqc_transitional" />
        <TStatCard label="Deprecated" :value="latest.pqc_deprecated" />
        <TStatCard label="Unsafe" :value="latest.pqc_unsafe" />
      </div>

      <section class="panel">
        <h2>Readiness over time</h2>
        <TLineChart :labels="trendLabels" :values="trendValues" />
      </section>

      <TDataTable
        :columns="historyColumns"
        :rows="historyRows"
        row-key="id"
        :empty-text="store.historyLoading ? 'Loading…' : 'No scans yet for this host.'"
        @row-click="onHistoryRowClick"
      >
        <template #[`cell:created_at`]="{ row }">
          {{ new Date(String(row.created_at)).toLocaleString() }}
        </template>
      </TDataTable>
    </template>
  </section>
</template>

<style scoped>
.machines-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.machines-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.stat-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--space-3);
}
.panel {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: var(--space-4);
}
.panel h2 {
  margin: 0 0 var(--space-3);
  font-family: var(--font-display);
  font-size: 1rem;
  font-weight: 500;
}
</style>
```

- [ ] **Step 4: Run the tests**

```bash
cd web && pnpm --filter report-portal test -- tests/views/Machines.spec.ts
```
Expected: 4 passing tests.

- [ ] **Step 5: vue-tsc sanity check**

```bash
cd web && pnpm --filter report-portal exec vue-tsc --noEmit
```
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
cd .worktrees/report-portal-phase2
git add web/apps/report-portal/src/views/Machines.vue \
        web/apps/report-portal/tests/views/Machines.spec.ts
git commit -m "feat(report-portal): implement Machines view (list + detail)

List mode: sortable host table, worst-readiness-first, row click
navigates to detail. Trend direction rendered as TPill (improving
safe / declining unsafe / stable neutral).

Detail mode: stat cards from latest scan, TLineChart of readiness
over scan history, scan history table linking to /scans/:id. Uses
watch(hostname) to re-fetch when user navigates between detail
pages without unmounting.

4 Vitest component tests covering both modes + row navigation."
```

---

## Task 8: Scans store

**Files:**
- Create: `web/apps/report-portal/src/stores/scans.ts`

- [ ] **Step 1: Write the store**

Create `web/apps/report-portal/src/stores/scans.ts`:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { ScanSummary, ScanDetail, Finding } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useScansStore = defineStore('scans', () => {
  const items = ref<ScanSummary[]>([]);
  const detail = ref<ScanDetail | null>(null);
  const findings = ref<Finding[]>([]);
  const loading = ref(false);
  const detailLoading = ref(false);

  async function fetch(): Promise<void> {
    const api = useApiClient().get();
    loading.value = true;
    try {
      items.value = await api.listScans();
    } catch (e) {
      useToast().error({
        title: 'Failed to load scans',
        description: String(e),
      });
    } finally {
      loading.value = false;
    }
  }

  async function fetchDetail(id: string): Promise<void> {
    const api = useApiClient().get();
    detailLoading.value = true;
    try {
      const [d, f] = await Promise.all([api.getScan(id), api.getFindings(id)]);
      detail.value = d;
      findings.value = f;
    } catch (e) {
      useToast().error({
        title: `Failed to load scan ${id}`,
        description: String(e),
      });
    } finally {
      detailLoading.value = false;
    }
  }

  return { items, detail, findings, loading, detailLoading, fetch, fetchDetail };
});
```

- [ ] **Step 2: Type-check**

```bash
cd web && pnpm --filter report-portal exec vue-tsc --noEmit
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
cd .worktrees/report-portal-phase2
git add web/apps/report-portal/src/stores/scans.ts
git commit -m "feat(report-portal): add scans store

fetchDetail uses Promise.all for getScan + getFindings so the
detail page loads both in parallel."
```

---

## Task 9: Scans view (TDD, list + detail)

**Files:**
- Create: `web/apps/report-portal/tests/views/Scans.spec.ts`
- Modify: `web/apps/report-portal/src/views/Scans.vue`

- [ ] **Step 1: Write the failing component tests**

Create `web/apps/report-portal/tests/views/Scans.spec.ts`:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';
import Scans from '../../src/views/Scans.vue';
import { useScansStore } from '../../src/stores/scans';

beforeEach(() => {
  vi.clearAllMocks();
});

const SCAN_1 = {
  id: 'scan-1', hostname: 'app01', org_id: 'o1', created_at: '2026-04-20T10:00:00Z',
  finding_count: 56, pqc_safe: 40, pqc_transitional: 10, pqc_deprecated: 4, pqc_unsafe: 2, readiness_pct: 72,
};
const SCAN_2 = {
  id: 'scan-2', hostname: 'db01', org_id: 'o1', created_at: '2026-04-21T10:00:00Z',
  finding_count: 55, pqc_safe: 20, pqc_transitional: 18, pqc_deprecated: 12, pqc_unsafe: 5, readiness_pct: 45,
};
const FINDING_A = {
  id: 'f-1', scan_id: 'scan-1', finding_index: 0,
  subject: 'rsa-2048-key', algorithm: 'RSA-2048', key_size: 2048,
  pqc_status: 'TRANSITIONAL', file_path: '/etc/ssl/cert.key',
  category: 'key', migration_priority: 70,
};
const DETAIL_1 = { ...SCAN_1, result: {} };

function makeRouter(path: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/scans', name: 'scans', component: { template: '<div/>' } },
      { path: '/scans/:id', name: 'scan', component: { template: '<div/>' } },
      { path: '/', component: { template: '<div/>' } },
    ],
  });
  router.push(path);
  return router;
}

async function mountAt(path: string, state: { items?: unknown[]; detail?: unknown; findings?: unknown[] } = {}) {
  const router = makeRouter(path);
  await router.isReady();
  return mount(Scans, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          stubActions: true,
          initialState: {
            scans: {
              items: state.items ?? [],
              detail: state.detail ?? null,
              findings: state.findings ?? [],
              loading: false,
              detailLoading: false,
            },
          },
        }),
        router,
      ],
    },
  });
}

describe('Scans view — list mode', () => {
  it('calls fetch on mount and renders scan rows', async () => {
    const wrapper = await mountAt('/scans', { items: [SCAN_1, SCAN_2] });
    const store = useScansStore();
    await flushPromises();

    expect(store.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('app01');
    expect(html).toContain('db01');
    wrapper.unmount();
  });

  it('clicking a row navigates to /scans/:id', async () => {
    const wrapper = await mountAt('/scans', { items: [SCAN_1] });
    await flushPromises();

    const row = wrapper.find('[data-test="scan-row-scan-1"]');
    expect(row.exists()).toBe(true);
    await row.trigger('click');
    await flushPromises();

    expect(wrapper.vm.$route.path).toBe('/scans/scan-1');
    wrapper.unmount();
  });
});

describe('Scans view — detail mode', () => {
  it('calls fetchDetail on mount with scan id from route param', async () => {
    const wrapper = await mountAt('/scans/scan-1', { detail: DETAIL_1, findings: [FINDING_A] });
    const store = useScansStore();
    await flushPromises();

    expect(store.fetchDetail).toHaveBeenCalledWith('scan-1');
    wrapper.unmount();
  });

  it('renders stat cards + findings table from stubbed detail', async () => {
    const wrapper = await mountAt('/scans/scan-1', { detail: DETAIL_1, findings: [FINDING_A] });
    await flushPromises();

    const html = wrapper.html();
    expect(html).toContain('RSA-2048');
    expect(html).toContain('rsa-2048-key');
    expect(html).toContain('40'); // pqc_safe
    wrapper.unmount();
  });
});
```

- [ ] **Step 2: Run the tests to confirm they fail**

```bash
cd web && pnpm --filter report-portal test -- tests/views/Scans.spec.ts
```
Expected: 4 failures.

- [ ] **Step 3: Implement Scans.vue**

Replace `web/apps/report-portal/src/views/Scans.vue`:

```vue
<script setup lang="ts">
import { computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  TStatCard,
  TDataTable,
  TPill,
  type Column,
  type PillVariant,
} from '@triton/ui';
import type { PqcStatus } from '@triton/api-client';
import { useScansStore } from '../stores/scans';

const route = useRoute();
const router = useRouter();
const store = useScansStore();

const scanId = computed(() =>
  typeof route.params.id === 'string' ? route.params.id : '',
);
const isDetail = computed(() => scanId.value.length > 0);

interface ScanRow {
  id: string;
  created_at: string;
  hostname: string;
  finding_count: number;
  pqc_safe: number;
  pqc_transitional: number;
  pqc_deprecated: number;
  pqc_unsafe: number;
  readiness_pct: number;
  [key: string]: unknown;
}

const rows = computed<ScanRow[]>(() =>
  store.items.map((s) => ({
    id: s.id,
    created_at: s.created_at,
    hostname: s.hostname,
    finding_count: s.finding_count,
    pqc_safe: s.pqc_safe,
    pqc_transitional: s.pqc_transitional,
    pqc_deprecated: s.pqc_deprecated,
    pqc_unsafe: s.pqc_unsafe,
    readiness_pct: s.readiness_pct,
  })),
);

const columns: Column<ScanRow>[] = [
  { key: 'created_at', label: 'Date' },
  { key: 'hostname', label: 'Host' },
  { key: 'finding_count', label: 'Findings', numeric: true, align: 'right' },
  { key: 'pqc_safe', label: 'Safe', numeric: true, align: 'right' },
  { key: 'pqc_transitional', label: 'Trans.', numeric: true, align: 'right' },
  { key: 'pqc_deprecated', label: 'Depr.', numeric: true, align: 'right' },
  { key: 'pqc_unsafe', label: 'Unsafe', numeric: true, align: 'right' },
  { key: 'readiness_pct', label: 'Readiness %', numeric: true, align: 'right' },
];

function onRowClick(row: Record<string, unknown>) {
  void router.push(`/scans/${String(row.id)}`);
}

interface FindingRow {
  id: string;
  subject: string;
  algorithm: string;
  key_size: number;
  pqc_status: PqcStatus;
  category: string;
  file_path: string;
  migration_priority: number;
  [key: string]: unknown;
}

const findingRows = computed<FindingRow[]>(() =>
  [...store.findings]
    .sort((a, b) => b.migration_priority - a.migration_priority)
    .map((f) => ({
      id: f.id,
      subject: f.subject,
      algorithm: f.algorithm,
      key_size: f.key_size,
      pqc_status: f.pqc_status,
      category: f.category,
      file_path: f.file_path,
      migration_priority: f.migration_priority,
    })),
);

const findingColumns: Column<FindingRow>[] = [
  { key: 'subject', label: 'Subject' },
  { key: 'algorithm', label: 'Algorithm' },
  { key: 'key_size', label: 'Key size', numeric: true, align: 'right' },
  { key: 'pqc_status', label: 'Status' },
  { key: 'category', label: 'Category' },
  { key: 'file_path', label: 'File path' },
  { key: 'migration_priority', label: 'Priority', numeric: true, align: 'right' },
];

function pqcVariant(s: PqcStatus): PillVariant {
  if (s === 'SAFE') return 'safe';
  if (s === 'TRANSITIONAL') return 'warn';
  if (s === 'DEPRECATED') return 'deprecated';
  return 'unsafe';
}

onMounted(() => {
  if (isDetail.value) void store.fetchDetail(scanId.value);
  else void store.fetch();
});

watch(scanId, (id, prev) => {
  if (id && id !== prev) void store.fetchDetail(id);
  else if (!id) void store.fetch();
});
</script>

<template>
  <section class="scans-view">
    <template v-if="!isDetail">
      <header class="scans-head">
        <h1>Scans</h1>
        <p class="sub">All scans across your fleet.</p>
      </header>

      <TDataTable
        :columns="columns"
        :rows="rows"
        row-key="id"
        :empty-text="store.loading ? 'Loading…' : 'No scans yet.'"
        @row-click="onRowClick"
      >
        <template #[`cell:created_at`]="{ row }">
          <span :data-test="`scan-row-${String(row.id)}`">
            {{ new Date(String(row.created_at)).toLocaleString() }}
          </span>
        </template>
      </TDataTable>
    </template>

    <template v-else>
      <header class="scans-head">
        <h1>Scan {{ scanId.slice(0, 8) }}</h1>
        <p v-if="store.detail" class="sub">
          {{ store.detail.hostname }} · {{ new Date(store.detail.created_at).toLocaleString() }}
        </p>
      </header>

      <div v-if="store.detail" class="stat-row">
        <TStatCard label="Safe" :value="store.detail.pqc_safe" />
        <TStatCard label="Transitional" :value="store.detail.pqc_transitional" />
        <TStatCard label="Deprecated" :value="store.detail.pqc_deprecated" />
        <TStatCard label="Unsafe" :value="store.detail.pqc_unsafe" />
      </div>

      <TDataTable
        :columns="findingColumns"
        :rows="findingRows"
        row-key="id"
        :empty-text="store.detailLoading ? 'Loading…' : 'No findings in this scan.'"
      >
        <template #[`cell:pqc_status`]="{ row }">
          <TPill :variant="pqcVariant(row.pqc_status as PqcStatus)">
            {{ String(row.pqc_status) }}
          </TPill>
        </template>
      </TDataTable>
    </template>
  </section>
</template>

<style scoped>
.scans-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.scans-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.stat-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--space-3);
}
</style>
```

- [ ] **Step 4: Run the tests**

```bash
cd web && pnpm --filter report-portal test -- tests/views/Scans.spec.ts
```
Expected: 4 passing tests.

- [ ] **Step 5: vue-tsc sanity check**

```bash
cd web && pnpm --filter report-portal exec vue-tsc --noEmit
```
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
cd .worktrees/report-portal-phase2
git add web/apps/report-portal/src/views/Scans.vue \
        web/apps/report-portal/tests/views/Scans.spec.ts
git commit -m "feat(report-portal): implement Scans view (list + detail)

List mode: all scans across fleet, date/host/counts/readiness%,
row click navigates to detail.

Detail mode: stat cards from scan summary, findings table sorted
by migration_priority DESC, pqc_status rendered as TPill
(SAFE=safe, TRANSITIONAL=warn, DEPRECATED=deprecated, UNSAFE=unsafe).

4 Vitest component tests covering both modes + row navigation."
```

---

## Task 10: End-to-end sanity check + full build

**Files:** none (runs existing tools)

- [ ] **Step 1: Run full report-portal test suite**

```bash
cd web && pnpm --filter report-portal test
```
Expected: 11 passing tests (3 Overview + 4 Machines + 4 Scans).

- [ ] **Step 2: Run full workspace tests**

```bash
cd web && pnpm test
```
Expected: all workspace tests pass (manage-portal, report-portal, api-client, ui, auth).

- [ ] **Step 3: Run report-portal build**

```bash
cd web && pnpm --filter report-portal build
```
Expected: `vue-tsc --noEmit && vite build` completes without errors; `pkg/server/ui/dist/` updated with new Vue bundle.

- [ ] **Step 4: Run report-portal dev server + manual smoke test (optional but recommended)**

```bash
cd web && pnpm --filter report-portal dev
```

In another terminal:
```bash
cd .worktrees/report-portal-phase2
make db-up
go run ./cmd/server
```

Visit `http://localhost:5174/ui/` — log in, verify:
- Overview renders the exec bar, stat cards, trend chart, blockers strip
- Machines list renders hosts; clicking a host navigates to detail
- Machine detail renders stat cards + trend chart + scan history
- Scans list renders scans; clicking a scan navigates to detail
- Scan detail renders stat cards + findings table

Stop both servers (Ctrl-C) when done.

- [ ] **Step 5: Commit any follow-ups (e.g. CSS tweaks from smoke test)**

If the smoke test revealed issues, fix them and commit with a dedicated `fix(report-portal): ...` message.

If no issues, skip this step.

---

## After all tasks

Use the `superpowers:finishing-a-development-branch` skill with:
- Branch: `feat/report-portal-phase-2`
- Worktree: `.worktrees/report-portal-phase2`
- Main branch: `main`
