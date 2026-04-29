<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { TCrumbBar, TStatCard, TPill, TDataTable } from '@triton/ui';
import type { Column } from '@triton/ui';
import type {
  NacsaServerRow, NacsaHostRow,
  NacsaMigPhase, NacsaMigActivity,
} from '@triton/api-client';
import { useNacsaStore } from '../stores/nacsa';

const nacsa = useNacsaStore();

// ── Tabs ──────────────────────────────────────────────────────────────────────
type TabId = 'summary' | 'inventory' | 'cbom' | 'risk' | 'migration';
const activeTab = ref<TabId>('summary');
const TABS: { id: TabId; label: string }[] = [
  { id: 'summary',   label: 'Summary' },
  { id: 'inventory', label: 'Inventory' },
  { id: 'cbom',      label: 'CBOM' },
  { id: 'risk',      label: 'Risk' },
  { id: 'migration', label: 'Migration' },
];

// ── Breadcrumb ────────────────────────────────────────────────────────────────
const crumbs = computed(() => {
  const items: { label: string; href?: string }[] = [{ label: 'All Servers' }];
  if (nacsa.scope.manageServerId) {
    items[0] = { label: 'All Servers', href: '#/nacsa' };
    items.push({ label: nacsa.scope.manageServerName || nacsa.scope.manageServerId });
  }
  if (nacsa.scope.hostname) {
    items[items.length - 1] = {
      label: nacsa.scope.manageServerName || nacsa.scope.manageServerId,
      href: '#/nacsa',
    };
    items.push({ label: nacsa.scope.hostname });
  }
  return items;
});

function resetDrill() {
  nacsa.clearDrill();
  activeTab.value = 'summary';
}

// ── Summary tab ───────────────────────────────────────────────────────────────
const readinessPct = computed(() => nacsa.summary?.readiness_pct ?? 0);
const readinessBar = computed(() => Math.min(readinessPct.value, 100));

// ── Inventory tab ─────────────────────────────────────────────────────────────
const serverCols: Column<NacsaServerRow>[] = [
  { key: 'name',          label: 'Server',       width: '2fr' },
  { key: 'host_count',    label: 'Hosts',        width: '80px', numeric: true },
  { key: 'readiness_pct', label: 'Readiness %',  width: '120px', numeric: true },
  { key: 'last_scan_at',  label: 'Last Scan',    width: '160px' },
];
const hostCols: Column<NacsaHostRow>[] = [
  { key: 'hostname',      label: 'Hostname',     width: '2fr' },
  { key: 'scan_profile',  label: 'Profile',      width: '100px' },
  { key: 'readiness_pct', label: 'Readiness %',  width: '120px', numeric: true },
  { key: 'last_scan_at',  label: 'Last Scan',    width: '160px' },
];

function onServerClick(row: NacsaServerRow) {
  nacsa.drillToServer(row.id, row.name);
  activeTab.value = 'inventory';
  void nacsa.fetchHosts();
}

function onHostClick(row: NacsaHostRow) {
  nacsa.drillToHost(row.hostname);
  activeTab.value = 'cbom';
  void nacsa.fetchCBOM();
  void nacsa.fetchRisk();
}

// ── CBOM tab ──────────────────────────────────────────────────────────────────
const cbomStatusFilters = ref<string[]>([]);
const CBOM_STATUSES = ['UNSAFE', 'DEPRECATED', 'TRANSITIONAL', 'SAFE'];

function toggleCBOMStatus(s: string) {
  const idx = cbomStatusFilters.value.indexOf(s);
  if (idx === -1) cbomStatusFilters.value.push(s);
  else cbomStatusFilters.value.splice(idx, 1);
  void nacsa.fetchCBOM(cbomStatusFilters.value.join(',') || undefined);
}

function cbomStatusClass(status: string): string {
  switch (status) {
    case 'UNSAFE':       return 'status-unsafe';
    case 'DEPRECATED':   return 'status-deprecated';
    case 'TRANSITIONAL': return 'status-transitional';
    default:             return 'status-safe';
  }
}

// ── Risk tab ──────────────────────────────────────────────────────────────────
const riskSort = ref<'score' | 'impact' | 'hostname'>('score');
const expandedRiskRow = ref<string | null>(null);

function setRiskSort(s: typeof riskSort.value) {
  riskSort.value = s;
  void nacsa.fetchRisk(s);
}

function toggleRiskRow(key: string) {
  expandedRiskRow.value = expandedRiskRow.value === key ? null : key;
}

function riskBandClass(band: string): string {
  switch (band) {
    case 'CRITICAL': return 'risk-critical';
    case 'HIGH':     return 'risk-high';
    case 'MEDIUM':   return 'risk-medium';
    default:         return 'risk-low';
  }
}

// ── Migration tab ─────────────────────────────────────────────────────────────
const activeMigPhase = ref<number | null>(null);

function setActivePhase(phase: number) {
  activeMigPhase.value = activeMigPhase.value === phase ? null : phase;
}

function phaseClass(status: NacsaMigPhase['status']): string {
  switch (status) {
    case 'complete':     return 'phase-complete';
    case 'in_progress':  return 'phase-active';
    default:             return 'phase-pending';
  }
}

function activityIcon(status: NacsaMigActivity['status']): string {
  if (status === 'done')   return '✓';
  if (status === 'active') return '→';
  return '○';
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────
onMounted(() => {
  void nacsa.fetchSummary();
  void nacsa.fetchServers();
  void nacsa.fetchMigration();
});

watch(activeTab, (tab) => {
  if (tab === 'cbom')      void nacsa.fetchCBOM(cbomStatusFilters.value.join(',') || undefined);
  if (tab === 'risk')      void nacsa.fetchRisk(riskSort.value);
  if (tab === 'migration') void nacsa.fetchMigration();
});
</script>

<template>
  <section class="nacsa-view">
    <!-- Breadcrumb -->
    <TCrumbBar :crumbs="crumbs" @click.prevent="resetDrill" />

    <!-- Tab strip -->
    <nav class="tab-strip">
      <button
        v-for="t in TABS"
        :key="t.id"
        class="tab-btn"
        :class="{ 'is-active': activeTab === t.id }"
        @click="activeTab = t.id"
      >
        {{ t.label }}
      </button>
    </nav>

    <!-- ── SUMMARY TAB ── -->
    <div v-if="activeTab === 'summary'" class="tab-content">
      <!-- Hero readiness bar -->
      <div class="hero-bar panel">
        <div class="hero-left">
          <span class="hero-pct">{{ readinessPct.toFixed(1) }}%</span>
          <span class="hero-label">NACSA Arahan 9 Readiness</span>
        </div>
        <div class="hero-progress">
          <div class="progress-track">
            <div class="progress-fill" :style="{ width: readinessBar + '%' }"></div>
          </div>
          <div class="progress-labels">
            <span>0%</span>
            <span>Target: {{ nacsa.summary?.target_pct ?? 80 }}% by {{ nacsa.summary?.target_year ?? 2030 }}</span>
            <span>100%</span>
          </div>
        </div>
      </div>

      <!-- Stat cards -->
      <div class="stat-row">
        <TStatCard label="Compliant"     :value="nacsa.summary?.compliant     ?? 0" />
        <TStatCard label="Transitional"  :value="nacsa.summary?.transitional  ?? 0" />
        <TStatCard label="Non-Compliant" :value="nacsa.summary?.non_compliant ?? 0" />
        <TStatCard label="Total Assets"  :value="nacsa.summary?.total_assets  ?? 0" />
      </div>

      <!-- Top blockers -->
      <div class="panel">
        <h2>Top Blockers</h2>
        <div v-if="!nacsa.summary?.top_blockers?.length" class="empty">No unsafe assets found.</div>
        <ul v-else class="blockers">
          <li v-for="b in nacsa.summary.top_blockers" :key="`${b.hostname}|${b.algorithm}`">
            <span class="b-host">{{ b.hostname }}</span>
            <span class="b-algo">{{ b.algorithm }}</span>
            <TPill variant="unsafe">{{ b.severity }}</TPill>
            <span class="b-count">{{ b.asset_count }} assets</span>
          </li>
        </ul>
      </div>

      <!-- Migration mini progress -->
      <div v-if="nacsa.summary?.migration_phases?.length" class="panel">
        <h2>Migration Progress</h2>
        <div class="migration-mini">
          <div
            v-for="p in nacsa.summary.migration_phases"
            :key="p.phase"
            class="mig-row"
          >
            <span class="mig-label" :class="phaseClass(p.status)">Fasa {{ p.phase }}</span>
            <div class="mig-track">
              <div class="mig-fill" :class="phaseClass(p.status)" :style="{ width: p.progress_pct + '%' }"></div>
            </div>
            <span class="mig-pct" :class="phaseClass(p.status)">
              {{ p.status === 'complete' ? '✓' : p.progress_pct + '%' }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <!-- ── INVENTORY TAB ── -->
    <div v-else-if="activeTab === 'inventory'" class="tab-content">
      <template v-if="nacsa.scope.manageServerId">
        <h2>Hosts — {{ nacsa.scope.manageServerName || nacsa.scope.manageServerId }}</h2>
        <TDataTable
          :columns="hostCols"
          :rows="nacsa.hosts"
          row-key="hostname"
          empty-text="No hosts found for this server."
          @row-click="onHostClick"
        />
      </template>
      <template v-else>
        <h2>Manage Servers</h2>
        <TDataTable
          :columns="serverCols"
          :rows="nacsa.servers"
          row-key="id"
          empty-text="No manage servers found. Scans must be relayed via a Manage Server."
          @row-click="onServerClick"
        />
      </template>
    </div>

    <!-- ── CBOM TAB ── -->
    <div v-else-if="activeTab === 'cbom'" class="tab-content">
      <div class="cbom-filters">
        <button
          v-for="s in CBOM_STATUSES"
          :key="s"
          class="filter-chip"
          :class="[cbomStatusClass(s), { 'is-active': cbomStatusFilters.includes(s) }]"
          @click="toggleCBOMStatus(s)"
        >
          {{ s }}
        </button>
      </div>
      <table class="data-table cbom-table">
        <thead>
          <tr>
            <th>Algorithm</th><th>Key Length</th><th>Status</th><th>Assets</th><th>Module</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in nacsa.cbom"
            :key="`${row.algorithm}|${row.pqc_status}|${row.module}`"
            :class="cbomStatusClass(row.pqc_status)"
          >
            <td>{{ row.algorithm }}</td>
            <td>{{ row.key_size ? row.key_size + '-bit' : '—' }}</td>
            <td><span class="status-badge" :class="cbomStatusClass(row.pqc_status)">{{ row.pqc_status }}</span></td>
            <td class="numeric">{{ row.asset_count }}</td>
            <td>{{ row.module }}</td>
          </tr>
          <tr v-if="!nacsa.cbom.length">
            <td colspan="5" class="empty">No crypto assets found for this scope.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ── RISK TAB ── -->
    <div v-else-if="activeTab === 'risk'" class="tab-content">
      <div class="sort-bar">
        <span>Sort:</span>
        <button
          v-for="s in (['score', 'impact', 'hostname'] as const)"
          :key="s"
          class="sort-btn"
          :class="{ 'is-active': riskSort === s }"
          @click="setRiskSort(s)"
        >{{ s }} {{ riskSort === s ? '↓' : '' }}</button>
      </div>
      <table class="data-table risk-table">
        <thead>
          <tr>
            <th>Algorithm</th><th>System</th><th>Impact</th><th>Likelihood</th><th>Score</th><th>Band</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="row in nacsa.risk" :key="`${row.algorithm}|${row.hostname}`">
            <tr
              :class="riskBandClass(row.risk_band)"
              style="cursor:pointer"
              @click="toggleRiskRow(`${row.algorithm}|${row.hostname}`)"
            >
              <td>{{ row.algorithm }}</td>
              <td>{{ row.hostname }}</td>
              <td class="numeric">{{ row.impact }}</td>
              <td class="numeric">{{ row.likelihood }}</td>
              <td class="numeric score-cell">{{ row.score }}</td>
              <td><span class="risk-badge" :class="riskBandClass(row.risk_band)">{{ row.risk_band }}</span></td>
            </tr>
            <tr v-if="expandedRiskRow === `${row.algorithm}|${row.hostname}`" class="expand-row">
              <td colspan="6">
                <div class="expand-detail">
                  <strong>Assets:</strong> {{ row.asset_count }}&emsp;
                  <strong>Score:</strong> Impact ({{ row.impact }}) × Likelihood ({{ row.likelihood }}) = {{ row.score }}
                </div>
              </td>
            </tr>
          </template>
          <tr v-if="!nacsa.risk.length">
            <td colspan="6" class="empty">No risk items in this scope.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- ── MIGRATION TAB ── -->
    <div v-else-if="activeTab === 'migration'" class="tab-content">
      <div v-if="!nacsa.migration?.phases.length" class="empty panel">
        No migration data configured. An admin can add phase data via the API.
      </div>
      <template v-else>
        <div class="gantt">
          <div
            v-for="p in nacsa.migration.phases"
            :key="p.phase"
            class="gantt-row"
            :class="{ 'is-active': activeMigPhase === p.phase }"
            @click="setActivePhase(p.phase)"
          >
            <span class="gantt-label" :class="phaseClass(p.status)">Fasa {{ p.phase }}</span>
            <div class="gantt-track">
              <div class="gantt-fill" :class="phaseClass(p.status)" :style="{ width: p.progress_pct + '%' }"></div>
            </div>
            <span class="gantt-pct" :class="phaseClass(p.status)">
              {{ p.status === 'complete' ? '✓ 100%' : p.progress_pct + '%' }}
            </span>
          </div>
        </div>

        <div
          v-for="p in nacsa.migration.phases"
          v-show="activeMigPhase === p.phase"
          :key="`detail-${p.phase}`"
          class="phase-detail panel"
        >
          <div class="phase-detail-head">
            <span class="phase-detail-title" :class="phaseClass(p.status)">
              Fasa {{ p.phase }} — {{ p.name }}
            </span>
            <span class="phase-detail-period">{{ p.period }}</span>
          </div>
          <ul class="activity-list">
            <li v-for="a in p.activities" :key="a.name" class="activity-row">
              <span class="act-icon" :class="a.status">{{ activityIcon(a.status) }}</span>
              <span class="act-name">{{ a.name }}</span>
              <span class="act-budget">RM {{ (a.budget_rm / 1_000_000).toFixed(1) }}M</span>
            </li>
          </ul>
          <div v-if="p.budget_total_rm > 0" class="budget-chips">
            <div class="budget-chip">
              <span class="chip-val">RM {{ (p.budget_total_rm / 1_000_000).toFixed(1) }}M</span>
              <span class="chip-lbl">Budget</span>
            </div>
            <div class="budget-chip spent">
              <span class="chip-val">RM {{ (p.budget_spent_rm / 1_000_000).toFixed(1) }}M</span>
              <span class="chip-lbl">Spent</span>
            </div>
            <div class="budget-chip remaining">
              <span class="chip-val">RM {{ ((p.budget_total_rm - p.budget_spent_rm) / 1_000_000).toFixed(1) }}M</span>
              <span class="chip-lbl">Remaining</span>
            </div>
          </div>
        </div>
      </template>
    </div>
  </section>
</template>

<style scoped>
.nacsa-view { display: flex; flex-direction: column; gap: var(--space-4); padding: var(--space-4); }

/* Tab strip */
.tab-strip { display: flex; gap: 2px; border-bottom: 1px solid var(--border); }
.tab-btn {
  padding: var(--space-2) var(--space-4);
  background: none; border: none; border-bottom: 2px solid transparent;
  color: var(--text-muted); cursor: pointer; font-size: 0.85rem;
  transition: color 0.15s, border-color 0.15s;
}
.tab-btn.is-active { color: var(--accent-strong); border-bottom-color: var(--accent-strong); }
.tab-btn:hover:not(.is-active) { color: var(--text-secondary); }
.tab-content { display: flex; flex-direction: column; gap: var(--space-4); }

/* Panel */
.panel {
  background: var(--bg-surface); border: 1px solid var(--border);
  border-radius: var(--radius); padding: var(--space-4);
}
.panel h2 { font-size: 0.9rem; font-weight: 500; margin: 0 0 var(--space-3); }
.empty { color: var(--text-muted); font-size: 0.8rem; text-align: center; padding: var(--space-4); }

/* Hero bar */
.hero-bar { display: flex; align-items: center; gap: var(--space-6); }
.hero-left { display: flex; flex-direction: column; align-items: center; min-width: 80px; }
.hero-pct { font-family: var(--font-display); font-size: 2.2rem; font-weight: 700; color: var(--color-safe, #4ade80); }
.hero-label { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.1em; color: var(--text-subtle); margin-top: 2px; }
.hero-progress { flex: 1; }
.progress-track { background: var(--bg-elevated); border-radius: 4px; height: 10px; margin-bottom: var(--space-1); }
.progress-fill { background: linear-gradient(90deg, #4ade80, #22c55e); height: 100%; border-radius: 4px; transition: width 0.4s; }
.progress-labels { display: flex; justify-content: space-between; font-size: 0.65rem; color: var(--text-subtle); }

/* Stat row */
.stat-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: var(--space-3); }

/* Blockers */
.blockers { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: var(--space-2); }
.blockers li { display: flex; align-items: center; gap: var(--space-3); padding: var(--space-2); background: var(--bg-elevated); border-radius: var(--radius-sm); font-size: 0.78rem; }
.b-host { font-weight: 500; flex: 1; }
.b-algo { color: var(--text-secondary); }
.b-count { color: var(--text-muted); font-size: 0.72rem; }

/* Migration mini */
.migration-mini { display: flex; flex-direction: column; gap: var(--space-2); }
.mig-row { display: flex; align-items: center; gap: var(--space-3); }
.mig-label { font-size: 0.78rem; width: 48px; }
.mig-track { flex: 1; background: var(--bg-elevated); border-radius: 3px; height: 8px; }
.mig-fill { height: 100%; border-radius: 3px; transition: width 0.4s; }
.mig-pct { font-size: 0.72rem; width: 40px; text-align: right; }

/* Phase colours */
.phase-complete { color: var(--color-safe, #4ade80); }
.phase-active   { color: var(--color-transitional, #f97316); }
.phase-pending  { color: var(--text-muted); }
.mig-fill.phase-complete { background: #4ade80; }
.mig-fill.phase-active   { background: #f97316; }
.mig-fill.phase-pending  { background: var(--bg-elevated); }

/* CBOM filters */
.cbom-filters { display: flex; gap: var(--space-2); flex-wrap: wrap; }
.filter-chip {
  padding: var(--space-1) var(--space-3); border-radius: var(--radius); font-size: 0.75rem;
  border: 1px solid currentColor; cursor: pointer; opacity: 0.5; transition: opacity 0.15s;
  background: none;
}
.filter-chip.is-active { opacity: 1; }
.status-unsafe       { color: var(--color-unsafe, #ef4444); }
.status-deprecated   { color: var(--color-deprecated, #a78bfa); }
.status-transitional { color: var(--color-transitional, #f97316); }
.status-safe         { color: var(--color-safe, #4ade80); }

/* Tables */
.data-table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
.data-table th { text-align: left; padding: var(--space-2) var(--space-3); color: var(--text-subtle); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
.data-table td { padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--border-subtle, var(--border)); }
.data-table tr:hover td { background: var(--bg-elevated); }
.numeric { text-align: right; font-variant-numeric: tabular-nums; }
.status-badge, .risk-badge {
  display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 0.68rem; font-weight: 600;
}

/* CBOM row borders */
.cbom-table tr.status-unsafe      td:first-child { border-left: 3px solid #ef4444; }
.cbom-table tr.status-deprecated  td:first-child { border-left: 3px solid #a78bfa; }
.cbom-table tr.status-transitional td:first-child { border-left: 3px solid #f97316; }
.cbom-table tr.status-safe        td:first-child { border-left: 3px solid #4ade80; }

/* Risk */
.sort-bar { display: flex; align-items: center; gap: var(--space-2); }
.sort-bar span { font-size: 0.75rem; color: var(--text-muted); }
.sort-btn {
  padding: var(--space-1) var(--space-3); font-size: 0.75rem; border-radius: var(--radius);
  border: 1px solid var(--border); background: none; cursor: pointer; color: var(--text-secondary);
}
.sort-btn.is-active { background: var(--accent-strong); color: #fff; border-color: var(--accent-strong); }
.risk-critical { color: #ef4444; }
.risk-high     { color: #f97316; }
.risk-medium   { color: #60a5fa; }
.risk-low      { color: #4ade80; }
.risk-table tr.risk-critical td:first-child { border-left: 3px solid #ef4444; }
.risk-table tr.risk-high     td:first-child { border-left: 3px solid #f97316; }
.risk-table tr.risk-medium   td:first-child { border-left: 3px solid #60a5fa; }
.risk-table tr.risk-low      td:first-child { border-left: 3px solid #4ade80; }
.score-cell { font-weight: 700; }
.expand-row td { background: var(--bg-elevated); }
.expand-detail { font-size: 0.78rem; color: var(--text-secondary); padding: var(--space-2) 0; }

/* Gantt */
.gantt { display: flex; flex-direction: column; gap: var(--space-3); padding: var(--space-4); background: var(--bg-surface); border: 1px solid var(--border); border-radius: var(--radius); }
.gantt-row { display: flex; align-items: center; gap: var(--space-4); cursor: pointer; }
.gantt-row.is-active { font-weight: 600; }
.gantt-label { font-size: 0.8rem; width: 52px; }
.gantt-track { flex: 1; background: var(--bg-elevated); border-radius: 3px; height: 10px; }
.gantt-fill { height: 100%; border-radius: 3px; transition: width 0.4s; }
.gantt-fill.phase-complete { background: #4ade80; }
.gantt-fill.phase-active   { background: #f97316; }
.gantt-pct { font-size: 0.75rem; width: 56px; text-align: right; }

/* Phase detail */
.phase-detail-head { display: flex; align-items: baseline; justify-content: space-between; margin-bottom: var(--space-3); }
.phase-detail-title { font-size: 0.9rem; font-weight: 600; }
.phase-detail-period { font-size: 0.75rem; color: var(--text-muted); }
.activity-list { list-style: none; padding: 0; margin: 0 0 var(--space-4); display: flex; flex-direction: column; gap: var(--space-2); }
.activity-row { display: flex; align-items: center; gap: var(--space-3); font-size: 0.8rem; }
.act-icon { width: 16px; font-weight: 700; }
.act-icon.done    { color: #4ade80; }
.act-icon.active  { color: #f97316; }
.act-icon.pending { color: var(--text-muted); }
.act-name { flex: 1; }
.act-budget { color: var(--text-subtle); font-size: 0.75rem; }
.budget-chips { display: flex; gap: var(--space-3); }
.budget-chip { text-align: center; }
.chip-val { display: block; font-family: var(--font-display); font-weight: 600; font-size: 1rem; color: var(--text-primary); }
.chip-lbl { display: block; font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-muted); }
.budget-chip.spent     .chip-val { color: #4ade80; }
.budget-chip.remaining .chip-val { color: #f97316; }
</style>
