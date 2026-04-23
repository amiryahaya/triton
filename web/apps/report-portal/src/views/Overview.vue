<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue';
import { TStatCard, TPill, TLineChart } from '@triton/ui';
import type { PillVariant } from '@triton/ui';
import type { PolicyVerdictSummary } from '@triton/api-client';
import { useOverviewStore } from '../stores/overview';

const overview = useOverviewStore();

const REFRESH_INTERVAL_MS = 60_000;
let refreshTimer: ReturnType<typeof setInterval> | undefined;

onMounted(() => {
  void overview.fetch();
  refreshTimer = setInterval(() => { void overview.fetch(); }, REFRESH_INTERVAL_MS);
});

onUnmounted(() => {
  if (refreshTimer !== undefined) clearInterval(refreshTimer);
});

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
