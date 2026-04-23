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
