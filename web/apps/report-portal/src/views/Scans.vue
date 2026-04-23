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
