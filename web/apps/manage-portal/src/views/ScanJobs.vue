<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import {
  TButton,
  TDataTable,
  TPill,
  TSelect,
  TFormField,
  useToast,
  type Column,
  type PillVariant,
} from '@triton/ui';
import type {
  ScanJob,
  ScanJobStatus,
  EnqueueReq,
} from '@triton/api-client';
import { useScanJobsStore } from '../stores/scanjobs';
import { useZonesStore } from '../stores/zones';
import ScanJobEnqueueForm from './modals/ScanJobEnqueueForm.vue';
import ScanJobDetailDrawer from './modals/ScanJobDetailDrawer.vue';

const jobs = useScanJobsStore();
const zones = useZonesStore();
const toast = useToast();

const enqueueOpen = ref(false);
const drawerJobID = ref<string | null>(null);

const columns: Column<ScanJob>[] = [
  { key: 'profile', label: 'Profile' },
  { key: 'zone_id', label: 'Zone' },
  { key: 'host_id', label: 'Host' },
  { key: 'status', label: 'Status' },
  { key: 'enqueued_at', label: 'Enqueued' },
  { key: 'progress_text', label: 'Progress' },
  { key: 'id', label: '', width: '110px', align: 'right' },
];

// TPill ships: safe | warn | deprecated | unsafe | info | neutral |
// enterprise. Map scan-job statuses to the closest semantic match.
const statusVariant: Record<ScanJobStatus, PillVariant> = {
  queued: 'neutral',
  running: 'warn',
  completed: 'safe',
  failed: 'unsafe',
  cancelled: 'info',
};

const zoneNameByID = computed(() => {
  const m = new Map<string, string>();
  for (const z of zones.items) m.set(z.id, z.name);
  return m;
});

// TSelect requires a defined-string modelValue; the store keeps status
// optional. Normalise around an empty string.
const filterStatus = computed<string>({
  get: () => jobs.filter.status ?? '',
  set: (v: string) => {
    jobs.filter.status = v ? (v as ScanJobStatus) : undefined;
  },
});

onMounted(async () => {
  await zones.fetch();
  jobs.startPolling();
});

onUnmounted(() => {
  jobs.stopPolling();
});

// Refetch whenever the status filter changes. The store persists the
// filter to localStorage on its own via a deep watcher.
watch(
  () => jobs.filter.status,
  () => {
    void jobs.fetch();
  }
);

async function onEnqueue(req: EnqueueReq) {
  try {
    const created = await jobs.enqueue(req);
    toast.success({
      title: 'Enqueued scan jobs',
      description: `${created.length} job${created.length === 1 ? '' : 's'} queued.`,
    });
    enqueueOpen.value = false;
  } catch (e) {
    toast.error({ title: 'Enqueue failed', description: String(e) });
  }
}

async function cancelRow(j: ScanJob) {
  try {
    await jobs.requestCancel(j.id);
    toast.info({ title: 'Cancel requested', description: j.id });
  } catch (e) {
    toast.error({ title: 'Cancel failed', description: String(e) });
  }
}

function openDrawer(j: ScanJob) {
  drawerJobID.value = j.id;
}
</script>

<template>
  <section class="scanjobs-view">
    <header class="scanjobs-head">
      <div>
        <h1>Scan Jobs</h1>
        <p class="scanjobs-sub">Scan queue across agents and zones. Polls every 5 seconds.</p>
      </div>
      <TButton
        variant="primary"
        size="sm"
        @click="enqueueOpen = true"
      >
        Enqueue
      </TButton>
    </header>

    <div class="scanjobs-filter">
      <TFormField label="Filter by status">
        <TSelect v-model="filterStatus">
          <option value="">
            All statuses
          </option>
          <option value="queued">
            Queued
          </option>
          <option value="running">
            Running
          </option>
          <option value="completed">
            Completed
          </option>
          <option value="failed">
            Failed
          </option>
          <option value="cancelled">
            Cancelled
          </option>
        </TSelect>
      </TFormField>
    </div>

    <TDataTable
      :columns="columns"
      :rows="jobs.items"
      row-key="id"
      :empty-text="jobs.loading ? 'Loading…' : 'No scan jobs yet.'"
      @row-click="openDrawer"
    >
      <template #[`cell:zone_id`]="{ row }">
        {{ row.zone_id ? (zoneNameByID.get(row.zone_id) ?? row.zone_id) : '—' }}
      </template>
      <template #[`cell:host_id`]="{ row }">
        {{ row.host_id ?? '—' }}
      </template>
      <template #[`cell:status`]="{ row }">
        <TPill :variant="statusVariant[row.status]">
          {{ row.status }}
        </TPill>
      </template>
      <template #[`cell:progress_text`]="{ row }">
        {{ row.progress_text || '—' }}
      </template>
      <template #[`cell:id`]="{ row }">
        <div class="scanjobs-actions">
          <TButton
            v-if="row.status === 'queued' || row.status === 'running'"
            variant="ghost"
            size="sm"
            @click.stop="cancelRow(row)"
          >
            Cancel
          </TButton>
        </div>
      </template>
    </TDataTable>

    <ScanJobEnqueueForm
      :open="enqueueOpen"
      :zones="zones.items"
      @close="enqueueOpen = false"
      @submit="onEnqueue"
    />

    <ScanJobDetailDrawer
      :open="!!drawerJobID"
      :job-i-d="drawerJobID"
      @close="drawerJobID = null"
    />
  </section>
</template>

<style scoped>
.scanjobs-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.scanjobs-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.scanjobs-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.scanjobs-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.scanjobs-filter {
  max-width: 280px;
}
.scanjobs-actions {
  display: flex;
  gap: var(--space-2);
  justify-content: flex-end;
  width: 100%;
}
</style>
