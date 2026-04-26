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
  PortSurveyEnqueueReq,
} from '@triton/api-client';
import { useScanJobsStore } from '../stores/scanjobs';
import { useTagsStore } from '../stores/tags';
import { useHostsStore } from '../stores/hosts';
import ScanJobEnqueueForm from './modals/ScanJobEnqueueForm.vue';
import ScanJobDetailDrawer from './modals/ScanJobDetailDrawer.vue';
import PortSurveyEnqueueForm from './modals/PortSurveyEnqueueForm.vue';

const jobs = useScanJobsStore();
const tags = useTagsStore();
const hosts = useHostsStore();
const toast = useToast();

const enqueueOpen = ref(false);
const drawerJobID = ref<string | null>(null);
const portSurveyOpen = ref(false);

const columns: Column<ScanJob>[] = [
  { key: 'profile', label: 'Profile' },
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

// TSelect requires a defined-string modelValue; the store keeps status
// optional. Normalise around an empty string.
const filterStatus = computed<string>({
  get: () => jobs.filter.status ?? '',
  set: (v: string) => {
    jobs.filter.status = v ? (v as ScanJobStatus) : undefined;
  },
});

onMounted(async () => {
  await tags.fetch();
  jobs.startPolling();
  void hosts.fetch();
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

async function onPortSurveySubmit(req: PortSurveyEnqueueReq) {
  try {
    const created = await jobs.enqueuePortSurvey(req);
    toast.success({
      title: 'Port survey queued',
      description: `${created.length} job${created.length === 1 ? '' : 's'} created`,
    });
    portSurveyOpen.value = false;
  } catch (e) {
    toast.error({ title: 'Failed to queue port survey', description: String(e) });
  }
}
</script>

<template>
  <section class="scanjobs-view">
    <header class="scanjobs-head">
      <div>
        <h1>Scan Jobs</h1>
        <p class="scanjobs-sub">Scan queue across agents and tags. Polls every 5 seconds.</p>
      </div>
      <div class="scanjobs-head-actions">
        <TButton variant="secondary" size="sm" @click="portSurveyOpen = true">
          Port Survey
        </TButton>
        <TButton
          variant="primary"
          size="sm"
          @click="enqueueOpen = true"
        >
          Enqueue
        </TButton>
      </div>
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
      <template #[`cell:profile`]="{ row }">
        {{ row.profile }}
        <span v-if="row.job_type === 'port_survey'" class="port-survey-badge">Port Survey</span>
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
      :tags="tags.items"
      @close="enqueueOpen = false"
      @submit="onEnqueue"
    />

    <ScanJobDetailDrawer
      :open="!!drawerJobID"
      :job-i-d="drawerJobID"
      @close="drawerJobID = null"
    />

    <PortSurveyEnqueueForm
      :open="portSurveyOpen"
      :hosts="hosts.items"
      @close="portSurveyOpen = false"
      @submit="onPortSurveySubmit"
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
.scanjobs-head-actions {
  display: flex;
  gap: var(--space-2);
  align-items: center;
}
.scanjobs-actions {
  display: flex;
  gap: var(--space-2);
  justify-content: flex-end;
  width: 100%;
}
.port-survey-badge {
  display: inline-block;
  font-size: 0.7rem;
  background: #dbeafe;
  color: #1d4ed8;
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  margin-left: 0.3rem;
  vertical-align: middle;
}
</style>
