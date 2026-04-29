<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { useRouter } from 'vue-router';
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
} from '@triton/api-client';
import { useScanJobsStore } from '../stores/scanjobs';
import ScanJobDetailDrawer from './modals/ScanJobDetailDrawer.vue';

const router = useRouter();
const jobs = useScanJobsStore();
const toast = useToast();

const drawerJobID = ref<string | null>(null);
const activeTab = ref<'jobs' | 'schedules'>('jobs');

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
  jobs.startPolling();
  void jobs.fetchSchedules();
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
        <p class="scanjobs-sub">Scan queue across agents and tags. Polls every 5 seconds.</p>
      </div>
      <div class="scanjobs-head-actions">
        <TButton variant="primary" size="sm" @click="router.push('/operations/scan-jobs/new')">
          New Scan
        </TButton>
      </div>
    </header>

    <div class="tab-bar">
      <button :class="{ active: activeTab === 'jobs' }" @click="activeTab = 'jobs'">Jobs</button>
      <button :class="{ active: activeTab === 'schedules' }" @click="activeTab = 'schedules'">Schedules</button>
    </div>

    <template v-if="activeTab === 'jobs'">
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
    </template>

    <div v-if="activeTab === 'schedules'" class="schedules-panel">
      <div v-if="jobs.schedulesLoading">Loading…</div>
      <table v-else class="t-table">
        <thead>
          <tr>
            <th>Name</th><th>Schedule</th><th>Next run</th><th>Enabled</th><th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in jobs.schedules" :key="s.id">
            <td>{{ s.name }}</td>
            <td>{{ s.cron_expr }}</td>
            <td>{{ new Date(s.next_run_at).toLocaleString() }}</td>
            <td>
              <input type="checkbox" :checked="s.enabled"
                     @change="jobs.toggleSchedule(s.id, !s.enabled)" />
            </td>
            <td>
              <button class="btn-danger-sm" @click="jobs.deleteSchedule(s.id)">Delete</button>
            </td>
          </tr>
          <tr v-if="!jobs.schedules.length">
            <td colspan="5" class="empty-cell">No recurring schedules. Create one via New Scan.</td>
          </tr>
        </tbody>
      </table>
    </div>

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
.tab-bar {
  display: flex;
  gap: 0;
  border-bottom: 1px solid var(--border);
}
.tab-bar button {
  padding: 0.5rem 1.25rem;
  font-size: 0.875rem;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  color: var(--text-muted);
  font-family: var(--font-body);
  transition: color 0.15s, border-color 0.15s;
}
.tab-bar button.active {
  color: var(--text-primary);
  border-bottom-color: var(--color-primary, #2563eb);
}
.tab-bar button:hover:not(.active) {
  color: var(--text-primary);
}
.schedules-panel {
  overflow-x: auto;
}
.t-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}
.t-table th,
.t-table td {
  padding: 0.6rem 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
.t-table th {
  font-weight: 600;
  color: var(--text-muted);
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}
.empty-cell {
  color: var(--text-muted);
  font-style: italic;
  text-align: center;
}
.btn-danger-sm {
  padding: 0.25rem 0.6rem;
  font-size: 0.78rem;
  background: none;
  border: 1px solid var(--color-unsafe, #dc2626);
  color: var(--color-unsafe, #dc2626);
  border-radius: var(--radius-sm);
  cursor: pointer;
  font-family: var(--font-body);
}
.btn-danger-sm:hover {
  background: var(--color-unsafe, #dc2626);
  color: #fff;
}
</style>
