import { defineStore } from 'pinia';
import { ref, watch } from 'vue';
import type {
  ScanJob, ScanJobStatus, EnqueueReq, PortSurveyEnqueueReq,
  ScanBatch, BatchEnqueueReq, BatchEnqueueResp,
  ScanSchedule, ScheduleReq,
} from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

const FILTER_KEY = 'manage-portal.scanjobs.filter';

function loadFilter(): { status?: ScanJobStatus } {
  try { return JSON.parse(localStorage.getItem(FILTER_KEY) ?? '{}'); }
  catch { return {}; }
}

export const useScanJobsStore = defineStore('scanjobs', () => {
  const items = ref<ScanJob[]>([]);
  const selected = ref<ScanJob | null>(null);
  const loading = ref(false);
  const filter = ref<{ status?: ScanJobStatus }>(loadFilter());
  let pollHandle: number | null = null;

  watch(filter, (v) => localStorage.setItem(FILTER_KEY, JSON.stringify(v)), { deep: true });

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listScanJobs(filter.value); }
    catch (e) { useToast().error({ title: 'Failed to load scan jobs', description: String(e) }); }
    finally { loading.value = false; }
  }

  async function getDetail(id: string) {
    selected.value = await useApiClient().get().getScanJob(id);
  }

  async function enqueue(req: EnqueueReq) {
    const jobs = await useApiClient().get().enqueueScanJobs(req);
    await fetch();
    return jobs;
  }

  async function enqueuePortSurvey(req: PortSurveyEnqueueReq) {
    const result = await useApiClient().get().enqueuePortSurvey(req);
    await fetch();
    return result.jobs;
  }

  async function requestCancel(id: string) {
    await useApiClient().get().cancelScanJob(id);
    await fetch();
  }

  function startPolling() {
    if (pollHandle) return;
    fetch();
    pollHandle = window.setInterval(() => {
      if (document.hidden) return;
      fetch();
    }, 5000);
  }
  function stopPolling() {
    if (pollHandle) { clearInterval(pollHandle); pollHandle = null; }
  }

  // --- Batch state ---
  const batches = ref<ScanBatch[]>([]);
  const batchesLoading = ref(false);

  async function fetchBatches(limit = 50) {
    batchesLoading.value = true;
    try {
      const api = useApiClient().get();
      batches.value = await api.listBatches({ limit });
    } catch (e) {
      useToast().error({ title: 'Failed to load batches', description: String(e) });
    } finally {
      batchesLoading.value = false;
    }
  }

  async function enqueueBatch(req: BatchEnqueueReq): Promise<BatchEnqueueResp> {
    const api = useApiClient().get();
    const resp = await api.enqueueBatch(req);
    await fetchBatches();
    return resp;
  }

  // --- Schedule state ---
  const schedules = ref<ScanSchedule[]>([]);
  const schedulesLoading = ref(false);

  async function fetchSchedules() {
    schedulesLoading.value = true;
    try {
      const api = useApiClient().get();
      schedules.value = await api.listSchedules();
    } catch (e) {
      useToast().error({ title: 'Failed to load schedules', description: String(e) });
    } finally {
      schedulesLoading.value = false;
    }
  }

  async function createSchedule(req: ScheduleReq): Promise<ScanSchedule> {
    const api = useApiClient().get();
    const sched = await api.createSchedule(req);
    schedules.value.unshift(sched);
    return sched;
  }

  async function toggleSchedule(id: string, enabled: boolean) {
    try {
      const api = useApiClient().get();
      const updated = await api.patchSchedule(id, { enabled });
      const idx = schedules.value.findIndex(s => s.id === id);
      if (idx >= 0) schedules.value[idx] = updated;
    } catch (e) {
      useToast().error({ title: 'Failed to update schedule', description: String(e) });
    }
  }

  async function deleteSchedule(id: string) {
    try {
      const api = useApiClient().get();
      await api.deleteSchedule(id);
      schedules.value = schedules.value.filter(s => s.id !== id);
    } catch (e) {
      useToast().error({ title: 'Failed to delete schedule', description: String(e) });
    }
  }

  return {
    items, selected, loading, filter, fetch, getDetail, enqueue, enqueuePortSurvey, requestCancel, startPolling, stopPolling,
    batches, batchesLoading, fetchBatches, enqueueBatch,
    schedules, schedulesLoading, fetchSchedules,
    createSchedule, toggleSchedule, deleteSchedule,
  };
});
