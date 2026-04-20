import { defineStore } from 'pinia';
import { ref, watch } from 'vue';
import type { ScanJob, ScanJobStatus, EnqueueReq } from '@triton/api-client';
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

  return { items, selected, loading, filter, fetch, getDetail, enqueue, requestCancel, startPolling, stopPolling };
});
