import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { PushStatus } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const usePushStatusStore = defineStore('pushstatus', () => {
  const status = ref<PushStatus | null>(null);
  const loading = ref(false);
  let pollHandle: number | null = null;

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { status.value = await api.getPushStatus(); }
    catch (e) { useToast().error({ title: 'Failed to load push status', description: String(e) }); }
    finally { loading.value = false; }
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

  return { status, loading, fetch, startPolling, stopPolling };
});
