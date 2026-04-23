import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { HostSummary, ScanSummary } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useMachinesStore = defineStore('machines', () => {
  const items = ref<HostSummary[]>([]);
  const history = ref<ScanSummary[]>([]);
  const loading = ref(false);
  const historyLoading = ref(false);

  async function fetch(): Promise<void> {
    const api = useApiClient().get();
    loading.value = true;
    try {
      items.value = await api.listMachines();
    } catch (e) {
      useToast().error({
        title: 'Failed to load machines',
        description: String(e),
      });
    } finally {
      loading.value = false;
    }
  }

  async function fetchHistory(hostname: string): Promise<void> {
    const api = useApiClient().get();
    historyLoading.value = true;
    try {
      history.value = await api.getMachineHistory(hostname);
    } catch (e) {
      useToast().error({
        title: `Failed to load history for ${hostname}`,
        description: String(e),
      });
    } finally {
      historyLoading.value = false;
    }
  }

  return { items, history, loading, historyLoading, fetch, fetchHistory };
});
