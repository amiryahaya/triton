import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { ExecutiveSummary } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useOverviewStore = defineStore('overview', () => {
  const summary = ref<ExecutiveSummary | null>(null);
  const loading = ref(false);

  async function fetch(): Promise<void> {
    const api = useApiClient().get();
    loading.value = true;
    try {
      summary.value = await api.executive();
    } catch (e) {
      useToast().error({
        title: 'Failed to load overview',
        description: String(e),
      });
    } finally {
      loading.value = false;
    }
  }

  return { summary, loading, fetch };
});
