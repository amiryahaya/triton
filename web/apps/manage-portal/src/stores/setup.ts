import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { SetupStatus } from '@triton/api-client';
import { useApiClient } from './apiClient';

export const useSetupStore = defineStore('setup', () => {
  const status = ref<SetupStatus | null>(null);
  const loading = ref(false);
  const error = ref<string>('');

  async function refresh() {
    const api = useApiClient().get();
    loading.value = true;
    error.value = '';
    try {
      status.value = await api.getSetupStatus();
    } catch (err) {
      error.value = err instanceof Error ? err.message : 'failed to load setup status';
    } finally {
      loading.value = false;
    }
  }

  return { status, loading, error, refresh };
});
