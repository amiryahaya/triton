import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { Lockout } from '@triton/api-client';
import { useApiClient } from './apiClient';

export const useSecurityStore = defineStore('security', () => {
  const items = ref<Lockout[]>([]);
  const loading = ref(false);

  async function fetch() {
    loading.value = true;
    try {
      const resp = await useApiClient().get().listLockouts();
      items.value = resp.active_lockouts;
    } finally {
      loading.value = false;
    }
  }

  async function remove(email: string, ip: string): Promise<void> {
    await useApiClient().get().clearLockout(email, ip);
    items.value = items.value.filter((l: Lockout) => !(l.email === email && l.ip === ip));
  }

  return { items, loading, fetch, remove };
});
