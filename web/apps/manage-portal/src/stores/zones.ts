import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { Zone } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useZonesStore = defineStore('zones', () => {
  const items = ref<Zone[]>([]);
  const loading = ref(false);
  const selected = ref<Zone | null>(null);

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listZones(); }
    catch (e) { useToast().error({ title: 'Failed to load zones', description: String(e) }); }
    finally { loading.value = false; }
  }
  async function create(req: { name: string; description?: string }) {
    const api = useApiClient().get();
    const z = await api.createZone(req);
    items.value.push(z);
    return z;
  }
  async function update(id: string, req: { name: string; description?: string }) {
    const api = useApiClient().get();
    const z = await api.updateZone(id, req);
    const i = items.value.findIndex(x => x.id === id);
    if (i >= 0) items.value[i] = z;
    return z;
  }
  async function remove(id: string) {
    const api = useApiClient().get();
    await api.deleteZone(id);
    items.value = items.value.filter(x => x.id !== id);
  }

  return { items, loading, selected, fetch, create, update, remove };
});
