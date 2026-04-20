import { defineStore } from 'pinia';
import { ref, watch } from 'vue';
import type { Host, CreateHostReq } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

const FILTER_KEY = 'manage-portal.hosts.filter';

function loadFilter(): { zoneID?: string } {
  try { return JSON.parse(localStorage.getItem(FILTER_KEY) ?? '{}'); }
  catch { return {}; }
}

export const useHostsStore = defineStore('hosts', () => {
  const items = ref<Host[]>([]);
  const loading = ref(false);
  const filter = ref<{ zoneID?: string }>(loadFilter());

  watch(filter, (v) => localStorage.setItem(FILTER_KEY, JSON.stringify(v)), { deep: true });

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listHosts(filter.value.zoneID); }
    catch (e) { useToast().error({ title: 'Failed to load hosts', description: String(e) }); }
    finally { loading.value = false; }
  }
  async function create(req: CreateHostReq) {
    const h = await useApiClient().get().createHost(req);
    items.value.push(h); return h;
  }
  async function bulkCreate(hosts: CreateHostReq[]) {
    const out = await useApiClient().get().bulkCreateHosts({ hosts });
    items.value.push(...out); return out;
  }
  async function update(id: string, req: CreateHostReq) {
    const h = await useApiClient().get().updateHost(id, req);
    const i = items.value.findIndex(x => x.id === id);
    if (i >= 0) items.value[i] = h;
    return h;
  }
  async function remove(id: string) {
    await useApiClient().get().deleteHost(id);
    items.value = items.value.filter(x => x.id !== id);
  }

  return { items, loading, filter, fetch, create, bulkCreate, update, remove };
});
