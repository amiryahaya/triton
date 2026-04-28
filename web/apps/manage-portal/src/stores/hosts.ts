import { defineStore } from 'pinia';
import { ref, watch } from 'vue';
import type { Host, CreateHostReq, UpdateHostReq } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

const FILTER_KEY = 'manage-portal.hosts.filter';

function loadFilter(): { tagIDs?: string[] } {
  try {
    const raw = localStorage.getItem(FILTER_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return { tagIDs: Array.isArray(parsed.tagIDs) ? parsed.tagIDs : undefined };
  } catch {
    return {};
  }
}

export const useHostsStore = defineStore('hosts', () => {
  const items = ref<Host[]>([]);
  const loading = ref(false);
  const filter = ref<{ tagIDs?: string[] }>(loadFilter());

  watch(filter, (v) => localStorage.setItem(FILTER_KEY, JSON.stringify(v)), { deep: true });

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listHosts(filter.value.tagIDs); }
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
  async function update(id: string, req: UpdateHostReq & { tag_ids?: string[] }) {
    const api = useApiClient().get();
    const { tag_ids, ...hostFields } = req;
    let h = await api.updateHost(id, hostFields);
    if (tag_ids !== undefined) {
      h = await api.setHostTags(id, tag_ids);
    }
    const i = items.value.findIndex(x => x.id === id);
    if (i >= 0) items.value[i] = h;
    return h;
  }
  async function remove(id: string) {
    await useApiClient().get().deleteHost(id);
    items.value = items.value.filter(x => x.id !== id);
  }
  async function registerSelf() {
    const h = await useApiClient().get().registerSelfHost();
    items.value.push(h);
    return h;
  }

  return { items, loading, filter, fetch, create, bulkCreate, update, remove, registerSelf };
});
