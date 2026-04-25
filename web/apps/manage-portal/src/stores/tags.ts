import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { Tag, CreateTagReq, UpdateTagReq } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useTagsStore = defineStore('tags', () => {
  const items = ref<Tag[]>([]);
  const loading = ref(false);

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listTags(); }
    catch (e) { useToast().error({ title: 'Failed to load tags', description: String(e) }); }
    finally { loading.value = false; }
  }

  async function create(req: CreateTagReq): Promise<Tag> {
    const tag = await useApiClient().get().createTag(req);
    items.value.push(tag);
    items.value.sort((a, b) => a.name.localeCompare(b.name));
    return tag;
  }

  async function update(id: string, req: UpdateTagReq): Promise<Tag> {
    const tag = await useApiClient().get().updateTag(id, req);
    const idx = items.value.findIndex(t => t.id === id);
    if (idx !== -1) items.value[idx] = tag;
    return tag;
  }

  async function remove(id: string): Promise<void> {
    await useApiClient().get().deleteTag(id);
    items.value = items.value.filter(t => t.id !== id);
  }

  return { items, loading, fetch, create, update, remove };
});
