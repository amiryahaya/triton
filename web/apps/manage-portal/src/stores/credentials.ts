import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { Credential, CreateCredentialReq } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useCredentialsStore = defineStore('credentials', () => {
  const items = ref<Credential[]>([]);
  const loading = ref(false);

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listCredentials(); }
    catch (e) { useToast().error({ title: 'Failed to load credentials', description: String(e) }); }
    finally { loading.value = false; }
  }

  async function create(req: CreateCredentialReq) {
    const c = await useApiClient().get().createCredential(req);
    items.value.push(c);
    return c;
  }

  async function remove(id: string) {
    await useApiClient().get().deleteCredential(id);
    items.value = items.value.filter(x => x.id !== id);
  }

  return { items, loading, fetch, create, remove };
});
