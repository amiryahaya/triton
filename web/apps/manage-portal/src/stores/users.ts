import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { ManageUser, CreateUserReq, CreateUserResp } from '@triton/api-client';
import { useApiClient } from './apiClient';

export const useUsersStore = defineStore('users', () => {
  const items = ref<ManageUser[]>([]);
  const loading = ref(false);

  async function fetch() {
    loading.value = true;
    try { items.value = await useApiClient().get().listUsers(); }
    finally { loading.value = false; }
  }
  async function create(req: CreateUserReq): Promise<CreateUserResp> {
    const resp = await useApiClient().get().createUser(req);
    await fetch();
    return resp;
  }
  async function remove(id: string): Promise<void> {
    await useApiClient().get().deleteUser(id);
    // Optimistically drop the row from local state. The list is short
    // enough that a refetch would also work; local prune is instant.
    items.value = items.value.filter((u) => u.id !== id);
  }

  return { items, loading, fetch, create, remove };
});
