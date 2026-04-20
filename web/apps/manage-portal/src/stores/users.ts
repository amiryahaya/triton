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

  return { items, loading, fetch, create };
});
