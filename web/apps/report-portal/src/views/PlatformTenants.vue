<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useApiClient } from '../stores/apiClient';
import type { TenantResponse } from '@triton/api-client';

const api = useApiClient();
const tenants = ref<TenantResponse[]>([]);
const loading = ref(true);
const error = ref('');

const showCreate = ref(false);
const createForm = ref({ licenceKey: '', adminName: '', adminEmail: '' });
const createBusy = ref(false);
const createError = ref('');

onMounted(async () => { await load(); });

async function load() {
  error.value = '';
  loading.value = true;
  try {
    tenants.value = await api.get().listPlatformTenants();
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load tenants';
  } finally {
    loading.value = false;
  }
}

async function create() {
  createBusy.value = true;
  createError.value = '';
  try {
    await api.get().createPlatformTenant(createForm.value);
    showCreate.value = false;
    createForm.value = { licenceKey: '', adminName: '', adminEmail: '' };
    await load();
  } catch (err) {
    createError.value = err instanceof Error ? err.message : 'Create failed';
  } finally {
    createBusy.value = false;
  }
}
</script>

<template>
  <div>
    <div class="header">
      <h1>Tenants</h1>
      <button @click="showCreate = true">Add tenant</button>
    </div>

    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="loading">Loading…</p>

    <table v-else>
      <thead>
        <tr><th>ID</th><th>Name</th><th>Licence status</th><th>Expires</th><th></th></tr>
      </thead>
      <tbody>
        <tr v-for="t in tenants" :key="t.id">
          <td><code>{{ t.id.slice(0, 8) }}</code></td>
          <td>{{ t.name }}</td>
          <td :class="t.licenceStatus">{{ t.licenceStatus }}</td>
          <td>{{ t.expiresAt ? new Date(t.expiresAt).toLocaleDateString() : '—' }}</td>
          <td><router-link :to="`/platform/tenants/${t.id}`">Detail</router-link></td>
        </tr>
      </tbody>
    </table>

    <div v-if="showCreate" class="modal-overlay" @click.self="showCreate = false">
      <div class="modal">
        <h2>Add Tenant</h2>
        <form @submit.prevent="create">
          <label>Licence key<input v-model="createForm.licenceKey" required /></label>
          <label>Admin name<input v-model="createForm.adminName" required /></label>
          <label>Admin email<input v-model="createForm.adminEmail" type="email" required /></label>
          <p v-if="createError" class="error">{{ createError }}</p>
          <div class="actions">
            <button type="button" @click="showCreate = false">Cancel</button>
            <button type="submit" :disabled="createBusy">{{ createBusy ? 'Creating…' : 'Create' }}</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<style scoped>
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-4); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--border); }
.error { color: var(--color-danger); }
.active { color: var(--color-success, green); }
.grace { color: var(--color-warning, orange); }
.expired { color: var(--color-danger); }
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; }
.modal { background: var(--bg-surface); padding: var(--space-6); border-radius: var(--radius); min-width: 360px; }
.modal form { display: flex; flex-direction: column; gap: var(--space-3); }
.modal label { display: flex; flex-direction: column; gap: var(--space-1); }
.actions { display: flex; gap: var(--space-2); justify-content: flex-end; }
</style>
