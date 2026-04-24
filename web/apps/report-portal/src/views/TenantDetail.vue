<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useApiClient } from '../stores/apiClient';
import type { TenantResponse } from '@triton/api-client';

const route = useRoute();
const router = useRouter();
const api = useApiClient();

const id = route.params.id as string;
const tenant = ref<TenantResponse | null>(null);
const loading = ref(true);
const error = ref('');

const renewKey = ref('');
const renewBusy = ref(false);
const renewError = ref('');

onMounted(async () => {
  try {
    tenant.value = await api.get().getPlatformTenant(id);
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load tenant';
  } finally {
    loading.value = false;
  }
});

async function renew() {
  if (!renewKey.value) return;
  renewBusy.value = true;
  renewError.value = '';
  try {
    await api.get().renewTenantLicence(id, renewKey.value);
    tenant.value = await api.get().getPlatformTenant(id);
    renewKey.value = '';
  } catch (err) {
    renewError.value = err instanceof Error ? err.message : 'Renew failed';
  } finally {
    renewBusy.value = false;
  }
}

async function remove() {
  if (!confirm('Delete this tenant? This action cannot be undone.')) return;
  try {
    await api.get().deletePlatformTenant(id);
    await router.push('/platform/tenants');
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Delete failed';
  }
}
</script>

<template>
  <div>
    <button @click="router.back()">← Back</button>
    <p v-if="loading">Loading…</p>
    <p v-if="error" class="error">{{ error }}</p>

    <template v-if="tenant">
      <h1>{{ tenant.name }}</h1>
      <dl>
        <dt>ID</dt><dd><code>{{ tenant.id }}</code></dd>
        <dt>Licence ID</dt><dd>{{ tenant.licenceId }}</dd>
        <dt>Status</dt><dd :class="tenant.licenceStatus">{{ tenant.licenceStatus }}</dd>
        <dt>Expires</dt><dd>{{ tenant.expiresAt ? new Date(tenant.expiresAt).toLocaleString() : '—' }}</dd>
      </dl>

      <section>
        <h2>Renew Licence</h2>
        <form @submit.prevent="renew">
          <label>New licence key<input v-model="renewKey" required /></label>
          <p v-if="renewError" class="error">{{ renewError }}</p>
          <button type="submit" :disabled="renewBusy">{{ renewBusy ? 'Renewing…' : 'Renew' }}</button>
        </form>
      </section>

      <section class="danger-zone">
        <h2>Danger zone</h2>
        <button class="danger" @click="remove">Delete tenant</button>
      </section>
    </template>
  </div>
</template>

<style scoped>
dl { display: grid; grid-template-columns: max-content 1fr; gap: var(--space-1) var(--space-4); margin: var(--space-4) 0; }
dt { font-weight: 600; color: var(--text-muted); }
section { margin-top: var(--space-6); }
form { display: flex; flex-direction: column; gap: var(--space-3); max-width: 360px; }
label { display: flex; flex-direction: column; gap: var(--space-1); }
.error { color: var(--color-danger); }
.active { color: var(--color-success, green); }
.grace { color: var(--color-warning, orange); }
.expired { color: var(--color-danger); }
.danger-zone { border-top: 1px solid var(--color-danger); padding-top: var(--space-4); }
button.danger { color: var(--color-danger); }
</style>
