<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { TInput, TFormField, TButton, useToast } from '@triton/ui';
import { useApiClient } from '../stores/apiClient';
import { useSetupStore } from '../stores/setup';

const router = useRouter();
const api = useApiClient();
const setup = useSetupStore();
const toast = useToast();

const serverName = ref('');
const licenseServerURL = ref('https://');
const licenseKey = ref('');
const busy = ref(false);
const error = ref('');

const confirmed = ref(false);
const confirmedName = ref('');
const confirmedID = ref('');

async function submit() {
  busy.value = true;
  error.value = '';
  try {
    const res = await api.get().activateLicense({
      server_name: serverName.value,
      license_server_url: licenseServerURL.value,
      license_key: licenseKey.value,
    });
    confirmedName.value = res.server_name;
    confirmedID.value = res.instance_id;
    confirmed.value = true;
    toast.success({ title: 'Licence activated', description: 'Manage Server is ready.' });
    await setup.refresh();
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'activation failed';
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="wiz">
    <template v-if="confirmed">
      <h1>Activation complete</h1>
      <div class="confirm-panel">
        <p><span class="label">Server name</span><span class="value">{{ confirmedName }}</span></p>
        <p><span class="label">Server ID</span><span class="value mono">{{ confirmedID }}</span></p>
      </div>
      <TButton
        variant="primary"
        @click="router.push('/dashboard')"
      >
        Go to dashboard
      </TButton>
    </template>
    <template v-else>
      <h1>Activate licence</h1>
      <p>Point at your Triton Licence Server and paste the licence key.</p>
      <TFormField label="Server name">
        <TInput
          v-model="serverName"
          maxlength="100"
          placeholder="e.g. HQ Manage Server"
        />
      </TFormField>
      <TFormField label="Licence Server URL">
        <TInput v-model="licenseServerURL" />
      </TFormField>
      <TFormField label="Licence key">
        <TInput v-model="licenseKey" />
      </TFormField>
      <p
        v-if="error"
        class="err"
      >
        {{ error }}
      </p>
      <TButton
        variant="primary"
        :disabled="busy || serverName.trim().length === 0"
        @click="submit"
      >
        {{ busy ? 'Activating…' : 'Activate' }}
      </TButton>
    </template>
  </div>
</template>

<style scoped>
.wiz {
  max-width: 480px;
  margin: 5rem auto;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}
.err {
  color: var(--danger);
}
.confirm-panel {
  background: var(--surface-2, #f4f4f5);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}
.confirm-panel p {
  margin: 0;
  display: flex;
  gap: 0.75rem;
  align-items: baseline;
}
.label {
  font-weight: 600;
  min-width: 7rem;
  color: var(--text-2, #6b7280);
  font-size: 0.875rem;
}
.value {
  color: var(--text-1, #111827);
}
.mono {
  font-family: ui-monospace, monospace;
  font-size: 0.875rem;
  word-break: break-all;
}
</style>
