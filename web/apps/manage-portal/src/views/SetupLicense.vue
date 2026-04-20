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

const licenseServerURL = ref('https://');
const licenseKey = ref('');
const busy = ref(false);
const error = ref('');

async function submit() {
  busy.value = true;
  error.value = '';
  try {
    await api.get().activateLicense({
      license_server_url: licenseServerURL.value,
      license_key: licenseKey.value,
    });
    toast.success({ title: 'Licence activated', description: 'Manage Server is ready.' });
    await setup.refresh();
    router.push('/dashboard');
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'activation failed';
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="wiz">
    <h1>Activate licence</h1>
    <p>Point at your Triton Licence Server and paste the licence key.</p>
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
      :disabled="busy"
      @click="submit"
    >
      {{ busy ? 'Activating…' : 'Activate' }}
    </TButton>
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
</style>
