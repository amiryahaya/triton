<script setup lang="ts">
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';
import { TInput, TFormField, TButton, useToast } from '@triton/ui';
import { useApiClient } from '../stores/apiClient';
import { useSetupStore } from '../stores/setup';

const router = useRouter();
const api = useApiClient();
const setup = useSetupStore();
const toast = useToast();

const email = ref('');
const name = ref('');
const password = ref('');
const busy = ref(false);
const error = ref('');

// Policy: ≥ 12 chars + must contain a digit. Mirrors Manage Server's
// createAdmin guard so the UI doesn't submit obviously-invalid payloads.
const valid = computed(
  () =>
    email.value.includes('@') &&
    password.value.length >= 12 &&
    /[0-9]/.test(password.value),
);

async function submit() {
  if (!valid.value) return;
  busy.value = true;
  error.value = '';
  try {
    await api.get().createAdmin({
      email: email.value,
      name: name.value,
      password: password.value,
    });
    toast.success({ title: 'Admin created', description: 'Continue to licence activation.' });
    await setup.refresh();
    router.push('/setup/license');
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'failed';
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="wiz">
    <h1>Create first admin</h1>
    <p>Set up the initial administrator account for this Manage Server instance.</p>
    <TFormField label="Email">
      <TInput
        v-model="email"
        type="email"
      />
    </TFormField>
    <TFormField label="Name (optional)">
      <TInput v-model="name" />
    </TFormField>
    <TFormField label="Password (≥ 12 chars, must contain a digit)">
      <TInput
        v-model="password"
        type="password"
      />
    </TFormField>
    <p
      v-if="error"
      class="err"
    >
      {{ error }}
    </p>
    <TButton
      variant="primary"
      :disabled="!valid || busy"
      @click="submit"
    >
      {{ busy ? 'Creating…' : 'Create admin' }}
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
