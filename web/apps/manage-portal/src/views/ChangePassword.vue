<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRouter } from 'vue-router';
import { TInput, TFormField, TButton, useToast } from '@triton/ui';
import { useApiClient } from '../stores/apiClient';
import { useAuthStore } from '../stores/auth';

const router = useRouter();
const api = useApiClient();
const auth = useAuthStore();
const toast = useToast();

const current = ref('');
const next = ref('');
const confirm = ref('');
const busy = ref(false);
const serverError = ref('');

// Policy: ≥ 12 chars + must contain a digit. Mirrors Manage Server's
// validatePassword guard so the UI doesn't submit obviously-invalid
// payloads and the submit button stays disabled until compliant.
const policyOK = computed(() => next.value.length >= 12 && /[0-9]/.test(next.value));
const matches = computed(() => next.value === confirm.value);
const differs = computed(() => next.value !== current.value);
const valid = computed(
  () => current.value.length > 0 && policyOK.value && matches.value && differs.value,
);

const forced = computed(() => auth.claims?.mustChangePassword === true);

async function submit() {
  if (!valid.value) return;
  busy.value = true;
  serverError.value = '';
  try {
    const resp = await api.get().changePassword({ current: current.value, next: next.value });
    auth.setToken(resp.token);
    toast.success({ title: 'Password changed' });
    await router.push('/dashboard');
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Failed';
    if (msg.includes('401')) {
      serverError.value = 'Current password is incorrect.';
      current.value = '';
    } else {
      serverError.value = msg;
    }
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <form
    class="wiz"
    @submit.prevent="submit"
  >
    <h1>Change password</h1>
    <p
      v-if="forced"
      class="forced"
    >
      First-time login. You must set a new password before continuing.
    </p>

    <TFormField label="Current password">
      <TInput
        v-model="current"
        type="password"
        autocomplete="current-password"
      />
    </TFormField>

    <TFormField label="New password (≥ 12 chars, must contain a digit)">
      <TInput
        v-model="next"
        type="password"
        autocomplete="new-password"
      />
    </TFormField>

    <TFormField label="Confirm new password">
      <TInput
        v-model="confirm"
        type="password"
        autocomplete="new-password"
      />
    </TFormField>

    <p
      v-if="next && !policyOK"
      class="hint"
    >
      Password must be at least 12 characters and contain at least one digit.
    </p>
    <p
      v-if="confirm && !matches"
      class="hint"
    >
      Passwords do not match.
    </p>
    <p
      v-if="next && !differs"
      class="hint"
    >
      New password must differ from current.
    </p>
    <p
      v-if="serverError"
      class="err"
    >
      {{ serverError }}
    </p>

    <TButton
      type="submit"
      variant="primary"
      :disabled="!valid || busy"
    >
      {{ busy ? 'Changing…' : 'Change password' }}
    </TButton>
  </form>
</template>

<style scoped>
.wiz {
  max-width: 480px;
  margin: 5rem auto;
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.forced {
  padding: var(--space-3);
  background: var(--warning-bg, var(--bg-surface));
  border-radius: var(--radius);
}
.hint {
  color: var(--text-muted);
  font-size: 0.85rem;
}
.err {
  color: var(--danger);
}
</style>
