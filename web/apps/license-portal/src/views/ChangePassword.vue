<script setup lang="ts">
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';
import { TPanel, TFormField, TInput, TButton, useToast } from '@triton/ui';
import { useApiClient } from '../stores/apiClient';
import { useAuthStore } from '../stores/auth';

const api = useApiClient();
const auth = useAuthStore();
const router = useRouter();
const toast = useToast();

const current = ref('');
const next = ref('');
const confirm = ref('');
const busy = ref(false);
const err = ref('');

const MIN = 12;

const canSubmit = computed(() =>
  current.value.length > 0
  && next.value.length >= MIN
  && next.value === confirm.value
);

async function submit() {
  err.value = '';
  busy.value = true;
  try {
    const resp = await api.get().changePassword({
      current: current.value,
      next: next.value,
    });
    auth.setToken(resp.token);
    auth.setMustChange(false);
    toast.success({ title: 'Password changed' });
    await router.replace('/');
  } catch (e) {
    err.value = e instanceof Error ? e.message : 'Change password failed';
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="cp">
    <TPanel title="Change password">
      <p class="sub">
        You must set a new password to continue.
      </p>
      <div class="form">
        <TFormField label="Current password" required>
          <TInput v-model="current" type="password" data-test="cp-current" />
        </TFormField>
        <TFormField label="New password" required hint="Minimum 12 characters.">
          <TInput v-model="next" type="password" data-test="cp-next" />
        </TFormField>
        <TFormField label="Confirm new password" required>
          <TInput v-model="confirm" type="password" data-test="cp-confirm" />
        </TFormField>
        <div v-if="err" class="err">{{ err }}</div>
        <TButton
          variant="primary"
          :disabled="!canSubmit || busy"
          data-test="cp-submit"
          @click="submit"
        >
          {{ busy ? 'Changing…' : 'Change password' }}
        </TButton>
      </div>
    </TPanel>
  </div>
</template>

<style scoped>
.cp { max-width: 480px; margin: 80px auto; padding: var(--space-4); }
.sub { color: var(--text-muted); font-size: 0.82rem; margin-bottom: var(--space-3); }
.form { display: flex; flex-direction: column; gap: var(--space-3); }
.err { color: var(--unsafe); font-size: 0.76rem; }
</style>
