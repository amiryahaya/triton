<script setup lang="ts">
import { ref, computed } from 'vue';
import { TPanel, TFormField, TInput, TButton, useToast } from '@triton/ui';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();

const name = ref('');
const email = ref('');
const busy = ref(false);
const result = ref<{ tempPassword: string; emailSent: boolean } | null>(null);
const err = ref('');

const canSubmit = computed(
  () => name.value.trim() !== '' && email.value.includes('@'),
);

async function submit() {
  err.value = '';
  busy.value = true;
  try {
    const resp = await api.get().setupFirstAdmin({
      name: name.value.trim(),
      email: email.value.trim(),
    });
    result.value = { tempPassword: resp.tempPassword, emailSent: resp.emailSent };
    toast.success({
      title: resp.emailSent ? 'Invite sent' : 'Admin created',
      description: resp.emailSent
        ? `Email sent to ${resp.user.email}.`
        : 'Email not configured — copy the temp password shown.',
    });
  } catch (e) {
    err.value = e instanceof Error ? e.message : 'Setup failed';
  } finally {
    busy.value = false;
  }
}

function goToLogin() {
  window.location.hash = '#/';
}
</script>

<template>
  <div class="setup">
    <TPanel title="First-time setup">
      <p class="sub">
        No administrator exists yet. Create the first Users account to
        continue. A temporary password will be emailed to this address
        (or displayed here if email is not configured).
      </p>
      <div v-if="!result" class="form">
        <TFormField label="Name" required>
          <TInput v-model="name" data-test="setup-name" />
        </TFormField>
        <TFormField label="Email" required>
          <TInput v-model="email" type="email" data-test="setup-email" />
        </TFormField>
        <div v-if="err" class="err">{{ err }}</div>
        <TButton
          variant="primary"
          :disabled="!canSubmit || busy"
          data-test="setup-submit"
          @click="submit"
        >
          {{ busy ? 'Creating…' : 'Send invite' }}
        </TButton>
      </div>
      <div v-else class="done">
        <p class="small">
          Admin user created. Temp password (copy now — shown only once):
        </p>
        <code class="temp">{{ result.tempPassword }}</code>
        <p v-if="result.emailSent" class="small ok">
          An email has also been sent.
        </p>
        <TButton variant="primary" @click="goToLogin">Go to login</TButton>
      </div>
    </TPanel>
  </div>
</template>

<style scoped>
.setup {
  max-width: 480px;
  margin: 80px auto;
  padding: var(--space-4);
}
.sub { color: var(--text-muted); font-size: 0.82rem; margin-bottom: var(--space-3); }
.form, .done { display: flex; flex-direction: column; gap: var(--space-3); }
.err { color: var(--unsafe); font-size: 0.76rem; }
.ok { color: var(--safe); }
.temp {
  display: block;
  padding: var(--space-2);
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 0.88rem;
  word-break: break-all;
}
.small { font-size: 0.78rem; color: var(--text-muted); }
</style>
