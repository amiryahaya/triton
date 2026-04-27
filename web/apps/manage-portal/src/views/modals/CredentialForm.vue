<script setup lang="ts">
import { ref, computed } from 'vue';
import type { CredentialAuthType, CreateCredentialReq } from '@triton/api-client';
import { TModal, TFormField, TSelect, TButton, TInput } from '@triton/ui';
import { useCredentialsStore } from '../../stores/credentials';

const emit = defineEmits<{ close: [] }>();
const store = useCredentialsStore();

const name = ref('');
const authType = ref<CredentialAuthType>('ssh-key');
const username = ref('');
const privateKey = ref('');
const passphrase = ref('');
const password = ref('');
const useHttps = ref(false);
const saving = ref(false);
const error = ref('');

const pemValid = computed(() => {
  if (authType.value !== 'ssh-key') return true;
  return privateKey.value.includes('-----BEGIN');
});

async function submit() {
  error.value = '';
  if (!name.value.trim()) { error.value = 'Name is required'; return; }
  if (!username.value.trim()) { error.value = 'Username is required'; return; }
  if (authType.value === 'ssh-key' && privateKey.value && !pemValid.value) {
    error.value = 'Private key must be in PEM format'; return;
  }

  const req: CreateCredentialReq = {
    name: name.value.trim(),
    auth_type: authType.value,
    username: username.value.trim(),
  };
  if (authType.value === 'ssh-key') {
    req.private_key = privateKey.value;
    if (passphrase.value) req.passphrase = passphrase.value;
  } else {
    req.password = password.value;
    if (authType.value === 'winrm-password') req.use_https = useHttps.value;
  }

  saving.value = true;
  try {
    await store.create(req);
    emit('close');
  } catch (e: unknown) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <TModal
    :open="true"
    title="Add Credential"
    @close="emit('close')"
  >
    <div class="credential-form">
      <TFormField label="Name" required>
        <TInput v-model="name" placeholder="prod-ssh-key" />
      </TFormField>

      <TFormField label="Type">
        <TSelect v-model="authType">
          <option value="ssh-key">SSH Key</option>
          <option value="ssh-password">SSH Password</option>
          <option value="winrm-password">WinRM Password</option>
        </TSelect>
      </TFormField>

      <TFormField label="Username" required>
        <TInput v-model="username" placeholder="ubuntu" />
      </TFormField>

      <template v-if="authType === 'ssh-key'">
        <TFormField label="Private Key (PEM)">
          <textarea
            v-model="privateKey"
            rows="6"
            class="textarea-input"
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          />
          <p v-if="privateKey && !pemValid" class="field-error">
            Must be PEM format (-----BEGIN …)
          </p>
        </TFormField>
        <TFormField label="Passphrase (optional)">
          <TInput v-model="passphrase" type="password" />
        </TFormField>
      </template>

      <template v-else>
        <TFormField label="Password">
          <TInput v-model="password" type="password" />
        </TFormField>
        <TFormField v-if="authType === 'winrm-password'" label="HTTPS">
          <label class="checkbox-row">
            <input v-model="useHttps" type="checkbox" />
            Use HTTPS (port 5986)
          </label>
        </TFormField>
      </template>

      <p v-if="error" class="field-error">{{ error }}</p>
    </div>

    <template #footer>
      <TButton variant="ghost" size="sm" @click="emit('close')">Cancel</TButton>
      <TButton variant="primary" size="sm" :disabled="saving" @click="submit">
        {{ saving ? 'Saving…' : 'Save to Vault' }}
      </TButton>
    </template>
  </TModal>
</template>

<style scoped>
.credential-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.textarea-input {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono, monospace);
  font-size: 0.8rem;
  background: var(--bg-surface);
  color: var(--text-primary);
  box-sizing: border-box;
  resize: vertical;
}
.checkbox-row {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  cursor: pointer;
  font-size: 0.875rem;
}
.checkbox-row input[type='checkbox'] {
  accent-color: var(--accent-strong);
  cursor: pointer;
}
.field-error {
  font-size: 0.75rem;
  color: var(--color-unsafe, #dc2626);
  margin: 0.25rem 0 0;
}
</style>
