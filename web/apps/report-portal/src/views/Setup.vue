<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { useApiClient } from '../stores/apiClient';

const router = useRouter();
const api = useApiClient();

const name = ref('');
const email = ref('');
const error = ref('');
const busy = ref(false);
const done = ref(false);
const tempPassword = ref('');

async function submit() {
  if (!name.value || !email.value) {
    error.value = 'Name and email are required.';
    return;
  }
  busy.value = true;
  error.value = '';
  try {
    const resp = await api.get().firstSetup({ name: name.value, email: email.value });
    tempPassword.value = resp.tempPassword;
    done.value = true;
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Setup failed';
  } finally {
    busy.value = false;
  }
}

function goToLogin() {
  void router.replace('/');
}
</script>

<template>
  <div class="setup-page">
    <h1>First-time Setup</h1>

    <div v-if="!done">
      <p>Create the initial platform administrator account.</p>
      <form @submit.prevent="submit">
        <label>
          Name
          <input v-model="name" type="text" name="name" required autocomplete="name" />
        </label>
        <label>
          Email
          <input v-model="email" type="email" name="email" required autocomplete="email" />
        </label>
        <p v-if="error" class="error">{{ error }}</p>
        <button type="submit" :disabled="busy">
          {{ busy ? 'Creating…' : 'Create admin' }}
        </button>
      </form>
    </div>

    <div v-else class="success">
      <h2>Admin created</h2>
      <p>Temporary password (shown once):</p>
      <code>{{ tempPassword }}</code>
      <p>Sign in with this password and change it immediately.</p>
      <button @click="goToLogin">Go to sign-in</button>
    </div>
  </div>
</template>

<style scoped>
.setup-page {
  max-width: 420px;
  margin: 10vh auto;
  padding: var(--space-6);
}
form { display: flex; flex-direction: column; gap: var(--space-3); }
label { display: flex; flex-direction: column; gap: var(--space-1); font-size: 0.875rem; }
input { padding: var(--space-2); border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--bg-input); color: var(--text-primary); }
.error { color: var(--color-danger); font-size: 0.8rem; }
.success { display: flex; flex-direction: column; gap: var(--space-3); }
code { background: var(--bg-subtle); padding: var(--space-2) var(--space-3); border-radius: var(--radius-sm); font-size: 1.1rem; word-break: break-all; }
</style>
