<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { useApiClient } from '../stores/apiClient';
import { useAuthStore } from '../stores/auth';

const router = useRouter();
const api = useApiClient();
const auth = useAuthStore();

const current = ref('');
const next = ref('');
const error = ref('');
const busy = ref(false);

async function submit() {
  if (!current.value || !next.value) {
    error.value = 'Both fields are required.';
    return;
  }
  busy.value = true;
  error.value = '';
  try {
    const resp = await api.get().changePassword({ current: current.value, next: next.value });
    auth.setToken(resp.token);
    await router.replace('/');
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to change password';
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="change-pw-page">
    <h1>Change Password</h1>
    <p>You must change your password before continuing.</p>
    <form @submit.prevent="submit">
      <label>
        Current password
        <input v-model="current" type="password" name="current_password" required />
      </label>
      <label>
        New password
        <input v-model="next" type="password" name="new_password" required />
      </label>
      <p v-if="error" class="error">{{ error }}</p>
      <button type="submit" :disabled="busy">{{ busy ? 'Saving…' : 'Change password' }}</button>
    </form>
  </div>
</template>

<style scoped>
.change-pw-page { max-width: 400px; margin: 10vh auto; padding: var(--space-6); }
form { display: flex; flex-direction: column; gap: var(--space-3); }
label { display: flex; flex-direction: column; gap: var(--space-1); font-size: 0.875rem; }
input { padding: var(--space-2); border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--bg-input); color: var(--text-primary); }
.error { color: var(--color-danger); font-size: 0.8rem; }
</style>
