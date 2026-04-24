<script setup lang="ts">
import { onMounted, ref } from 'vue';
import type { User } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';
import { useAuthStore } from '../stores/auth';
import UserForm from './modals/UserForm.vue';

const api = useApiClient();
const auth = useAuthStore();

const items = ref<User[]>([]);
const loading = ref(false);
const formOpen = ref(false);
const err = ref('');
const actionErr = ref('');
const tempCred = ref<{ intro: string; password: string } | null>(null);

async function load() {
  loading.value = true;
  err.value = '';
  try { items.value = await api.get().listUsers(); }
  catch (e) { err.value = String(e); }
  finally { loading.value = false; }
}
onMounted(load);

function selfID(): string | null {
  return auth.claims?.sub ?? null;
}

async function onSubmit(payload: { name: string; email: string }) {
  actionErr.value = '';
  tempCred.value = null;
  try {
    const resp = await api.get().createUser(payload);
    formOpen.value = false;
    await load();
    if (resp.emailSent) {
      tempCred.value = { intro: `Invite email sent to ${resp.user.email}.`, password: '' };
    } else {
      tempCred.value = {
        intro: `User created. Share this temp password with ${resp.user.email} — shown once:`,
        password: resp.tempPassword,
      };
    }
  } catch (e) {
    actionErr.value = 'Create failed: ' + String(e);
  }
}

async function onDelete(u: User) {
  if (u.id === selfID()) { actionErr.value = "Can't delete your own account"; return; }
  if (!confirm(`Delete ${u.email}?`)) return;
  actionErr.value = '';
  tempCred.value = null;
  try {
    await api.get().deleteUser(u.id);
    items.value = items.value.filter((x) => x.id !== u.id);
  } catch (e) {
    actionErr.value = 'Delete failed: ' + String(e);
  }
}

async function onResend(u: User) {
  actionErr.value = '';
  tempCred.value = null;
  try {
    const resp = await api.get().resendInvite(u.id);
    if (resp.emailSent) {
      tempCred.value = { intro: `Invite resent to ${u.email}.`, password: '' };
    } else {
      tempCred.value = {
        intro: `New temp password for ${u.email} — shown once:`,
        password: resp.tempPassword,
      };
    }
  } catch (e) {
    actionErr.value = 'Resend failed: ' + String(e);
  }
}
</script>

<template>
  <div class="users-page">
    <div class="page-header">
      <h1>Users</h1>
      <button class="btn-primary" @click="formOpen = true">New user</button>
    </div>

    <div v-if="actionErr" class="action-err">{{ actionErr }}</div>

    <div v-if="tempCred" class="temp-cred">
      <p class="small">{{ tempCred.intro }}</p>
      <code v-if="tempCred.password" class="temp">{{ tempCred.password }}</code>
      <button class="dismiss" @click="tempCred = null">Dismiss</button>
    </div>

    <div v-if="loading" class="muted">Loading…</div>
    <div v-else-if="err" class="err">{{ err }}</div>
    <div v-else-if="items.length === 0" class="muted">No users yet.</div>
    <table v-else class="table">
      <thead>
        <tr>
          <th>Email</th><th>Name</th><th>Created</th><th>Status</th><th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="u in items" :key="u.id">
          <td>{{ u.email }}</td>
          <td>{{ u.name }}</td>
          <td>{{ u.createdAt.slice(0, 10) }}</td>
          <td>
            <span :class="u.mustChangePassword ? 'pill warn' : 'pill ok'">
              {{ u.mustChangePassword ? 'Pending change' : 'Active' }}
            </span>
          </td>
          <td class="actions">
            <button @click="onResend(u)">Resend invite</button>
            <button :disabled="u.id === selfID()" @click="onDelete(u)">Delete</button>
          </td>
        </tr>
      </tbody>
    </table>

    <UserForm
      :open="formOpen"
      @close="formOpen = false"
      @submit="onSubmit"
    />
  </div>
</template>

<style scoped>
.users-page { padding: var(--space-4); }
.page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-4); }
.table { width: 100%; border-collapse: collapse; }
.table th, .table td { padding: var(--space-2) var(--space-3); text-align: left; border-bottom: 1px solid var(--border); }
.actions { display: flex; gap: var(--space-2); justify-content: flex-end; }
.pill { font-size: 0.72rem; padding: 2px 8px; border-radius: 999px; }
.pill.ok { background: var(--safe-soft); color: var(--safe); }
.pill.warn { background: var(--warn-soft); color: var(--warn); }
.muted { color: var(--text-muted); }
.err { color: var(--unsafe); }
.action-err { color: var(--unsafe); margin-bottom: var(--space-3); }
.btn-primary { background: var(--accent); color: white; padding: var(--space-2) var(--space-3); border: none; border-radius: var(--radius-sm); cursor: pointer; }
.temp-cred {
  margin-bottom: var(--space-4);
  padding: var(--space-3);
  background: var(--bg-elevated);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}
.temp {
  display: block;
  padding: var(--space-2);
  background: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: 0.88rem;
  word-break: break-all;
}
.small { font-size: 0.78rem; color: var(--text-muted); margin: 0; }
.dismiss {
  align-self: flex-start;
  background: none;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  padding: 2px 10px;
  font-size: 0.78rem;
  cursor: pointer;
  color: var(--text-muted);
}
</style>
