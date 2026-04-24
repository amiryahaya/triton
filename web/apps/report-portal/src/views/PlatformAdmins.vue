<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useApiClient } from '../stores/apiClient';
import type { ReportUser } from '@triton/api-client';

const api = useApiClient();
const admins = ref<ReportUser[]>([]);
const loading = ref(true);
const error = ref('');

const showInvite = ref(false);
const inviteName = ref('');
const inviteEmail = ref('');
const inviteBusy = ref(false);
const inviteError = ref('');

onMounted(async () => {
  await load();
});

async function load() {
  loading.value = true;
  try {
    admins.value = await api.get().listPlatformAdmins();
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Failed to load admins';
  } finally {
    loading.value = false;
  }
}

async function invite() {
  inviteBusy.value = true;
  inviteError.value = '';
  try {
    await api.get().invitePlatformAdmin({ name: inviteName.value, email: inviteEmail.value });
    showInvite.value = false;
    inviteName.value = '';
    inviteEmail.value = '';
    await load();
  } catch (err) {
    inviteError.value = err instanceof Error ? err.message : 'Invite failed';
  } finally {
    inviteBusy.value = false;
  }
}

async function remove(id: string) {
  if (!confirm('Delete this admin?')) return;
  try {
    await api.get().deletePlatformAdmin(id);
    await load();
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Delete failed';
  }
}
</script>

<template>
  <div>
    <div class="header">
      <h1>Platform Admins</h1>
      <button @click="showInvite = true">Invite admin</button>
    </div>

    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="loading">Loading…</p>

    <table v-else>
      <thead>
        <tr>
          <th>Name</th>
          <th>Email</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="admin in admins" :key="admin.id">
          <td>{{ admin.name }}</td>
          <td>{{ admin.email }}</td>
          <td><button class="danger" @click="remove(admin.id)">Delete</button></td>
        </tr>
      </tbody>
    </table>

    <div v-if="showInvite" class="modal-overlay" @click.self="showInvite = false">
      <div class="modal">
        <h2>Invite Platform Admin</h2>
        <form @submit.prevent="invite">
          <label>Name<input v-model="inviteName" required /></label>
          <label>Email<input v-model="inviteEmail" type="email" required /></label>
          <p v-if="inviteError" class="error">{{ inviteError }}</p>
          <div class="actions">
            <button type="button" @click="showInvite = false">Cancel</button>
            <button type="submit" :disabled="inviteBusy">{{ inviteBusy ? 'Sending…' : 'Invite' }}</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<style scoped>
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: var(--space-4); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: var(--space-2) var(--space-3); border-bottom: 1px solid var(--border); }
.error { color: var(--color-danger); }
.modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.4); display: flex; align-items: center; justify-content: center; }
.modal { background: var(--bg-surface); padding: var(--space-6); border-radius: var(--radius); min-width: 340px; }
.modal form { display: flex; flex-direction: column; gap: var(--space-3); }
.modal label { display: flex; flex-direction: column; gap: var(--space-1); }
.actions { display: flex; gap: var(--space-2); justify-content: flex-end; }
button.danger { color: var(--color-danger); }
</style>
