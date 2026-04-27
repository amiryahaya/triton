<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TButton, TDataTable, TConfirmDialog, useToast, type Column } from '@triton/ui';
import type { Credential } from '@triton/api-client';
import { useCredentialsStore } from '../stores/credentials';
import CredentialForm from './modals/CredentialForm.vue';

const store = useCredentialsStore();
const toast = useToast();
const formOpen = ref(false);
const confirmOpen = ref(false);
const pendingDeleteId = ref<string | null>(null);

onMounted(() => store.fetch());

const authTypeLabel: Record<string, string> = {
  'ssh-key': 'SSH Key',
  'ssh-password': 'SSH Password',
  'winrm-password': 'WinRM Password',
};

const columns: Column<Credential>[] = [
  { key: 'name', label: 'Name' },
  { key: 'auth_type', label: 'Type' },
  { key: 'in_use_count', label: 'Hosts', width: '80px', align: 'right' },
  { key: 'created_at', label: 'Created' },
  { key: 'id', label: '', width: '120px', align: 'right' },
];

function remove(id: string, inUseCount: number) {
  if (inUseCount > 0) {
    toast.error({
      title: 'Credential in use',
      description: `Unassign from all ${inUseCount} host(s) before deleting.`,
    });
    return;
  }
  pendingDeleteId.value = id;
  confirmOpen.value = true;
}

async function onConfirmDelete() {
  const id = pendingDeleteId.value;
  if (!id) return;
  try {
    await store.remove(id);
    toast.success({ title: 'Deleted' });
  } catch (e) {
    toast.error({ title: 'Delete failed', description: String(e) });
  } finally {
    confirmOpen.value = false;
    pendingDeleteId.value = null;
  }
}
</script>

<template>
  <section class="credentials-view">
    <header class="credentials-head">
      <div>
        <h1>Credentials</h1>
        <p class="credentials-sub">SSH keys and passwords stored in the server-side Vault.</p>
      </div>
      <TButton variant="primary" size="sm" @click="formOpen = true">
        + Add Credential
      </TButton>
    </header>

    <TDataTable
      :columns="columns"
      :rows="store.items"
      row-key="id"
      :empty-text="store.loading ? 'Loading…' : 'No credentials yet.'"
    >
      <template #[`cell:auth_type`]="{ row }">
        <span class="auth-badge">{{ authTypeLabel[row.auth_type] ?? row.auth_type }}</span>
      </template>
      <template #[`cell:created_at`]="{ row }">
        {{ new Date(row.created_at).toLocaleDateString() }}
      </template>
      <template #[`cell:id`]="{ row }">
        <TButton
          variant="danger"
          size="sm"
          @click="remove(row.id, row.in_use_count)"
        >
          Delete
        </TButton>
      </template>
    </TDataTable>

    <CredentialForm v-if="formOpen" @close="formOpen = false" @saved="formOpen = false; store.fetch()" />

    <TConfirmDialog
      :open="confirmOpen"
      title="Delete credential?"
      message="This will permanently remove the credential from the Vault. This cannot be undone."
      confirm-label="Delete"
      variant="danger"
      @confirm="onConfirmDelete"
      @cancel="confirmOpen = false; pendingDeleteId = null"
    />
  </section>
</template>

<style scoped>
.credentials-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.credentials-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.credentials-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.credentials-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.auth-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: var(--radius-full, 9999px);
  font-size: 0.72rem;
  font-weight: 500;
  background: var(--accent-muted, #e0e7ff);
  color: var(--accent, #4f46e5);
  white-space: nowrap;
}
</style>
