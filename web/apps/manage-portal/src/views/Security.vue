<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  TDataTable,
  TButton,
  TConfirmDialog,
  useToast,
  type Column,
} from '@triton/ui';
import { useSecurityStore } from '../stores/security';
import type { Lockout } from '@triton/api-client';

const security = useSecurityStore();
const toast = useToast();

const confirmOpen = ref(false);
const pendingUnlock = ref<Lockout | null>(null);

const columns: Column<Lockout>[] = [
  { key: 'email',         label: 'Email' },
  { key: 'ip',            label: 'IP' },
  { key: 'failures',      label: 'Failures' },
  { key: 'first_failure', label: 'First failure' },
  { key: 'locked_until',  label: 'Locked until' },
  { key: 'last_failure',  label: '', width: '120px', align: 'right' },
];

onMounted(() => {
  void security.fetch();
});

function askUnlock(l: Lockout) {
  pendingUnlock.value = l;
  confirmOpen.value = true;
}

async function onConfirmUnlock() {
  const l = pendingUnlock.value;
  if (!l) return;
  try {
    await security.remove(l.email, l.ip);
    toast.success({ title: 'Unlocked', description: l.email });
  } catch (e) {
    toast.error({ title: 'Unlock failed', description: String(e) });
  } finally {
    confirmOpen.value = false;
    pendingUnlock.value = null;
  }
}
</script>

<template>
  <section class="security-view">
    <header class="security-head">
      <div>
        <h1>Security Events</h1>
        <p class="security-sub">Active login lockouts. Unlock an account to restore access immediately.</p>
      </div>
      <TButton variant="ghost" size="sm" @click="void security.fetch()">Refresh</TButton>
    </header>

    <TDataTable
      :columns="columns"
      :rows="security.items"
      row-key="email"
      :empty-text="security.loading ? 'Loading…' : 'No active lockouts.'"
    >
      <template #[`cell:first_failure`]="{ row }">
        {{ new Date(row.first_failure).toLocaleString() }}
      </template>
      <template #[`cell:locked_until`]="{ row }">
        {{ new Date(row.locked_until).toLocaleString() }}
      </template>
      <template #[`cell:last_failure`]="{ row }">
        <TButton
          variant="danger"
          size="sm"
          :data-test="`unlock-${row.email}|${row.ip}`"
          @click="askUnlock(row)"
        >
          Unlock
        </TButton>
      </template>
    </TDataTable>

    <TConfirmDialog
      :open="confirmOpen"
      title="Unlock account?"
      :message="pendingUnlock
        ? `Unlock ${pendingUnlock.email} from IP ${pendingUnlock.ip}? They'll be able to log in again immediately.`
        : ''"
      confirm-label="Unlock"
      variant="primary"
      data-test="confirm-dialog"
      @confirm="onConfirmUnlock"
      @cancel="confirmOpen = false; pendingUnlock = null"
    />
  </section>
</template>

<style scoped>
.security-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.security-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.security-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.security-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
</style>
