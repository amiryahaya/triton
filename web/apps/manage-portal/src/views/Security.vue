<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import {
  TDataTable,
  TButton,
  TConfirmDialog,
  useToast,
  type Column,
} from '@triton/ui';
import { useSecurityStore } from '../stores/security';
import type { Lockout } from '@triton/api-client';

interface LockoutRow {
  email: string;
  ip: string;
  failures: number;
  first_failure: string;
  last_failure: string;
  locked_until: string;
  _key: string;
  [key: string]: unknown;
}

const security = useSecurityStore();
const toast = useToast();

const confirmOpen = ref(false);
const pendingUnlock = ref<Lockout | null>(null);

// Pre-map to add a composite row key — TDataTable requires keyof T & string.
const rows = computed<LockoutRow[]>(() =>
  security.items.map((l) => ({ ...l, _key: `${l.email}|${l.ip}` }))
);

const columns: Column<LockoutRow>[] = [
  { key: 'email',         label: 'Email' },
  { key: 'ip',            label: 'IP' },
  { key: 'failures',      label: 'Failures' },
  { key: 'first_failure', label: 'First failure' },
  { key: 'locked_until',  label: 'Locked until' },
  { key: '_key',          label: '', width: '120px', align: 'right' },
];

onMounted(() => {
  void security.fetch();
});

function askUnlock(row: Record<string, unknown>) {
  // row is always LockoutRow from the computed rows array; cast to Lockout for state
  pendingUnlock.value = row as unknown as Lockout;
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
      :rows="rows"
      row-key="_key"
      :empty-text="security.loading ? 'Loading…' : 'No active lockouts.'"
    >
      <template #[`cell:first_failure`]="{ row }">
        {{ new Date(String(row.first_failure)).toLocaleString() }}
      </template>
      <template #[`cell:locked_until`]="{ row }">
        {{ new Date(String(row.locked_until)).toLocaleString() }}
      </template>
      <template #[`cell:_key`]="{ row }">
        <TButton
          variant="danger"
          size="sm"
          :data-test="`unlock-${String(row._key)}`"
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
