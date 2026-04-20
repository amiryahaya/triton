<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import {
  TButton,
  TDataTable,
  TConfirmDialog,
  TPill,
  useToast,
  type Column,
  type PillVariant,
} from '@triton/ui';
import type { Agent, AgentStatus } from '@triton/api-client';
import { useAgentsStore } from '../stores/agents';
import { useZonesStore } from '../stores/zones';
import AgentEnrolForm from './modals/AgentEnrolForm.vue';

const agents = useAgentsStore();
const zones = useZonesStore();
const toast = useToast();

const enrolOpen = ref(false);
const confirmOpen = ref(false);
const pendingRevoke = ref<Agent | null>(null);

const columns: Column<Agent>[] = [
  { key: 'name', label: 'Name' },
  { key: 'zone_id', label: 'Zone' },
  { key: 'status', label: 'Status' },
  { key: 'cert_expires_at', label: 'Cert expires' },
  { key: 'last_seen_at', label: 'Last seen' },
  { key: 'id', label: '', width: '140px', align: 'right' },
];

// Map backend AgentStatus to a TPill variant. TPill ships these variants:
// safe | warn | deprecated | unsafe | info | neutral | enterprise. We
// use the closest semantic match — active = safe, pending = warn,
// revoked = unsafe.
const statusVariant: Record<AgentStatus, PillVariant> = {
  active: 'safe',
  pending: 'warn',
  revoked: 'unsafe',
};

const zoneNameByID = computed(() => {
  const m = new Map<string, string>();
  for (const z of zones.items) m.set(z.id, z.name);
  return m;
});

onMounted(async () => {
  await Promise.all([zones.fetch(), agents.fetch()]);
});

function askRevoke(a: Agent) {
  pendingRevoke.value = a;
  confirmOpen.value = true;
}

async function onEnrolSubmit(payload: { name: string; zone_id?: string }) {
  try {
    const filename = await agents.enrol(payload);
    toast.success({
      title: 'Agent enrolled',
      description: `Bundle saved as ${filename}. Store it somewhere safe.`,
    });
    enrolOpen.value = false;
  } catch (e) {
    toast.error({ title: 'Enrol failed', description: String(e) });
  }
}

async function onConfirmRevoke() {
  const a = pendingRevoke.value;
  if (!a) return;
  try {
    await agents.revoke(a.id);
    toast.success({ title: 'Agent revoked', description: a.name });
  } catch (e) {
    toast.error({ title: 'Revoke failed', description: String(e) });
  } finally {
    confirmOpen.value = false;
    pendingRevoke.value = null;
  }
}
</script>

<template>
  <section class="agents-view">
    <header class="agents-head">
      <div>
        <h1>Agents</h1>
        <p class="agents-sub">Remote scan workers enrolled with mTLS certificates.</p>
      </div>
      <TButton
        variant="primary"
        size="sm"
        @click="enrolOpen = true"
      >
        Enrol agent
      </TButton>
    </header>

    <TDataTable
      :columns="columns"
      :rows="agents.items"
      row-key="id"
      :empty-text="agents.loading ? 'Loading…' : 'No agents enrolled yet.'"
    >
      <template #[`cell:zone_id`]="{ row }">
        {{ row.zone_id ? (zoneNameByID.get(row.zone_id) ?? row.zone_id) : '—' }}
      </template>
      <template #[`cell:status`]="{ row }">
        <TPill :variant="statusVariant[row.status]">
          {{ row.status }}
        </TPill>
      </template>
      <template #[`cell:id`]="{ row }">
        <div class="agents-actions">
          <TButton
            v-if="row.status !== 'revoked'"
            variant="danger"
            size="sm"
            @click="askRevoke(row)"
          >
            Revoke
          </TButton>
        </div>
      </template>
    </TDataTable>

    <AgentEnrolForm
      :open="enrolOpen"
      :zones="zones.items"
      @close="enrolOpen = false"
      @submit="onEnrolSubmit"
    />

    <TConfirmDialog
      :open="confirmOpen"
      title="Revoke agent?"
      :message="pendingRevoke ? `Revoke ${pendingRevoke.name}? The agent will no longer be able to authenticate.` : ''"
      confirm-label="Revoke"
      variant="danger"
      @confirm="onConfirmRevoke"
      @cancel="confirmOpen = false; pendingRevoke = null"
    />
  </section>
</template>

<style scoped>
.agents-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.agents-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.agents-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.agents-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.agents-actions {
  display: flex;
  gap: var(--space-2);
  justify-content: flex-end;
  width: 100%;
}
</style>
