<script setup lang="ts">
import { onMounted, ref, computed } from 'vue';
import { useRoute } from 'vue-router';
import {
  TStatCard,
  TPanel,
  TButton,
  TConfirmDialog,
  TPill,
  TDataTable,
  useToast,
  type Column,
} from '@triton/ui';
import type { Licence, Paged, Activation } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const route = useRoute();
const id = computed(() => String(route.params.id));

const licence = ref<Licence | null>(null);
const activations = ref<Paged<Activation> | null>(null);
const revokeOpen = ref(false);

const actColumns: Column<Activation>[] = [
  { key: 'machineFingerprint', label: 'Machine fingerprint', width: '2fr' },
  { key: 'boundBy',            label: 'Bound by',            width: '1fr' },
  { key: 'boundAt',            label: 'When',                width: '1fr' },
  { key: 'status',             label: 'Status',              width: '100px' },
];

async function load() {
  try {
    licence.value = await api.get().licence(id.value);
    activations.value = await api.get().activations(id.value);
  } catch (err) {
    toast.error({ title: 'Load failed', description: String(err) });
  }
}

onMounted(load);

async function revoke() {
  try {
    await api.get().revokeLicence(id.value);
    toast.success({ title: 'Licence revoked' });
    revokeOpen.value = false;
    await load();
  } catch (err) {
    toast.error({ title: 'Revoke failed', description: String(err) });
  }
}

async function copyKey() {
  if (!licence.value) return;
  await navigator.clipboard.writeText(licence.value.key);
  toast.success({ title: 'Key copied to clipboard' });
}

function statusVariant(s: Activation['status']) {
  return s === 'online' ? 'safe' : s === 'offline' ? 'unsafe' : 'warn';
}

function daysRemaining(expiresAt: string): number {
  return Math.max(
    0,
    Math.floor((new Date(expiresAt).getTime() - Date.now()) / 864e5)
  );
}
</script>

<template>
  <div
    v-if="licence"
    class="detail"
  >
    <section class="head">
      <div class="head-body">
        <div class="label">
          Licence key
        </div>
        <div class="key">
          {{ licence.key }}
        </div>
        <div class="meta">
          <span>Tier <b>{{ licence.tier }}</b></span>
          <span>Issued <b>{{ licence.issuedAt }}</b></span>
          <span>Expires <b>{{ licence.expiresAt }}</b></span>
          <span>Bound <b>{{ licence.bound ? 'Yes' : 'No' }}</b></span>
        </div>
      </div>
      <div class="actions">
        <TButton
          size="sm"
          variant="secondary"
          @click="copyKey"
        >
          Copy key
        </TButton>
        <TButton
          size="sm"
          variant="danger"
          :disabled="!!licence.revokedAt"
          @click="revokeOpen = true"
        >
          Revoke
        </TButton>
      </div>
    </section>

    <div class="stats">
      <TStatCard
        label="Seats used"
        :value="activations?.total ?? 0"
        accent="var(--violet)"
      />
      <TStatCard
        label="Tier"
        :value="licence.tier"
        accent="var(--accent)"
      />
      <TStatCard
        label="Days remaining"
        :value="daysRemaining(licence.expiresAt)"
        accent="var(--warn)"
      />
    </div>

    <TPanel
      title="Seat activations"
      :subtitle="`· ${activations?.total ?? 0} bound`"
    >
      <TDataTable
        :columns="actColumns"
        :rows="activations?.rows ?? []"
        row-key="id"
      >
        <template #cell:status="{ row }">
          <TPill :variant="statusVariant((row as Activation).status)">
            {{ (row as Activation).status }}
          </TPill>
        </template>
      </TDataTable>
    </TPanel>
  </div>

  <TConfirmDialog
    :open="revokeOpen"
    title="Revoke licence?"
    :message="`Revoking ${licence?.key ?? ''} will deactivate all seats. This can't be undone.`"
    confirm-label="Revoke"
    @confirm="revoke"
    @cancel="revokeOpen = false"
  />
</template>

<style scoped>
.detail {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.head {
  background: linear-gradient(
    135deg,
    color-mix(in srgb, var(--portal-accent) 14%, transparent),
    color-mix(in srgb, var(--accent-strong) 4%, transparent)
  );
  border: 1px solid color-mix(in srgb, var(--portal-accent) 30%, var(--border));
  border-radius: var(--radius-lg);
  padding: var(--space-4) var(--space-5);
  display: flex;
  gap: var(--space-4);
  align-items: flex-start;
}
.head-body {
  flex: 1;
}
.label {
  font-size: 0.62rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--portal-accent);
  font-weight: 500;
}
.key {
  font-family: var(--font-mono);
  font-size: 1rem;
  color: var(--text-primary);
  margin: 4px 0;
}
.meta {
  display: flex;
  gap: var(--space-4);
  margin-top: var(--space-2);
  font-size: 0.74rem;
  color: var(--text-muted);
}
.meta b {
  color: var(--text-primary);
  font-family: var(--font-display);
  font-weight: 500;
}
.actions {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}
.stats {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--space-2);
}
</style>
