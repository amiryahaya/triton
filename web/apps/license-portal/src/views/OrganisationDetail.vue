<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import {
  TPanel, TDataTable, TPill, TButton, useToast, type Column, type PillVariant,
} from '@triton/ui';
import type { Organisation, Licence } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const route = useRoute();
const id = computed(() => String(route.params.id));

const org = ref<Organisation | null>(null);
const licences = ref<Licence[]>([]);

type LicenceStatus = 'Active' | 'Revoked' | 'Expired';

interface LicenceRow {
  id: string;
  tier: string;
  seats: number;
  seatsUsed: number;
  expiresAt: string;
  status: LicenceStatus;
  [key: string]: unknown;
}

const licColumns: Column<LicenceRow>[] = [
  { key: 'id', label: 'Licence ID', width: '2fr' },
  { key: 'tier', label: 'Tier', width: '0.8fr' },
  { key: 'seats', label: 'Seats', width: '0.8fr' },
  { key: 'expiresAt', label: 'Expires', width: '1fr' },
  { key: 'status', label: 'Status', width: '100px' },
];

function statusOf(l: Licence): LicenceStatus {
  if (l.revoked) return 'Revoked';
  if (new Date(l.expiresAt).getTime() < Date.now()) return 'Expired';
  return 'Active';
}

function statusVariant(s: LicenceStatus): PillVariant {
  if (s === 'Active') return 'safe';
  if (s === 'Revoked') return 'unsafe';
  return 'warn';
}

const licRows = computed<LicenceRow[]>(() =>
  licences.value.map((l) => ({
    id: l.id,
    tier: l.tier,
    seats: l.seats,
    seatsUsed: l.seatsUsed,
    expiresAt: l.expiresAt,
    status: statusOf(l),
  })),
);

onMounted(async () => {
  try {
    const [o, allLicences] = await Promise.all([
      api.get().org(id.value),
      api.get().licences(),
    ]);
    org.value = o;
    licences.value = allLicences.filter((l) => l.orgID === id.value);
  } catch (err) {
    toast.error({ title: 'Load failed', description: String(err) });
  }
});

function onLicenceClick(row: Record<string, unknown>) {
  window.location.hash = `#/licenses/${String(row.id)}`;
}

async function toggleSuspend() {
  if (!org.value) return;
  const next = !org.value.suspended;
  try {
    await api.get().suspendOrg(org.value.id, next);
    org.value = { ...org.value, suspended: next };
    toast.success({ title: next ? 'Organisation suspended' : 'Organisation unsuspended' });
  } catch (err) {
    toast.error({ title: 'Action failed', description: String(err) });
  }
}
</script>

<template>
  <div
    v-if="org"
    class="view"
  >
    <TPanel :title="org.name">
      <template #action>
        <TButton
          variant="secondary"
          size="sm"
          data-test="org-detail-suspend"
          @click="toggleSuspend"
        >
          {{ org.suspended ? 'Unsuspend' : 'Suspend' }}
        </TButton>
      </template>
      <dl class="kv">
        <dt>ID</dt><dd class="mono">{{ org.id }}</dd>
        <dt>Contact</dt><dd>{{ org.contact || '—' }}</dd>
        <dt>Notes</dt><dd>{{ org.notes || '—' }}</dd>
        <dt>Status</dt>
        <dd>
          <TPill :variant="org.suspended ? 'unsafe' : 'safe'">
            {{ org.suspended ? 'Suspended' : 'Active' }}
          </TPill>
        </dd>
        <dt>Created</dt><dd>{{ org.createdAt }}</dd>
        <dt>Updated</dt><dd>{{ org.updatedAt }}</dd>
      </dl>
    </TPanel>

    <TPanel
      title="Licences"
      :subtitle="`· ${licRows.length} issued`"
    >
      <TDataTable
        :columns="licColumns"
        :rows="licRows"
        row-key="id"
        empty-text="No licences for this organisation."
        @row-click="onLicenceClick"
      >
        <template #[`cell:seats`]="{ row }">
          {{ row.seatsUsed }} / {{ row.seats === 0 ? '∞' : row.seats }}
        </template>
        <template #[`cell:status`]="{ row }">
          <TPill :variant="statusVariant(row.status as LicenceStatus)">
            {{ String(row.status) }}
          </TPill>
        </template>
      </TDataTable>
    </TPanel>
  </div>
  <p v-else>Loading…</p>
</template>

<style scoped>
.view { display: flex; flex-direction: column; gap: var(--space-3); }
.kv {
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: var(--space-2) var(--space-3);
  font-size: 0.82rem;
}
.kv dt {
  color: var(--text-muted);
  font-size: 0.66rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
.kv dd { margin: 0; color: var(--text-primary); }
.mono { font-family: var(--font-mono); }
</style>
