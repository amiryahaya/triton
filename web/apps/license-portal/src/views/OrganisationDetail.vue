<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import {
  TPanel, TDataTable, TPill, useToast, type Column,
} from '@triton/ui';
import type { Organisation, Licence } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const route = useRoute();
const id = computed(() => String(route.params.id));

const org = ref<Organisation | null>(null);
const licences = ref<Licence[]>([]);

interface LicenceRow {
  id: string;
  tier: string;
  seats: number;
  seatsUsed: number;
  expiresAt: string;
  revoked: boolean;
  [key: string]: unknown;
}

const licColumns: Column<LicenceRow>[] = [
  { key: 'id', label: 'Licence ID', width: '2fr' },
  { key: 'tier', label: 'Tier', width: '0.8fr' },
  { key: 'seats', label: 'Seats', width: '0.8fr' },
  { key: 'expiresAt', label: 'Expires', width: '1fr' },
  { key: 'revoked', label: 'Status', width: '100px' },
];

const licRows = computed<LicenceRow[]>(() =>
  licences.value.map((l) => ({
    id: l.id,
    tier: l.tier,
    seats: l.seats,
    seatsUsed: l.seatsUsed,
    expiresAt: l.expiresAt,
    revoked: l.revoked,
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
</script>

<template>
  <div
    v-if="org"
    class="view"
  >
    <TPanel :title="org.name">
      <dl class="kv">
        <dt>ID</dt><dd class="mono">{{ org.id }}</dd>
        <dt>Contact</dt><dd>{{ org.contact || '—' }}</dd>
        <dt>Notes</dt><dd>{{ org.notes || '—' }}</dd>
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
        <template #[`cell:revoked`]="{ row }">
          <TPill :variant="row.revoked ? 'unsafe' : 'safe'">
            {{ row.revoked ? 'Revoked' : 'Active' }}
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
