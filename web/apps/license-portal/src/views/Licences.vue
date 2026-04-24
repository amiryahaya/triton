<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import {
  TDataTable, TPanel, TPill, TButton, TSelect, TStatCard, useToast,
  type Column, type PillVariant,
} from '@triton/ui';
import type {
  Licence, Organisation, CreateLicenceRequest,
} from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';
import LicenceForm from './modals/LicenceForm.vue';

const api = useApiClient();
const toast = useToast();

const items = ref<Licence[]>([]);
const orgs = ref<Organisation[]>([]);
const loading = ref(false);
const formOpen = ref(false);
const orgFilter = ref<string>('');

interface LicRow {
  id: string;
  orgName: string;
  tier: string;
  seatsText: string;
  scansCap: string;
  scope: string;
  expiresAt: string;
  status: 'Active' | 'Revoked' | 'Expired';
  [key: string]: unknown;
}

const columns: Column<LicRow>[] = [
  { key: 'orgName', label: 'Organisation', width: '1.5fr' },
  { key: 'tier', label: 'Tier', width: '0.6fr' },
  { key: 'seatsText', label: 'Seats', width: '0.8fr' },
  { key: 'scansCap', label: 'Scans cap', width: '0.8fr' },
  { key: 'scope', label: 'Scope', width: '0.8fr' },
  { key: 'expiresAt', label: 'Expires', width: '1fr' },
  { key: 'status', label: 'Status', width: '100px' },
];

function scansCapOf(l: Licence): string {
  const entry = l.limits.find((x) => x.metric === 'scans');
  if (!entry || entry.cap === 0) return '—';
  return String(entry.cap);
}

function scansCapNum(l: Licence): number {
  const entry = l.limits.find((x) => x.metric === 'scans');
  return entry?.cap ?? 0;
}

function statusOf(l: Licence): LicRow['status'] {
  if (l.revoked) return 'Revoked';
  if (new Date(l.expiresAt).getTime() < Date.now()) return 'Expired';
  return 'Active';
}

const rows = computed<LicRow[]>(() =>
  items.value.map((l) => ({
    id: l.id,
    orgName: l.orgName || l.orgID.slice(0, 8),
    tier: l.tier,
    seatsText: `${l.seatsUsed} / ${l.seats === 0 ? '∞' : l.seats}`,
    scansCap: scansCapOf(l),
    scope: l.product_scope,
    expiresAt: l.expiresAt,
    status: statusOf(l),
  })),
);

// Stats computed from the (already loaded) licence list — no extra
// round-trip. If the list grows past 1000 rows we'd need a backend
// stats endpoint, but LIMIT 1000 handles the near-term.
const stats = computed(() => {
  let free = 0, pro = 0, enterprise = 0;
  let seats = 0;
  let scans = 0;
  for (const l of items.value) {
    if (l.tier === 'free') free += 1;
    else if (l.tier === 'pro') pro += 1;
    else if (l.tier === 'enterprise') enterprise += 1;
    seats += l.seats;
    scans += scansCapNum(l);
  }
  return { total: items.value.length, free, pro, enterprise, seats, scans };
});

function tierVariant(t: string): PillVariant {
  return t === 'enterprise' ? 'enterprise' : t === 'pro' ? 'info' : 'neutral';
}

function statusVariant(s: LicRow['status']): PillVariant {
  if (s === 'Active') return 'safe';
  if (s === 'Revoked') return 'unsafe';
  return 'warn';
}

async function load() {
  loading.value = true;
  try {
    const [ls, os] = await Promise.all([
      api.get().licences(orgFilter.value ? { org: orgFilter.value } : undefined),
      api.get().orgs(),
    ]);
    items.value = ls;
    orgs.value = os;
  } catch (err) {
    toast.error({ title: 'Load failed', description: String(err) });
  } finally {
    loading.value = false;
  }
}

onMounted(load);

// Refetch when the org filter changes.
watch(orgFilter, load);

function onRowClick(row: Record<string, unknown>) {
  window.location.hash = `#/licenses/${String(row.id)}`;
}

async function onSubmit(payload: CreateLicenceRequest) {
  try {
    await api.get().createLicence(payload);
    // Refetch the list instead of patching state by hand. Gets:
    //   - correct ordering (backend sorts created_at DESC)
    //   - orgName populated via the JOIN in the list endpoint
    //     (POST response omits it)
    // Worth the extra round-trip since licence creation is rare.
    await load();
    formOpen.value = false;
    toast.success({ title: 'Licence created' });
  } catch (err) {
    toast.error({ title: 'Create failed', description: String(err) });
  }
}

function fmt(n: number): string {
  return n === 0 ? '0' : n.toLocaleString();
}
</script>

<template>
  <section class="view">
    <div class="stats">
      <TStatCard
        label="Licences"
        :value="stats.total"
        accent="var(--accent)"
      />
      <TStatCard
        label="Free"
        :value="stats.free"
      />
      <TStatCard
        label="Pro"
        :value="stats.pro"
        accent="var(--accent-strong)"
      />
      <TStatCard
        label="Enterprise"
        :value="stats.enterprise"
        accent="var(--violet)"
      />
      <TStatCard
        label="Seats total"
        :value="fmt(stats.seats)"
      />
      <TStatCard
        label="Scans cap total"
        :value="fmt(stats.scans)"
      />
    </div>

    <TPanel
      title="Licences"
      :subtitle="items.length ? `· ${items.length} shown` : ''"
    >
      <template #action>
        <div class="head-actions">
          <TSelect v-model="orgFilter">
            <option value="">All organisations</option>
            <option
              v-for="o in orgs"
              :key="o.id"
              :value="o.id"
            >{{ o.name }}</option>
          </TSelect>
          <TButton
            variant="primary"
            size="sm"
            @click="formOpen = true"
          >New licence</TButton>
        </div>
      </template>

      <TDataTable
        :columns="columns"
        :rows="rows"
        row-key="id"
        :empty-text="loading ? 'Loading…' : 'No licences yet.'"
        @row-click="onRowClick"
      >
        <template #[`cell:tier`]="{ row }">
          <TPill :variant="tierVariant(String(row.tier))" :dot="false">
            {{ String(row.tier) }}
          </TPill>
        </template>
        <template #[`cell:scope`]="{ row }">
          <TPill :variant="String(row.scope) === 'legacy' ? 'neutral' : 'info'" :dot="false">
            {{ String(row.scope) }}
          </TPill>
        </template>
        <template #[`cell:status`]="{ row }">
          <TPill :variant="statusVariant(row.status as LicRow['status'])">
            {{ String(row.status) }}
          </TPill>
        </template>
      </TDataTable>
    </TPanel>

    <LicenceForm
      :open="formOpen"
      :orgs="orgs"
      @close="formOpen = false"
      @submit="onSubmit"
    />
  </section>
</template>

<style scoped>
.view {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.stats {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: var(--space-2);
}
.head-actions {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  min-width: 320px;
}
</style>
