<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import {
  TDataTable, TPanel, TPill, TButton, useToast,
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
      api.get().licences(),
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

function onRowClick(row: Record<string, unknown>) {
  window.location.hash = `#/licenses/${String(row.id)}`;
}

async function onSubmit(payload: CreateLicenceRequest) {
  try {
    const created = await api.get().createLicence(payload);
    items.value.push(created);
    formOpen.value = false;
    toast.success({ title: 'Licence created' });
  } catch (err) {
    toast.error({ title: 'Create failed', description: String(err) });
  }
}
</script>

<template>
  <TPanel
    title="Licences"
    :subtitle="items.length ? `· ${items.length} total` : ''"
  >
    <template #action>
      <TButton
        variant="primary"
        size="sm"
        @click="formOpen = true"
      >New licence</TButton>
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
</template>
