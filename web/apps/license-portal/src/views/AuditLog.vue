<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  TDataTable, TPanel, TPill, useToast, type Column, type PillVariant,
} from '@triton/ui';
import type { AuditEntry } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const items = ref<AuditEntry[]>([]);

interface AuditRow {
  id: number;
  timestamp: string;
  eventType: string;
  actor: string;
  ipAddress: string;
  targets: string;
  [key: string]: unknown;
}

const columns: Column<AuditRow>[] = [
  { key: 'timestamp', label: 'When', width: '1.2fr' },
  { key: 'eventType', label: 'Event', width: '1fr' },
  { key: 'actor', label: 'Actor', width: '1fr' },
  { key: 'targets', label: 'Targets', width: '1.5fr' },
  { key: 'ipAddress', label: 'IP', width: '1fr' },
];

const rows = ref<AuditRow[]>([]);

function eventVariant(ev: string): PillVariant {
  if (ev.startsWith('activate')) return 'info';
  if (ev.startsWith('deactivate')) return 'warn';
  if (ev.startsWith('create')) return 'safe';
  if (ev.startsWith('revoke')) return 'unsafe';
  return 'neutral';
}

function targetsOf(e: AuditEntry): string {
  const parts: string[] = [];
  if (e.licenseID) parts.push(`L:${e.licenseID.slice(0, 8)}`);
  if (e.orgID) parts.push(`O:${e.orgID.slice(0, 8)}`);
  if (e.machineID) parts.push(`M:${e.machineID.slice(0, 8)}`);
  return parts.join(' · ') || '—';
}

onMounted(async () => {
  try {
    items.value = await api.get().audit(1);
    rows.value = items.value.map((e) => ({
      id: e.id,
      timestamp: e.timestamp,
      eventType: e.eventType,
      actor: e.actor,
      ipAddress: e.ipAddress,
      targets: targetsOf(e),
    }));
  } catch (err) {
    toast.error({ title: 'Failed to load audit log', description: String(err) });
  }
});
</script>

<template>
  <TPanel
    title="Audit log"
    :subtitle="items.length ? `· ${items.length} events` : ''"
  >
    <TDataTable
      :columns="columns"
      :rows="rows"
      row-key="id"
      empty-text="No audit events."
    >
      <template #[`cell:eventType`]="{ row }">
        <TPill :variant="eventVariant(String(row.eventType))">
          {{ String(row.eventType) }}
        </TPill>
      </template>
    </TDataTable>
  </TPanel>
</template>
