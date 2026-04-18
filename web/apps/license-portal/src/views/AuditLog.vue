<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TDataTable, TPanel, TPill, type Column } from '@triton/ui';
import type { AuditEntry, Paged } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const data = ref<Paged<AuditEntry> | null>(null);

const columns: Column<AuditEntry>[] = [
  { key: 'kind',      label: 'Kind',  width: '100px' },
  { key: 'subject',   label: 'Event', width: '2fr' },
  { key: 'actor',     label: 'Actor', width: '1fr' },
  { key: 'createdAt', label: 'When',  width: '1fr' },
];

function pill(k: AuditEntry['kind']) {
  return k === 'success' ? 'safe' : k === 'warn' ? 'warn' : k === 'error' ? 'unsafe' : 'info';
}

onMounted(async () => {
  data.value = await api.get().audit(1);
});
</script>

<template>
  <TPanel
    title="Audit log"
    :subtitle="data ? `· ${data.total} events` : ''"
  >
    <TDataTable
      :columns="columns"
      :rows="data?.rows ?? []"
      row-key="id"
    >
      <template #cell:kind="{ row }">
        <TPill :variant="pill((row as AuditEntry).kind)">
          {{ (row as AuditEntry).kind }}
        </TPill>
      </template>
    </TDataTable>
  </TPanel>
</template>
