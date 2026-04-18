<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TDataTable, TPanel, TPill, type Column } from '@triton/ui';
import type { Licence, Paged } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const data = ref<Paged<Licence> | null>(null);

const columns: Column<Licence>[] = [
  { key: 'key',       label: 'Key',     width: '2fr' },
  { key: 'tier',      label: 'Tier',    width: '0.8fr' },
  { key: 'seats',     label: 'Seats',   width: '0.6fr', align: 'right', numeric: true },
  { key: 'expiresAt', label: 'Expires', width: '1fr' },
  { key: 'revokedAt', label: 'Status',  width: '0.8fr' },
];

onMounted(async () => {
  data.value = await api.get().licences(1);
});

function tierVariant(t: Licence['tier']) {
  return t === 'enterprise' ? 'enterprise' : t === 'pro' ? 'info' : 'neutral';
}

function onRowClick(l: Licence) {
  window.location.hash = `#/licenses/${l.id}`;
}
</script>

<template>
  <TPanel
    title="Licences"
    :subtitle="data ? `· ${data.total} total` : ''"
  >
    <TDataTable
      :columns="columns"
      :rows="data?.rows ?? []"
      row-key="id"
      @row-click="onRowClick"
    >
      <template #cell:tier="{ row }">
        <TPill
          :variant="tierVariant((row as Licence).tier)"
          :dot="false"
        >
          {{ (row as Licence).tier }}
        </TPill>
      </template>
      <template #cell:revokedAt="{ row }">
        <TPill
          v-if="(row as Licence).revokedAt"
          variant="unsafe"
        >
          Revoked
        </TPill>
        <TPill
          v-else
          variant="safe"
        >
          Active
        </TPill>
      </template>
    </TDataTable>
  </TPanel>
</template>
