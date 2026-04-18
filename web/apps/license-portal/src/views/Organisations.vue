<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TDataTable, TPanel, TButton, useToast, type Column } from '@triton/ui';
import type { Organisation, Paged } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const data = ref<Paged<Organisation> | null>(null);
const loading = ref(true);

const columns: Column<Organisation>[] = [
  { key: 'name',      label: 'Name',    width: '2fr' },
  { key: 'createdAt', label: 'Created', width: '1fr' },
  { key: 'id',        label: 'ID',      width: '1fr' },
];

onMounted(async () => {
  try {
    data.value = await api.get().orgs(1);
  } catch (err) {
    toast.error({ title: 'Failed to load organisations', description: String(err) });
  } finally {
    loading.value = false;
  }
});

function onRowClick(o: Organisation) {
  window.location.hash = `#/orgs/${o.id}`;
}
</script>

<template>
  <TPanel
    title="Organisations"
    :subtitle="data ? `· ${data.total} total` : ''"
  >
    <template #action>
      <TButton
        variant="primary"
        size="sm"
      >
        + Add org
      </TButton>
    </template>
    <TDataTable
      :columns="columns"
      :rows="data?.rows ?? []"
      row-key="id"
      empty-text="No organisations yet."
      @row-click="onRowClick"
    />
  </TPanel>
</template>
