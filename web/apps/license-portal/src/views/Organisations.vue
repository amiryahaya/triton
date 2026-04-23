<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  TDataTable, TPanel, TButton, TConfirmDialog, useToast, type Column,
} from '@triton/ui';
import type { Organisation } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';
import OrganisationForm from './modals/OrganisationForm.vue';

const api = useApiClient();
const toast = useToast();
const items = ref<Organisation[]>([]);
const loading = ref(false);
const formOpen = ref(false);
const confirmOpen = ref(false);
const pendingDelete = ref<Organisation | null>(null);

interface OrgRow extends Organisation {
  [key: string]: unknown;
}

const columns: Column<OrgRow>[] = [
  { key: 'name', label: 'Name', width: '1.5fr' },
  { key: 'contact', label: 'Contact', width: '1.2fr' },
  { key: 'notes', label: 'Notes', width: '1.5fr' },
  { key: 'createdAt', label: 'Created', width: '1fr' },
  { key: 'updatedAt', label: 'Updated', width: '1fr' },
  { key: 'id', label: '', width: '120px', align: 'right' },
];

async function load() {
  loading.value = true;
  try {
    items.value = await api.get().orgs();
  } catch (err) {
    toast.error({ title: 'Failed to load organisations', description: String(err) });
  } finally {
    loading.value = false;
  }
}

onMounted(load);

function onRowClick(row: Record<string, unknown>) {
  window.location.hash = `#/orgs/${String(row.id)}`;
}

function askDelete(o: Organisation) {
  pendingDelete.value = o;
  confirmOpen.value = true;
}

async function confirmDelete() {
  const o = pendingDelete.value;
  if (!o) return;
  try {
    await api.get().deleteOrg(o.id);
    items.value = items.value.filter((x) => x.id !== o.id);
    toast.success({ title: 'Organisation deleted' });
  } catch (err) {
    toast.error({ title: 'Delete failed', description: String(err) });
  } finally {
    confirmOpen.value = false;
    pendingDelete.value = null;
  }
}

async function onSubmit(payload: { name: string; contact?: string; notes?: string }) {
  try {
    const o = await api.get().createOrg(payload);
    items.value.push(o);
    formOpen.value = false;
    toast.success({ title: 'Organisation created', description: o.name });
  } catch (err) {
    toast.error({ title: 'Create failed', description: String(err) });
  }
}
</script>

<template>
  <TPanel
    title="Organisations"
    :subtitle="items.length ? `· ${items.length} total` : ''"
  >
    <template #action>
      <TButton
        variant="primary"
        size="sm"
        @click="formOpen = true"
      >
        New organisation
      </TButton>
    </template>

    <TDataTable
      :columns="columns"
      :rows="items"
      row-key="id"
      :empty-text="loading ? 'Loading…' : 'No organisations yet.'"
      @row-click="onRowClick"
    >
      <template #[`cell:id`]="{ row }">
        <TButton
          variant="danger"
          size="sm"
          :data-test="`org-delete-${String(row.id)}`"
          @click.stop="askDelete(row as unknown as Organisation)"
        >
          Delete
        </TButton>
      </template>
    </TDataTable>
  </TPanel>

  <OrganisationForm
    :open="formOpen"
    @close="formOpen = false"
    @submit="onSubmit"
  />

  <TConfirmDialog
    :open="confirmOpen"
    title="Delete organisation?"
    :message="pendingDelete
      ? `Deleting '${pendingDelete.name}' cascades to all its licences and activations.`
      : ''"
    confirm-label="Delete"
    variant="danger"
    @confirm="confirmDelete"
    @cancel="confirmOpen = false; pendingDelete = null"
  />
</template>
