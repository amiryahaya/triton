<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  TButton,
  TDataTable,
  TConfirmDialog,
  useToast,
  type Column,
} from '@triton/ui';
import type { Zone } from '@triton/api-client';
import { useZonesStore } from '../stores/zones';
import ZoneForm from './modals/ZoneForm.vue';

const zones = useZonesStore();
const toast = useToast();

const formOpen = ref(false);
const editing = ref<Zone | null>(null);
const confirmOpen = ref(false);
const pendingDelete = ref<Zone | null>(null);

const columns: Column<Zone>[] = [
  { key: 'name', label: 'Name' },
  { key: 'description', label: 'Description' },
  { key: 'created_at', label: 'Created' },
  { key: 'id', label: '', width: '160px', align: 'right' },
];

onMounted(() => { void zones.fetch(); });

function openNew() {
  editing.value = null;
  formOpen.value = true;
}

function openEdit(z: Zone) {
  editing.value = z;
  formOpen.value = true;
}

function askDelete(z: Zone) {
  pendingDelete.value = z;
  confirmOpen.value = true;
}

async function onSubmit(payload: { name: string; description?: string }) {
  try {
    if (editing.value) {
      await zones.update(editing.value.id, payload);
      toast.success({ title: 'Zone updated', description: payload.name });
    } else {
      await zones.create(payload);
      toast.success({ title: 'Zone created', description: payload.name });
    }
    formOpen.value = false;
    editing.value = null;
  } catch (e) {
    toast.error({ title: 'Save failed', description: String(e) });
  }
}

async function onConfirmDelete() {
  const z = pendingDelete.value;
  if (!z) return;
  try {
    await zones.remove(z.id);
    toast.success({ title: 'Zone deleted', description: z.name });
  } catch (e) {
    toast.error({ title: 'Delete failed', description: String(e) });
  } finally {
    confirmOpen.value = false;
    pendingDelete.value = null;
  }
}
</script>

<template>
  <section class="zones-view">
    <header class="zones-head">
      <div>
        <h1>Zones</h1>
        <p class="zones-sub">Logical groupings for hosts and agents.</p>
      </div>
      <TButton
        variant="primary"
        size="sm"
        @click="openNew"
      >
        New zone
      </TButton>
    </header>

    <TDataTable
      :columns="columns"
      :rows="zones.items"
      row-key="id"
      :empty-text="zones.loading ? 'Loading…' : 'No zones yet.'"
    >
      <template #[`cell:id`]="{ row }">
        <div class="zones-actions">
          <TButton
            variant="ghost"
            size="sm"
            @click="openEdit(row)"
          >
            Edit
          </TButton>
          <TButton
            variant="danger"
            size="sm"
            :data-test="`zone-delete-${row.id}`"
            @click="askDelete(row)"
          >
            Delete
          </TButton>
        </div>
      </template>
    </TDataTable>

    <ZoneForm
      :open="formOpen"
      :editing="editing"
      @close="formOpen = false; editing = null"
      @submit="onSubmit"
    />

    <TConfirmDialog
      :open="confirmOpen"
      title="Delete zone?"
      :message="pendingDelete
        ? `Deleting zone '${pendingDelete.name}' will set zone_id to NULL on any hosts in `
          + 'it (they become unassigned) and on any scan jobs referencing this '
          + 'zone (audit trail preserved). Zone memberships are cascaded-deleted. '
          + 'This cannot be undone.'
        : ''"
      confirm-label="Delete"
      variant="danger"
      data-test="confirm-dialog"
      @confirm="onConfirmDelete"
      @cancel="confirmOpen = false; pendingDelete = null"
    />
  </section>
</template>

<style scoped>
.zones-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.zones-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.zones-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.zones-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.zones-actions {
  display: flex;
  gap: var(--space-2);
  justify-content: flex-end;
  width: 100%;
}
</style>
