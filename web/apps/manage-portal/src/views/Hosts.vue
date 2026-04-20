<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import {
  TButton,
  TDataTable,
  TConfirmDialog,
  TFormField,
  TSelect,
  useToast,
  type Column,
} from '@triton/ui';
import type { CreateHostReq, Host } from '@triton/api-client';
import { useHostsStore } from '../stores/hosts';
import { useZonesStore } from '../stores/zones';
import HostForm from './modals/HostForm.vue';
import HostBulkForm from './modals/HostBulkForm.vue';

const hosts = useHostsStore();
const zones = useZonesStore();
const toast = useToast();

const formOpen = ref(false);
const editing = ref<Host | null>(null);
const bulkOpen = ref(false);
const confirmOpen = ref(false);
const pendingDelete = ref<Host | null>(null);

const columns: Column<Host>[] = [
  { key: 'hostname', label: 'Hostname' },
  { key: 'ip', label: 'IP' },
  { key: 'zone_id', label: 'Zone' },
  { key: 'os', label: 'OS' },
  { key: 'last_seen_at', label: 'Last seen' },
  { key: 'id', label: '', width: '160px', align: 'right' },
];

const zoneNameByID = computed(() => {
  const m = new Map<string, string>();
  for (const z of zones.items) m.set(z.id, z.name);
  return m;
});

// TSelect requires a defined string modelValue; the store keeps zoneID
// optional. Normalise around an empty string for the dropdown.
const filterZoneID = computed<string>({
  get: () => hosts.filter.zoneID ?? '',
  set: (v: string) => { hosts.filter.zoneID = v || undefined; },
});

onMounted(async () => {
  // Load zones first so the filter dropdown + zone-name cell have data.
  await Promise.all([zones.fetch(), hosts.fetch()]);
});

// Trigger a refetch whenever the zone filter changes. The store persists
// the filter to localStorage on its own via a deep watcher.
watch(
  () => hosts.filter.zoneID,
  () => { void hosts.fetch(); }
);

function openNew() {
  editing.value = null;
  formOpen.value = true;
}

function openEdit(h: Host) {
  editing.value = h;
  formOpen.value = true;
}

function askDelete(h: Host) {
  pendingDelete.value = h;
  confirmOpen.value = true;
}

async function onSubmit(payload: CreateHostReq) {
  try {
    if (editing.value) {
      await hosts.update(editing.value.id, payload);
      toast.success({ title: 'Host updated', description: payload.hostname });
    } else {
      await hosts.create(payload);
      toast.success({ title: 'Host created', description: payload.hostname });
    }
    formOpen.value = false;
    editing.value = null;
  } catch (e) {
    toast.error({ title: 'Save failed', description: String(e) });
  }
}

async function onBulkSubmit(rows: CreateHostReq[]) {
  try {
    const created = await hosts.bulkCreate(rows);
    toast.success({
      title: 'Bulk import complete',
      description: `${created.length} host${created.length === 1 ? '' : 's'} imported.`,
    });
    bulkOpen.value = false;
  } catch (e) {
    toast.error({ title: 'Bulk import failed', description: String(e) });
  }
}

async function onConfirmDelete() {
  const h = pendingDelete.value;
  if (!h) return;
  try {
    await hosts.remove(h.id);
    toast.success({ title: 'Host deleted', description: h.hostname });
  } catch (e) {
    toast.error({ title: 'Delete failed', description: String(e) });
  } finally {
    confirmOpen.value = false;
    pendingDelete.value = null;
  }
}
</script>

<template>
  <section class="hosts-view">
    <header class="hosts-head">
      <div>
        <h1>Hosts</h1>
        <p class="hosts-sub">Targets available for scan jobs and agent binding.</p>
      </div>
      <div class="hosts-head-actions">
        <TButton
          variant="secondary"
          size="sm"
          @click="bulkOpen = true"
        >
          Bulk import
        </TButton>
        <TButton
          variant="primary"
          size="sm"
          @click="openNew"
        >
          New host
        </TButton>
      </div>
    </header>

    <div class="hosts-filter">
      <TFormField label="Filter by zone">
        <TSelect v-model="filterZoneID">
          <option value="">
            All zones
          </option>
          <option
            v-for="z in zones.items"
            :key="z.id"
            :value="z.id"
          >
            {{ z.name }}
          </option>
        </TSelect>
      </TFormField>
    </div>

    <TDataTable
      :columns="columns"
      :rows="hosts.items"
      row-key="id"
      :empty-text="hosts.loading ? 'Loading…' : 'No hosts yet.'"
    >
      <template #[`cell:zone_id`]="{ row }">
        {{ row.zone_id ? (zoneNameByID.get(row.zone_id) ?? row.zone_id) : '—' }}
      </template>
      <template #[`cell:id`]="{ row }">
        <div class="hosts-actions">
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
            :data-test="`host-delete-${row.id}`"
            @click="askDelete(row)"
          >
            Delete
          </TButton>
        </div>
      </template>
    </TDataTable>

    <HostForm
      :open="formOpen"
      :editing="editing"
      :zones="zones.items"
      @close="formOpen = false; editing = null"
      @submit="onSubmit"
    />

    <HostBulkForm
      :open="bulkOpen"
      @close="bulkOpen = false"
      @submit="onBulkSubmit"
    />

    <TConfirmDialog
      :open="confirmOpen"
      title="Delete host?"
      :message="pendingDelete
        ? `Deleting host '${pendingDelete.hostname}' will set host_id to NULL on scan jobs `
          + 'referencing it. Historical scan results remain in the queue / Report '
          + 'Server. This cannot be undone.'
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
.hosts-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.hosts-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.hosts-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.hosts-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.hosts-head-actions {
  display: flex;
  gap: var(--space-2);
}
.hosts-filter {
  max-width: 280px;
}
.hosts-actions {
  display: flex;
  gap: var(--space-2);
  justify-content: flex-end;
  width: 100%;
}
</style>
