<script setup lang="ts">
import { onMounted, ref, watch } from 'vue';
import { useRouter } from 'vue-router';
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
import { useTagsStore } from '../stores/tags';
import HostForm from './modals/HostForm.vue';
import HostBulkForm from './modals/HostBulkForm.vue';

const hosts = useHostsStore();
const tags = useTagsStore();
const toast = useToast();
const router = useRouter();

const formOpen = ref(false);
const editing = ref<Host | null>(null);
const bulkOpen = ref(false);
const confirmOpen = ref(false);
const pendingDelete = ref<Host | null>(null);

const columns: Column<Host>[] = [
  { key: 'ip', label: 'IP' },
  { key: 'hostname', label: 'Hostname' },
  { key: 'tags', label: 'Tags' },
  { key: 'os', label: 'OS' },
  { key: 'last_seen_at', label: 'Last seen' },
  { key: 'id', label: '', width: '160px', align: 'right' },
];

// TSelect requires a defined string modelValue; the store keeps tagID
// optional. Normalise around an empty string for the dropdown.
const filterTagID = ref(hosts.filter.tagID ?? '');

watch(filterTagID, (v) => {
  hosts.filter.tagID = v || undefined;
  void hosts.fetch();
});

onMounted(async () => {
  // Load tags first so the filter dropdown + tag chips have data.
  await Promise.all([tags.fetch(), hosts.fetch()]);
});

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
      toast.success({ title: 'Host updated', description: payload.ip });
    } else {
      await hosts.create(payload);
      toast.success({ title: 'Host created', description: payload.ip });
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
    toast.success({ title: 'Host deleted', description: h.hostname || h.ip });
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
          @click="router.push('/inventory/discover')"
        >
          Discovery
        </TButton>
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
      <TFormField label="Filter by tag">
        <TSelect v-model="filterTagID">
          <option value="">
            All tags
          </option>
          <option
            v-for="t in tags.items"
            :key="t.id"
            :value="t.id"
          >
            {{ t.name }}
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
      <template #[`cell:tags`]="{ row }">
        <div class="tag-chips">
          <span
            v-for="tag in row.tags"
            :key="tag.id"
            class="tag-chip"
            :style="{ background: tag.color }"
          >{{ tag.name }}</span>
          <span
            v-if="!row.tags.length"
            class="muted"
          >—</span>
        </div>
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
      :tags="tags.items"
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
        ? `Deleting host '${pendingDelete.hostname || pendingDelete.ip}' will set host_id to NULL on scan jobs `
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
.tag-chips {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-1);
  align-items: center;
}
.tag-chip {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: var(--radius-full, 9999px);
  font-size: 0.72rem;
  font-weight: 500;
  color: #fff;
  white-space: nowrap;
}
.muted {
  color: var(--text-muted);
}
</style>
