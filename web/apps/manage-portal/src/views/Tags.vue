<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  TButton,
  TDataTable,
  TConfirmDialog,
  useToast,
  type Column,
} from '@triton/ui';
import type { Tag } from '@triton/api-client';
import { useTagsStore } from '../stores/tags';
import TagForm from './modals/TagForm.vue';

const tags = useTagsStore();
const toast = useToast();

const formOpen = ref(false);
const editing = ref<Tag | null>(null);
const confirmOpen = ref(false);
const pendingDelete = ref<Tag | null>(null);

const columns: Column<Tag>[] = [
  { key: 'color', label: '', width: '40px' },
  { key: 'name', label: 'Name' },
  { key: 'host_count', label: 'Hosts', width: '80px' },
  { key: 'id', label: '', width: '160px', align: 'right' },
];

onMounted(() => { void tags.fetch(); });

function openNew() {
  editing.value = null;
  formOpen.value = true;
}

function openEdit(t: Tag) {
  editing.value = t;
  formOpen.value = true;
}

function askDelete(t: Tag) {
  pendingDelete.value = t;
  confirmOpen.value = true;
}

async function onSubmit(payload: { name: string; color: string }) {
  try {
    if (editing.value) {
      await tags.update(editing.value.id, payload);
      toast.success({ title: 'Tag updated', description: payload.name });
    } else {
      await tags.create(payload);
      toast.success({ title: 'Tag created', description: payload.name });
    }
    formOpen.value = false;
    editing.value = null;
  } catch (e) {
    toast.error({ title: 'Save failed', description: String(e) });
  }
}

async function onConfirmDelete() {
  const t = pendingDelete.value;
  if (!t) return;
  try {
    await tags.remove(t.id);
    toast.success({ title: 'Tag deleted', description: t.name });
  } catch (e) {
    toast.error({ title: 'Delete failed', description: String(e) });
  } finally {
    confirmOpen.value = false;
    pendingDelete.value = null;
  }
}
</script>

<template>
  <section class="tags-view">
    <header class="tags-head">
      <div>
        <h1>Tags</h1>
        <p class="tags-sub">Label hosts for filtering and grouping.</p>
      </div>
      <TButton
        variant="primary"
        size="sm"
        @click="openNew"
      >
        New tag
      </TButton>
    </header>

    <TDataTable
      :columns="columns"
      :rows="tags.items"
      row-key="id"
      :empty-text="tags.loading ? 'Loading…' : 'No tags yet.'"
    >
      <template #[`cell:color`]="{ row }">
        <span
          class="tags-color-swatch"
          :style="{ background: row.color }"
          :aria-label="row.color"
        />
      </template>
      <template #[`cell:host_count`]="{ row }">
        {{ row.host_count ?? 0 }}
      </template>
      <template #[`cell:id`]="{ row }">
        <div class="tags-actions">
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
            :data-test="`tag-delete-${row.id}`"
            @click="askDelete(row)"
          >
            Delete
          </TButton>
        </div>
      </template>
    </TDataTable>

    <TagForm
      :open="formOpen"
      :editing="editing"
      @close="formOpen = false; editing = null"
      @submit="onSubmit"
    />

    <TConfirmDialog
      :open="confirmOpen"
      title="Delete tag?"
      :message="pendingDelete
        ? `Deleting tag '${pendingDelete.name}' will remove it from all `
          + `${pendingDelete.host_count ?? 0} host(s) that use it. This cannot be undone.`
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
.tags-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.tags-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.tags-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.tags-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.tags-color-swatch {
  display: inline-block;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  vertical-align: middle;
}
.tags-actions {
  display: flex;
  gap: var(--space-2);
  justify-content: flex-end;
  width: 100%;
}
</style>
