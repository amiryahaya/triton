<script setup lang="ts">
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue';
import { TModal, TFormField, TInput, TSelect, TButton } from '@triton/ui';
import type { Host, Tag, CreateHostReq } from '@triton/api-client';
import { useCredentialsStore } from '../../stores/credentials';

const props = defineProps<{
  open: boolean;
  editing?: Host | null;
  tags: Tag[];
}>();

const emit = defineEmits<{
  close: [];
  submit: [payload: CreateHostReq];
}>();

const credStore = useCredentialsStore();

const hostname = ref('');
const ip = ref('');
const selectedTagIDs = ref<string[]>([]);
const error = ref('');
const credentialsRef = ref<string | null>(null);
const accessPort = ref<number | null>(null);
const dropdownOpen = ref(false);
const dropdownRef = ref<HTMLElement | null>(null);

watch(
  () => [props.open, props.editing],
  () => {
    if (!props.open) return;
    credStore.fetch();
    hostname.value = props.editing?.hostname ?? '';
    ip.value = props.editing?.ip ?? '';
    selectedTagIDs.value = props.editing?.tags.map(t => t.id) ?? [];
    credentialsRef.value = props.editing?.credentials_ref ?? null;
    accessPort.value = props.editing?.access_port ?? null;
    error.value = '';
    dropdownOpen.value = false;
  },
  { immediate: true }
);

watch(credentialsRef, (id) => {
  if (!id) { accessPort.value = null; return; }
  const cred = credStore.items.find(c => c.id === id);
  if (!cred) return;
  accessPort.value = cred.auth_type === 'winrm-password' ? 5985 : 22;
});

const credOptions = computed(() => [
  { value: null, label: '— none —' },
  ...credStore.items.map(c => ({ value: c.id, label: `${c.name} (${c.auth_type})` })),
]);

const selectedTags = computed(() =>
  props.tags.filter(t => selectedTagIDs.value.includes(t.id))
);

function onClickOutside(e: MouseEvent) {
  if (dropdownRef.value && !dropdownRef.value.contains(e.target as Node)) {
    dropdownOpen.value = false;
  }
}

onMounted(() => document.addEventListener('mousedown', onClickOutside));
onBeforeUnmount(() => document.removeEventListener('mousedown', onClickOutside));

function submit() {
  if (!ip.value.trim()) {
    error.value = 'IP address is required.';
    return;
  }
  emit('submit', {
    ip: ip.value.trim(),
    hostname: hostname.value.trim() || undefined,
    tag_ids: selectedTagIDs.value,
    credentials_ref: credentialsRef.value ?? null,
    access_port: accessPort.value ?? undefined,
  });
}
</script>

<template>
  <TModal
    :open="open"
    :title="editing ? 'Edit host' : 'New host'"
    @close="emit('close')"
  >
    <div class="host-form">
      <TFormField label="Hostname">
        <TInput v-model="hostname" />
      </TFormField>
      <TFormField
        label="IP address"
        required
        :error="error"
      >
        <TInput v-model="ip" />
      </TFormField>

      <TFormField label="Tags">
        <div
          ref="dropdownRef"
          class="tag-dropdown"
        >
          <button
            type="button"
            class="tag-dropdown-toggle"
            @click="dropdownOpen = !dropdownOpen"
          >
            <span
              v-if="selectedTags.length === 0"
              class="placeholder"
            >Select tags…</span>
            <div
              v-else
              class="selected-chips"
            >
              <span
                v-for="t in selectedTags"
                :key="t.id"
                class="tag-chip"
                :style="{ background: t.color }"
              >{{ t.name }}</span>
            </div>
            <span class="caret">▾</span>
          </button>
          <div
            v-if="dropdownOpen"
            class="tag-dropdown-list"
          >
            <label
              v-for="tag in tags"
              :key="tag.id"
              class="tag-option"
            >
              <input
                type="checkbox"
                :value="tag.id"
                v-model="selectedTagIDs"
              />
              <span
                class="tag-chip"
                :style="{ background: tag.color }"
              >{{ tag.name }}</span>
            </label>
            <span
              v-if="!tags.length"
              class="no-tags"
            >No tags defined yet.</span>
          </div>
        </div>
      </TFormField>

      <TFormField label="Credential">
        <TSelect v-model="credentialsRef">
          <option
            v-for="opt in credOptions"
            :key="opt.value ?? '__none__'"
            :value="opt.value"
          >
            {{ opt.label }}
          </option>
        </TSelect>
      </TFormField>
      <TFormField label="SSH Port">
        <TInput
          type="number"
          :min="1"
          :max="65535"
          :model-value="accessPort ?? ''"
          placeholder="Default (22)"
          @update:model-value="(v: string) => { const n = parseInt(v, 10); accessPort = isNaN(n) ? null : n; }"
        />
      </TFormField>
    </div>
    <template #footer>
      <TButton
        variant="ghost"
        size="sm"
        @click="emit('close')"
      >
        Cancel
      </TButton>
      <TButton
        variant="primary"
        size="sm"
        @click="submit"
      >
        {{ editing ? 'Save' : 'Create' }}
      </TButton>
    </template>
  </TModal>
</template>

<style scoped>
.host-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

/* ── Tag dropdown ─────────────────────────────────────────── */
.tag-dropdown {
  position: relative;
}

.tag-dropdown-toggle {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-2);
  width: 100%;
  min-height: 36px;
  padding: var(--space-1) var(--space-3);
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  font-size: 0.8rem;
  font-family: var(--font-body);
  color: var(--text-primary);
  cursor: pointer;
  text-align: left;
}

.tag-dropdown-toggle:focus {
  outline: none;
  border-color: var(--accent-strong);
  box-shadow: 0 0 0 2px var(--accent-muted);
}

.placeholder {
  color: var(--text-muted);
}

.selected-chips {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-1);
  flex: 1;
}

.caret {
  color: var(--text-muted);
  font-size: 0.7rem;
  flex-shrink: 0;
}

.tag-dropdown-list {
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  right: 0;
  z-index: 100;
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  padding: var(--space-1) 0;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
  max-height: 200px;
  overflow-y: auto;
}

.tag-option {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-1) var(--space-3);
  cursor: pointer;
  font-size: 0.82rem;
}

.tag-option:hover {
  background: var(--bg-sunken);
}

.tag-option input[type='checkbox'] {
  accent-color: var(--accent-strong);
  cursor: pointer;
  flex-shrink: 0;
}

.no-tags {
  padding: var(--space-2) var(--space-3);
  font-size: 0.78rem;
  color: var(--text-muted);
}

/* ── Tag chips (shared) ───────────────────────────────────── */
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
</style>
