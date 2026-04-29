<template>
  <div class="step-content">
    <h2 class="step-title">Hosts</h2>

    <!-- Search -->
    <div class="host-filters">
      <input v-model="search" class="t-input" placeholder="Search hostname or IP…" />
    </div>

    <!-- Selected chips -->
    <div v-if="selectedHosts.length" class="chip-area">
      <span class="chip-count">{{ selectedHosts.length }} host{{ selectedHosts.length !== 1 ? 's' : '' }} selected</span>
      <span v-for="h in selectedHosts" :key="h.id" class="chip">
        {{ credIcon(h) }} {{ h.hostname || h.ip }}
        <button class="chip-remove" @click="deselect(h.id)">&#x2715;</button>
      </span>
    </div>

    <!-- Host list -->
    <div class="host-list">
      <label v-for="h in filteredHosts" :key="h.id" class="host-row"
             :class="{ selected: isSelected(h.id) }">
        <input type="checkbox" :checked="isSelected(h.id)" @change="toggleHost(h)" />
        <span class="cred-icon">{{ credIcon(h) }}</span>
        <span class="hostname">{{ h.hostname || h.ip }}</span>
        <span v-if="h.hostname" class="ip">{{ h.ip }}</span>
      </label>
    </div>

    <!-- Legend -->
    <div class="legend">
      <span>🟢 SSH credential</span>
      <span>🟡 No credential — filesystem will be skipped</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import type { Host } from '@triton/api-client';
import type { WizardState } from './wizardTypes';
import { useApiClient } from '../../stores/apiClient';

const props = defineProps<{ modelValue: WizardState }>();
const emit = defineEmits<{ 'update:modelValue': [WizardState] }>();

const allHosts = ref<Host[]>([]);
const search = ref('');

onMounted(async () => {
  const api = useApiClient().get();
  allHosts.value = await api.listHosts();
});

const filteredHosts = computed(() =>
  allHosts.value.filter(h => {
    const q = search.value.toLowerCase();
    return !q || (h.hostname ?? '').toLowerCase().includes(q) || h.ip.includes(q);
  })
);

const selectedHosts = computed(() =>
  allHosts.value.filter(h => props.modelValue.hostIDs.includes(h.id))
);

function isSelected(id: string) {
  return props.modelValue.hostIDs.includes(id);
}

function credIcon(h: Host): string {
  if (h.credentials_ref && h.ssh_port > 0) return '🟢';
  return '🟡';
}

function toggleHost(h: Host) {
  const ids = isSelected(h.id)
    ? props.modelValue.hostIDs.filter(id => id !== h.id)
    : [...props.modelValue.hostIDs, h.id];
  emit('update:modelValue', { ...props.modelValue, hostIDs: ids });
}

function deselect(id: string) {
  emit('update:modelValue', {
    ...props.modelValue,
    hostIDs: props.modelValue.hostIDs.filter(i => i !== id),
  });
}
</script>

<style scoped>
.step-content {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.step-title {
  font-family: var(--font-display);
  font-size: 1.1rem;
  margin: 0;
}

.host-filters {
  display: flex;
  gap: var(--space-2);
}

.t-input {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 0.875rem;
  background: var(--bg-surface);
  color: var(--text-primary);
  box-sizing: border-box;
}

.t-input:focus {
  outline: none;
  border-color: var(--color-primary, #2563eb);
}

.chip-area {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-1);
  align-items: center;
}

.chip-count {
  font-size: 0.75rem;
  color: var(--text-muted);
  margin-right: var(--space-1);
}

.chip {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  font-size: 0.78rem;
  background: var(--bg-muted, #f3f4f6);
  border: 1px solid var(--border);
  border-radius: 9999px;
  padding: 0.15rem 0.5rem;
}

.chip-remove {
  background: none;
  border: none;
  padding: 0;
  cursor: pointer;
  font-size: 0.7rem;
  color: var(--text-muted);
  line-height: 1;
}

.chip-remove:hover {
  color: var(--text-primary);
}

.host-list {
  display: flex;
  flex-direction: column;
  gap: 0;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  overflow: hidden;
  max-height: 280px;
  overflow-y: auto;
}

.host-row {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-2) var(--space-3);
  cursor: pointer;
  font-size: 0.85rem;
  border-bottom: 1px solid var(--border);
  transition: background 0.1s;
}

.host-row:last-child {
  border-bottom: none;
}

.host-row:hover {
  background: var(--bg-muted, #f9fafb);
}

.host-row.selected {
  background: color-mix(in srgb, var(--color-primary, #2563eb) 6%, transparent);
}

.host-row input[type="checkbox"] {
  flex-shrink: 0;
}

.cred-icon {
  font-size: 0.9rem;
  flex-shrink: 0;
}

.hostname {
  flex: 1;
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.ip {
  font-size: 0.78rem;
  color: var(--text-muted);
  flex-shrink: 0;
}

.legend {
  display: flex;
  gap: var(--space-4);
  font-size: 0.75rem;
  color: var(--text-muted);
  flex-wrap: wrap;
}
</style>
