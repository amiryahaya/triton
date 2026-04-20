<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TSelect, TFormField, TInput, TButton } from '@triton/ui';
import type { Zone, EnqueueReq, ScanJobProfile } from '@triton/api-client';

const props = defineProps<{ open: boolean; zones: Zone[] }>();
const emit = defineEmits<{ close: []; submit: [req: EnqueueReq] }>();

const selectedZones = ref<string[]>([]);
const profile = ref<ScanJobProfile>('standard');
const filter = ref('');
const busy = ref(false);

watch(
  () => props.open,
  (o) => {
    if (!o) return;
    selectedZones.value = [];
    profile.value = 'standard';
    filter.value = '';
    busy.value = false;
  }
);

function onSubmit() {
  if (selectedZones.value.length === 0) return;
  busy.value = true;
  try {
    emit('submit', {
      zones: selectedZones.value,
      profile: profile.value,
      target_filter: filter.value.trim() || undefined,
    });
  } finally {
    // Parent controls modal close + toast; reset busy so the button
    // re-enables if the parent opts to keep the modal open (e.g. error).
    busy.value = false;
  }
}
</script>

<template>
  <TModal
    :open="props.open"
    title="Enqueue scan jobs"
    width="min(560px, 92vw)"
    @close="emit('close')"
  >
    <div class="enqueue-form">
      <TFormField
        label="Zones (multi-select)"
        required
      >
        <select
          v-model="selectedZones"
          multiple
          class="zones-multi"
          size="6"
        >
          <option
            v-for="z in props.zones"
            :key="z.id"
            :value="z.id"
          >
            {{ z.name }}
          </option>
        </select>
      </TFormField>
      <TFormField label="Profile">
        <TSelect v-model="profile">
          <option value="quick">
            Quick
          </option>
          <option value="standard">
            Standard
          </option>
          <option value="comprehensive">
            Comprehensive
          </option>
        </TSelect>
      </TFormField>
      <TFormField label="Hostname filter (glob, optional)">
        <TInput
          v-model="filter"
          placeholder="db-*"
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
        :disabled="selectedZones.length === 0 || busy"
        @click="onSubmit"
      >
        {{ busy ? 'Enqueueing…' : 'Enqueue' }}
      </TButton>
    </template>
  </TModal>
</template>

<style scoped>
.enqueue-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.zones-multi {
  width: 100%;
  padding: var(--space-2);
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-family: var(--font-body);
  font-size: 0.85rem;
  color: var(--text-primary);
}
</style>
