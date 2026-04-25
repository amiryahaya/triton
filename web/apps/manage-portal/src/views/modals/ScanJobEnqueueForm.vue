<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TSelect, TFormField, TInput, TButton } from '@triton/ui';
import type { Tag, EnqueueReq, ScanJobProfile } from '@triton/api-client';

const props = defineProps<{ open: boolean; tags: Tag[] }>();
const emit = defineEmits<{ close: []; submit: [req: EnqueueReq] }>();

const selectedTags = ref<string[]>([]);
const profile = ref<ScanJobProfile>('standard');
const filter = ref('');
const busy = ref(false);

watch(
  () => props.open,
  (o) => {
    if (!o) return;
    selectedTags.value = [];
    profile.value = 'standard';
    filter.value = '';
    busy.value = false;
  }
);

function onSubmit() {
  if (selectedTags.value.length === 0) return;
  busy.value = true;
  try {
    emit('submit', {
      tags: selectedTags.value,
      profile: profile.value,
      host_filter: filter.value.trim() || undefined,
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
        label="Tags (multi-select)"
        required
      >
        <select
          v-model="selectedTags"
          multiple
          class="tags-multi"
          size="6"
        >
          <option
            v-for="t in props.tags"
            :key="t.id"
            :value="t.id"
          >
            {{ t.name }}
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
      <TFormField label="Host filter (glob, optional)">
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
        :disabled="selectedTags.length === 0 || busy"
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
.tags-multi {
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
