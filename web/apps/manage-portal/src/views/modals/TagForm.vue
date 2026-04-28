<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TFormField, TInput, TButton } from '@triton/ui';
import type { Tag } from '@triton/api-client';

const PRESET_COLORS = [
  '#EF4444', '#F97316', '#EAB308', '#22C55E',
  '#06B6D4', '#3B82F6', '#6366F1', '#A855F7',
  '#EC4899', '#14B8A6', '#64748B', '#1E293B',
];

const props = defineProps<{
  open: boolean;
  editing?: Tag | null;
}>();

const emit = defineEmits<{
  close: [];
  submit: [payload: { name: string; color: string }];
}>();

const name = ref('');
const color = ref(PRESET_COLORS[0]);
const error = ref('');

watch(
  () => [props.open, props.editing],
  () => {
    if (!props.open) return;
    name.value = props.editing?.name ?? '';
    color.value = props.editing?.color ?? PRESET_COLORS[0];
    error.value = '';
  },
  { immediate: true }
);

function submit() {
  if (!name.value.trim()) {
    error.value = 'Name is required.';
    return;
  }
  emit('submit', { name: name.value.trim().toLowerCase(), color: color.value });
}
</script>

<template>
  <TModal
    :open="open"
    :title="editing ? 'Edit tag' : 'New tag'"
    @close="emit('close')"
  >
    <div class="tag-form">
      <TFormField
        label="Name"
        required
        :error="error"
      >
        <TInput v-model="name" />
      </TFormField>
      <TFormField label="Color">
        <div class="tag-color-palette">
          <button
            v-for="c in PRESET_COLORS"
            :key="c"
            type="button"
            class="tag-color-swatch"
            :class="{ 'tag-color-swatch--active': color === c }"
            :style="{ background: c }"
            :aria-label="c"
            @click="color = c"
          />
        </div>
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
.tag-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.tag-color-palette {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  padding: var(--space-1) 0;
}
.tag-color-swatch {
  width: 28px;
  height: 28px;
  border-radius: 50%;
  border: 2px solid transparent;
  cursor: pointer;
  transition: transform 0.1s, border-color 0.1s;
  outline: none;
  padding: 0;
}
.tag-color-swatch:hover {
  transform: scale(1.15);
}
.tag-color-swatch--active {
  border-color: var(--text-default);
  transform: scale(1.15);
}
</style>
