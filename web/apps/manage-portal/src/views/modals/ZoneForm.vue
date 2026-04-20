<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TFormField, TInput, TButton } from '@triton/ui';
import type { Zone } from '@triton/api-client';

const props = defineProps<{
  open: boolean;
  editing?: Zone | null;
}>();

const emit = defineEmits<{
  close: [];
  submit: [payload: { name: string; description?: string }];
}>();

const name = ref('');
const description = ref('');
const error = ref('');

watch(
  () => [props.open, props.editing],
  () => {
    if (!props.open) return;
    name.value = props.editing?.name ?? '';
    description.value = props.editing?.description ?? '';
    error.value = '';
  },
  { immediate: true }
);

function submit() {
  if (!name.value.trim()) {
    error.value = 'Name is required.';
    return;
  }
  emit('submit', {
    name: name.value.trim(),
    description: description.value.trim() || undefined,
  });
}
</script>

<template>
  <TModal
    :open="open"
    :title="editing ? 'Edit zone' : 'New zone'"
    @close="emit('close')"
  >
    <div class="zone-form">
      <TFormField
        label="Name"
        required
        :error="error"
      >
        <TInput v-model="name" />
      </TFormField>
      <TFormField label="Description">
        <TInput v-model="description" />
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
.zone-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
</style>
