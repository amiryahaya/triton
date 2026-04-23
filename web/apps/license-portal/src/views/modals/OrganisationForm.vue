<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TFormField, TInput, TButton } from '@triton/ui';

const props = defineProps<{
  open: boolean;
}>();

const emit = defineEmits<{
  close: [];
  submit: [payload: { name: string; contact?: string; notes?: string }];
}>();

const name = ref('');
const contact = ref('');
const notes = ref('');
const error = ref('');

watch(
  () => props.open,
  (open) => {
    if (!open) return;
    name.value = '';
    contact.value = '';
    notes.value = '';
    error.value = '';
  },
  { immediate: true },
);

function submit() {
  if (!name.value.trim()) {
    error.value = 'Name is required.';
    return;
  }
  emit('submit', {
    name: name.value.trim(),
    contact: contact.value.trim() || undefined,
    notes: notes.value.trim() || undefined,
  });
}
</script>

<template>
  <TModal
    :open="open"
    title="New organisation"
    @close="emit('close')"
  >
    <div class="form">
      <TFormField
        label="Name"
        required
        :error="error"
      >
        <TInput v-model="name" />
      </TFormField>
      <TFormField label="Contact">
        <TInput v-model="contact" />
      </TFormField>
      <TFormField label="Notes">
        <TInput v-model="notes" />
      </TFormField>
    </div>
    <template #footer>
      <TButton
        variant="ghost"
        size="sm"
        @click="emit('close')"
      >Cancel</TButton>
      <TButton
        variant="primary"
        size="sm"
        @click="submit"
      >Create</TButton>
    </template>
  </TModal>
</template>

<style scoped>
.form { display: flex; flex-direction: column; gap: var(--space-3); }
</style>
