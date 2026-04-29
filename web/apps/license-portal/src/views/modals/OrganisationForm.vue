<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { TModal, TFormField, TInput, TButton } from '@triton/ui';
import type { Organisation } from '@triton/api-client';

export interface OrgFormPayload {
  name: string;
  contact_name: string;
  contact_phone?: string;
  contact_email: string;
  notes?: string;
}

const props = defineProps<{
  open: boolean;
  org?: Organisation;
}>();

const emit = defineEmits<{
  close: [];
  submit: [payload: OrgFormPayload];
}>();

const isEdit = computed(() => !!props.org);

const name = ref('');
const contactName = ref('');
const contactPhone = ref('');
const contactEmail = ref('');
const notes = ref('');
const nameError = ref('');
const contactNameError = ref('');
const contactEmailError = ref('');

watch(
  () => props.open,
  (open) => {
    if (!open) return;
    name.value = props.org?.name ?? '';
    contactName.value = props.org?.contact_name ?? '';
    contactPhone.value = props.org?.contact_phone ?? '';
    contactEmail.value = props.org?.contact_email ?? '';
    notes.value = props.org?.notes ?? '';
    nameError.value = '';
    contactNameError.value = '';
    contactEmailError.value = '';
  },
  { immediate: true },
);

function submit() {
  nameError.value = '';
  contactNameError.value = '';
  contactEmailError.value = '';

  let valid = true;
  if (!name.value.trim()) {
    nameError.value = 'Name is required.';
    valid = false;
  }
  if (!contactName.value.trim()) {
    contactNameError.value = 'Contact name is required.';
    valid = false;
  }
  if (!contactEmail.value.trim()) {
    contactEmailError.value = 'Contact email is required.';
    valid = false;
  }
  if (!valid) return;

  emit('submit', {
    name: name.value.trim(),
    contact_name: contactName.value.trim(),
    contact_phone: contactPhone.value.trim() || undefined,
    contact_email: contactEmail.value.trim(),
    notes: notes.value.trim() || undefined,
  });
}
</script>

<template>
  <TModal
    :open="open"
    :title="isEdit ? 'Edit organisation' : 'New organisation'"
    @close="emit('close')"
  >
    <div class="form">
      <TFormField
        label="Name"
        required
        :error="nameError"
      >
        <TInput v-model="name" />
      </TFormField>
      <TFormField
        label="Contact name"
        required
        :error="contactNameError"
      >
        <TInput
          v-model="contactName"
          placeholder="Full name"
        />
      </TFormField>
      <TFormField
        label="Contact email"
        required
        :error="contactEmailError"
      >
        <TInput
          v-model="contactEmail"
          type="email"
          placeholder="contact@example.com"
        />
      </TFormField>
      <TFormField label="Contact phone">
        <TInput
          v-model="contactPhone"
          type="tel"
          placeholder="+601234"
        />
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
      >{{ isEdit ? 'Save' : 'Create' }}</TButton>
    </template>
  </TModal>
</template>

<style scoped>
.form { display: flex; flex-direction: column; gap: var(--space-3); }
</style>
