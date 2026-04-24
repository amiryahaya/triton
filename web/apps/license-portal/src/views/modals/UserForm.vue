<script setup lang="ts">
import { ref, watch, computed } from 'vue';
import { TModal, TFormField, TInput, TButton } from '@triton/ui';

const props = defineProps<{ open: boolean }>();
const emit = defineEmits<{
  close: [];
  submit: [payload: { name: string; email: string }];
}>();

const name = ref('');
const email = ref('');

watch(
  () => props.open,
  (open) => { if (open) { name.value = ''; email.value = ''; } },
  { immediate: true },
);

const canSubmit = computed(
  () => name.value.trim() !== '' && email.value.includes('@'),
);

function submit() {
  if (!canSubmit.value) return;
  emit('submit', { name: name.value.trim(), email: email.value.trim() });
}
</script>

<template>
  <TModal :open="open" title="New user" @close="emit('close')">
    <div class="form">
      <TFormField label="Name" required>
        <TInput v-model="name" data-test="user-name" />
      </TFormField>
      <TFormField label="Email" required>
        <TInput v-model="email" type="email" data-test="user-email" />
      </TFormField>
    </div>
    <template #footer>
      <TButton variant="ghost" size="sm" @click="emit('close')">Cancel</TButton>
      <TButton
        variant="primary"
        size="sm"
        :disabled="!canSubmit"
        data-test="user-submit"
        @click="submit"
      >Send invite</TButton>
    </template>
  </TModal>
</template>

<style scoped>
.form { display: flex; flex-direction: column; gap: var(--space-3); }
</style>
