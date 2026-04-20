<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TFormField, TInput, TSelect, TButton } from '@triton/ui';
import type { CreateUserReq } from '@triton/api-client';

const props = defineProps<{ open: boolean }>();

const emit = defineEmits<{
  close: [];
  submit: [payload: CreateUserReq];
}>();

const email = ref('');
const name = ref('');
const role = ref<'admin' | 'network_engineer'>('network_engineer');
const error = ref('');

watch(
  () => props.open,
  (o) => {
    if (!o) return;
    email.value = '';
    name.value = '';
    role.value = 'network_engineer';
    error.value = '';
  }
);

function submit() {
  const e = email.value.trim();
  const n = name.value.trim();
  if (!e) {
    error.value = 'Email is required.';
    return;
  }
  if (!n) {
    error.value = 'Name is required.';
    return;
  }
  error.value = '';
  emit('submit', { email: e, name: n, role: role.value });
}
</script>

<template>
  <TModal
    :open="props.open"
    title="New user"
    width="min(520px, 92vw)"
    @close="emit('close')"
  >
    <div class="user-form">
      <TFormField
        label="Email"
        required
        :error="error"
      >
        <TInput
          v-model="email"
          type="email"
        />
      </TFormField>
      <TFormField
        label="Name"
        required
      >
        <TInput v-model="name" />
      </TFormField>
      <TFormField label="Role">
        <TSelect v-model="role">
          <option value="admin">
            admin
          </option>
          <option value="network_engineer">
            network_engineer
          </option>
        </TSelect>
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
        Create
      </TButton>
    </template>
  </TModal>
</template>

<style scoped>
.user-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
</style>
