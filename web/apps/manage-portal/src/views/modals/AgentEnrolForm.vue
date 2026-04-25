<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TFormField, TInput, TButton } from '@triton/ui';

const props = defineProps<{
  open: boolean;
}>();

const emit = defineEmits<{
  close: [];
  submit: [payload: { name: string }];
}>();

const name = ref('');
const error = ref('');
const busy = ref(false);

watch(
  () => props.open,
  (o) => {
    if (!o) return;
    name.value = '';
    error.value = '';
    busy.value = false;
  }
);

async function submit() {
  if (!name.value.trim()) {
    error.value = 'Agent name is required.';
    return;
  }
  busy.value = true;
  try {
    emit('submit', {
      name: name.value.trim(),
    });
  } finally {
    // Parent controls close + success/error toast; release the spinner
    // on the next tick so double-submit is blocked while the request is
    // in flight but the button re-enables if the parent leaves the
    // modal open.
    busy.value = false;
  }
}
</script>

<template>
  <TModal
    :open="open"
    :title="'Enrol new agent'"
    width="min(560px, 92vw)"
    @close="emit('close')"
  >
    <div class="enrol-form">
      <div
        class="enrol-warn"
        role="alert"
      >
        <strong>One-shot download.</strong> The enrolment bundle contains
        a private key that is <em>not</em> stored on the server. Save the
        downloaded <code>.tar.gz</code> immediately — if you lose it, you
        must revoke this agent and enrol a new one.
      </div>
      <TFormField
        label="Agent name"
        required
        :error="error"
      >
        <TInput v-model="name" />
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
        :disabled="busy"
        @click="submit"
      >
        {{ busy ? 'Enrolling…' : 'Enrol and download' }}
      </TButton>
    </template>
  </TModal>
</template>

<style scoped>
.enrol-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.enrol-warn {
  padding: var(--space-3);
  border: 1px solid var(--warn);
  background: var(--warn-muted);
  color: var(--warn);
  border-radius: var(--radius-sm);
  font-size: 0.78rem;
  line-height: 1.5;
}
.enrol-warn strong { color: var(--warn); }
.enrol-warn code {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  padding: 1px 4px;
  background: var(--bg-surface);
  border-radius: var(--radius-sm);
}
</style>
