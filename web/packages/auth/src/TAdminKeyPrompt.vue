<script setup lang="ts">
import { ref } from 'vue';
import { TButton, TInput, TFormField } from '@triton/ui';

const emit = defineEmits<{ submit: [key: string] }>();
const key = ref('');

function onSubmit(ev: Event) {
  ev.preventDefault();
  if (key.value.trim()) emit('submit', key.value.trim());
}
</script>

<template>
  <div class="t-admin-prompt">
    <form
      class="t-admin-card"
      @submit="onSubmit"
    >
      <h1 class="t-admin-title">
        License Server
      </h1>
      <p class="t-admin-sub">
        Admin key required to continue.
      </p>
      <TFormField
        label="Admin key"
        required
      >
        <TInput
          v-model="key"
          type="password"
          placeholder="X-Triton-Admin-Key"
        />
      </TFormField>
      <TButton
        type="submit"
        variant="primary"
        :disabled="!key.trim()"
      >
        Unlock
      </TButton>
    </form>
  </div>
</template>

<style scoped>
.t-admin-prompt {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-base);
}
.t-admin-card {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: var(--space-8) var(--space-8);
  width: min(360px, 92vw);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
  box-shadow: var(--shadow-lg);
}
.t-admin-title {
  font-family: var(--font-display);
  font-size: 1.6rem;
  font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--text-primary);
  margin: 0;
}
.t-admin-sub {
  color: var(--text-muted);
  font-size: 0.82rem;
  margin: 0;
}
</style>
