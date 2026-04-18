<script setup lang="ts">
defineProps<{
  modelValue: string | number;
  error?: boolean;
  placeholder?: string;
  type?: string;
  disabled?: boolean;
}>();

const emit = defineEmits<{ 'update:modelValue': [v: string] }>();

function onInput(ev: Event) {
  emit('update:modelValue', (ev.target as HTMLInputElement).value);
}
</script>

<template>
  <input
    class="t-input"
    :class="{ 'is-error': error }"
    :value="modelValue"
    :placeholder="placeholder"
    :type="type ?? 'text'"
    :disabled="disabled"
    @input="onInput"
  >
</template>

<style scoped>
.t-input {
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  color: var(--text-primary);
  padding: var(--space-2) var(--space-3);
  border-radius: var(--radius-sm);
  font-size: 0.8rem;
  font-family: var(--font-body);
  outline: none;
  width: 100%;
}
.t-input:focus {
  border-color: var(--accent-strong);
  box-shadow: 0 0 0 2px var(--accent-muted);
}
.t-input.is-error { border-color: var(--unsafe); }
.t-input:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
