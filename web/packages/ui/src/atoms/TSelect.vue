<script setup lang="ts">
defineProps<{
  modelValue: string | number;
  error?: boolean;
  disabled?: boolean;
}>();

const emit = defineEmits<{ 'update:modelValue': [v: string] }>();

function onChange(ev: Event) {
  emit('update:modelValue', (ev.target as HTMLSelectElement).value);
}
</script>

<template>
  <select
    class="t-input t-select"
    :class="{ 'is-error': error }"
    :value="modelValue"
    :disabled="disabled"
    @change="onChange"
  >
    <slot />
  </select>
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
.t-input:focus { border-color: var(--accent-strong); box-shadow: 0 0 0 2px var(--accent-muted); }
.t-input.is-error { border-color: var(--unsafe); }
.t-input:disabled { opacity: 0.5; cursor: not-allowed; }

.t-select {
  appearance: none;
  background-image:
    linear-gradient(45deg, transparent 50%, var(--text-muted) 50%),
    linear-gradient(135deg, var(--text-muted) 50%, transparent 50%);
  background-position: calc(100% - 15px) 50%, calc(100% - 10px) 50%;
  background-size: 5px 5px, 5px 5px;
  background-repeat: no-repeat;
  padding-right: calc(var(--space-3) + 15px);
}
</style>
