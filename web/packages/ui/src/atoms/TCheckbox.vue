<script setup lang="ts">
const props = defineProps<{
  modelValue: boolean;
  label?: string;
  disabled?: boolean;
}>();

const emit = defineEmits<{ 'update:modelValue': [v: boolean] }>();

function onClick() {
  if (props.disabled) return;
  emit('update:modelValue', !props.modelValue);
}
</script>

<template>
  <button
    type="button"
    class="t-check"
    :class="{ 'is-checked': modelValue, 'is-disabled': disabled }"
    :aria-checked="modelValue"
    role="checkbox"
    :disabled="disabled"
    @click="onClick"
  >
    <span class="t-check-box" />
    <span
      v-if="label"
      class="t-check-label"
    >{{ label }}</span>
  </button>
</template>

<style scoped>
.t-check {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  background: transparent;
  border: none;
  cursor: pointer;
  padding: 0;
  font-family: var(--font-body);
}
.t-check-box {
  width: 14px; height: 14px;
  border: 1px solid var(--border-strong);
  border-radius: 3px;
  background: transparent;
  position: relative;
  transition:
    background var(--motion-hover) var(--ease),
    border-color var(--motion-hover) var(--ease);
}
.t-check.is-checked .t-check-box {
  background: var(--accent);
  border-color: var(--accent);
}
.t-check.is-checked .t-check-box::after {
  content: '✓';
  position: absolute;
  top: -4px; left: 1px;
  color: var(--bg-base);
  font-size: 0.72rem;
  font-weight: 700;
}
.t-check.is-disabled { opacity: 0.5; cursor: not-allowed; }
.t-check-label { font-size: 0.76rem; color: var(--text-primary); }
</style>
