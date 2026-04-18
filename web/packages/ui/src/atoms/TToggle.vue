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
    class="t-toggle"
    :class="{ 'is-on': modelValue, 'is-disabled': disabled }"
    :aria-pressed="modelValue"
    :disabled="disabled"
    @click="onClick"
  >
    <span class="t-toggle-track">
      <span class="t-toggle-thumb" />
    </span>
    <span
      v-if="label"
      class="t-toggle-label"
    >{{ label }}</span>
  </button>
</template>

<style scoped>
.t-toggle {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  background: transparent;
  border: none;
  cursor: pointer;
  padding: 0;
  font-family: var(--font-body);
}
.t-toggle-track {
  width: 30px;
  height: 17px;
  border-radius: var(--radius-pill);
  background: var(--border-strong);
  position: relative;
  transition: background var(--motion-hover) var(--ease);
}
.t-toggle-thumb {
  width: 13px;
  height: 13px;
  border-radius: 50%;
  background: var(--text-primary);
  position: absolute;
  top: 2px; left: 2px;
  transition: transform var(--motion-hover) var(--ease);
}
.t-toggle.is-on .t-toggle-track { background: var(--accent); }
.t-toggle.is-on .t-toggle-thumb {
  transform: translateX(13px);
  background: var(--bg-base);
}
.t-toggle.is-disabled { opacity: 0.5; cursor: not-allowed; }
.t-toggle-label { font-size: 0.76rem; color: var(--text-primary); }
</style>
