<script setup lang="ts">
import { computed } from 'vue';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg';

const props = withDefaults(
  defineProps<{
    variant?: ButtonVariant;
    size?: ButtonSize;
    disabled?: boolean;
    type?: 'button' | 'submit' | 'reset';
  }>(),
  { variant: 'primary', size: 'md', disabled: false, type: 'button' }
);

const emit = defineEmits<{ click: [ev: MouseEvent] }>();

const classes = computed(() => ({
  [`t-btn--${props.variant}`]: true,
  [`t-btn--${props.size}`]: true,
  'is-disabled': props.disabled,
}));

function onClick(ev: MouseEvent) {
  if (props.disabled) return;
  emit('click', ev);
}
</script>

<template>
  <button
    class="t-btn"
    :class="classes"
    :type="type"
    :disabled="disabled"
    @click="onClick"
  >
    <slot />
  </button>
</template>

<style scoped>
.t-btn {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  font-family: var(--font-body);
  font-weight: 500;
  cursor: pointer;
  transition:
    background var(--motion-hover) var(--ease),
    color var(--motion-hover) var(--ease),
    border-color var(--motion-hover) var(--ease);
}
.t-btn:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: 2px;
}

.t-btn--sm { padding: var(--space-1) var(--space-3); font-size: 0.7rem; }
.t-btn--md { padding: var(--space-2) var(--space-4); font-size: 0.78rem; }
.t-btn--lg { padding: var(--space-3) var(--space-5); font-size: 0.85rem; }

.t-btn--primary {
  background: var(--accent);
  color: var(--bg-base);
  box-shadow: 0 0 0 1px var(--accent-muted), 0 2px 8px var(--accent-muted);
}
.t-btn--primary:hover:not(.is-disabled) { background: var(--accent-strong); }

.t-btn--secondary {
  background: var(--bg-elevated);
  color: var(--text-primary);
  border-color: var(--border-strong);
}
.t-btn--secondary:hover:not(.is-disabled) { background: var(--bg-hover); }

.t-btn--ghost {
  background: transparent;
  color: var(--text-muted);
}
.t-btn--ghost:hover:not(.is-disabled) {
  color: var(--text-primary);
  background: var(--accent-muted);
}

.t-btn--danger {
  background: var(--unsafe-muted);
  color: var(--unsafe);
  border-color: var(--unsafe);
}
.t-btn--danger:hover:not(.is-disabled) {
  background: var(--unsafe);
  color: var(--bg-base);
}

.is-disabled { opacity: 0.4; cursor: not-allowed; }
</style>
