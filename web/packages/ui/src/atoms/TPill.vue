<script setup lang="ts">
import TDot from './TDot.vue';

export type PillVariant =
  | 'safe' | 'warn' | 'deprecated' | 'unsafe'
  | 'info' | 'neutral' | 'enterprise';

withDefaults(
  defineProps<{ variant?: PillVariant; dot?: boolean }>(),
  { variant: 'neutral', dot: true }
);
</script>

<template>
  <span
    class="t-pill"
    :class="`t-pill--${variant}`"
  >
    <TDot v-if="dot" />
    <slot />
  </span>
</template>

<style scoped>
.t-pill {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: 2px var(--space-2);
  border-radius: var(--radius-pill);
  font-size: 0.66rem;
  font-weight: 500;
  border: 1px solid transparent;
  font-family: var(--font-body);
  line-height: 1.4;
}
.t-pill--safe       { color: var(--safe);       background: var(--safe-muted);       border-color: var(--safe); }
.t-pill--warn       { color: var(--warn);       background: var(--warn-muted);       border-color: var(--warn); }
.t-pill--deprecated { color: var(--deprecated); background: var(--deprecated-muted); border-color: var(--deprecated); }
.t-pill--unsafe     { color: var(--unsafe);     background: var(--unsafe-muted);     border-color: var(--unsafe); }
.t-pill--info       { color: var(--accent-strong); background: var(--accent-muted);  border-color: var(--accent-strong); }
.t-pill--neutral    { color: var(--text-muted); background: var(--bg-elevated);      border-color: var(--border); }
.t-pill--enterprise { color: var(--violet-text); background: var(--violet-soft);      border-color: var(--violet-border); }
</style>
