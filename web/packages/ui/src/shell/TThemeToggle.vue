<script setup lang="ts">
import { computed } from 'vue';
import { useTheme } from '../composables/useTheme';

const { mode, resolved, setMode } = useTheme();

const icon = computed(() => {
  if (mode.value === 'system') return '◐';
  return mode.value === 'light' ? '☀' : '◑';
});

const label = computed(() => {
  if (mode.value === 'system') return `Auto (${resolved.value})`;
  return mode.value === 'light' ? 'Light' : 'Dark';
});

// Cycle: (any resolved dark) → light → system → (dark again via system)
// Keyed on resolved so 'system resolving to dark' starts the cycle correctly.
function onClick() {
  if (resolved.value === 'dark') {
    setMode('light');
  } else {
    // resolved='light': go to system (which resolves to dark per OS pref)
    setMode('system');
  }
}
</script>

<template>
  <button
    type="button"
    class="t-theme-toggle"
    :aria-label="`Theme: ${label}`"
    @click="onClick"
  >
    <span class="t-theme-ico">{{ icon }}</span>
    <span class="t-theme-label">{{ label }}</span>
  </button>
</template>

<style scoped>
.t-theme-toggle {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: var(--space-1) var(--space-2);
  border-radius: var(--radius-sm);
  background: var(--bg-base);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  font-size: 0.68rem;
  font-family: var(--font-body);
  font-weight: 500;
  cursor: pointer;
}

.t-theme-toggle:hover {
  background: var(--bg-elevated);
  color: var(--text-primary);
}

.t-theme-toggle:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: 2px;
}
</style>
