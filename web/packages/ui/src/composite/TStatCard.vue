<script setup lang="ts">
withDefaults(
  defineProps<{
    label: string;
    value: string | number;
    delta?: string;
    deltaDir?: 'up' | 'down' | 'neutral';
    accent?: string;
  }>(),
  { deltaDir: 'neutral', delta: undefined, accent: undefined }
);
</script>

<template>
  <div
    class="t-stat-card"
    :style="accent ? { '--stat-accent': accent } : undefined"
  >
    <div class="t-stat-label">
      {{ label }}
    </div>
    <div class="t-stat-value">
      {{ value }}
    </div>
    <div
      v-if="delta"
      class="t-stat-delta"
      :class="`is-${deltaDir}`"
    >
      {{ delta }}
    </div>
  </div>
</template>

<style scoped>
.t-stat-card {
  position: relative;
  padding: var(--space-3) var(--space-4);
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}
.t-stat-card::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 2px;
  background: var(--stat-accent, var(--accent-strong));
  opacity: 0.7;
}
.t-stat-label {
  font-size: 0.58rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text-subtle);
  font-weight: 500;
  font-family: var(--font-body);
}
.t-stat-value {
  font-family: var(--font-display);
  font-size: 1.85rem;
  font-weight: 600;
  letter-spacing: -0.03em;
  font-variant-numeric: tabular-nums;
  color: var(--text-primary);
  line-height: 1.05;
  margin: 2px 0 3px;
}
.t-stat-delta {
  font-size: 0.66rem;
  font-weight: 500;
  color: var(--text-muted);
}
.t-stat-delta.is-up { color: var(--safe); }
.t-stat-delta.is-down { color: var(--warn); }
</style>
