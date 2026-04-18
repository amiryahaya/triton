<script setup lang="ts">
withDefaults(
  defineProps<{ title: string; subtitle?: string }>(),
  { subtitle: undefined }
);
</script>

<template>
  <section class="t-panel">
    <header class="t-panel-head">
      <h3 class="t-panel-title">
        {{ title }}
      </h3>
      <span
        v-if="subtitle"
        class="t-panel-sub"
      >{{ subtitle }}</span>
      <span class="t-panel-action"><slot name="action" /></span>
    </header>
    <div class="t-panel-body">
      <slot />
    </div>
  </section>
</template>

<style scoped>
.t-panel {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}
.t-panel-head {
  padding: var(--space-3) var(--space-4);
  display: flex;
  align-items: center;
  gap: var(--space-2);
  border-bottom: 1px solid var(--border);
}
.t-panel-title {
  font-family: var(--font-display);
  font-size: 0.88rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--text-primary);
  margin: 0;
}
.t-panel-sub {
  font-size: 0.66rem;
  color: var(--text-subtle);
  margin-left: 2px;
}
.t-panel-action {
  margin-left: auto;
  font-size: 0.66rem;
  color: var(--accent-strong);
  font-weight: 500;
  cursor: pointer;
}
.t-panel-body { padding: var(--space-4); }
</style>
