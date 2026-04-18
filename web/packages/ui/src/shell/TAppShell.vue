<script setup lang="ts">
defineProps<{ portalAccent: string }>();
</script>

<template>
  <div
    class="t-app"
    :style="{
      '--portal-accent': portalAccent,
      '--portal-accent-soft': `color-mix(in srgb, ${portalAccent} 12%, transparent)`,
    }"
  >
    <slot name="sidebar" />
    <main class="t-app-main">
      <header class="t-topbar">
        <slot name="topbar" />
      </header>
      <div class="t-app-page">
        <slot />
      </div>
    </main>
  </div>
</template>

<style scoped>
.t-app {
  display: grid;
  grid-template-columns: var(--sidebar-w) 1fr;
  min-height: 100vh;
  color: var(--text-primary);
  background: var(--bg-base);
}

.t-app-main {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.t-topbar {
  position: sticky;
  top: 0;
  z-index: var(--z-topbar);
  height: var(--topbar-h);
  background: var(--bg-surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: 0 var(--space-4);
}

.t-app-page {
  flex: 1;
  padding: var(--space-5);
  overflow: auto;
}
</style>
