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
  /* TSidebar is position:fixed so it's removed from the grid flow —
     without this explicit grid-column, the main area auto-places
     into column 1 (overlapped by the fixed sidebar) and the page
     body ends up squashed into a 256px sliver, invisible behind
     the sidebar. Pin main to column 2. */
  grid-column: 2;
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
