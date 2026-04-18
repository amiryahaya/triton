<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';

export interface AppEntry {
  id: string;
  name: string;
  subtitle: string;
  url: string | null;
  accent: string;
}

defineProps<{
  apps: AppEntry[];
  currentId: string;
}>();

const open = ref(false);
const root = ref<HTMLElement | null>(null);

function toggle() { open.value = !open.value; }
function close(ev?: MouseEvent) {
  if (!ev || !root.value?.contains(ev.target as Node)) open.value = false;
}

onMounted(() => document.addEventListener('click', close));
onUnmounted(() => document.removeEventListener('click', close));
</script>

<template>
  <div
    ref="root"
    class="t-app-switcher"
  >
    <button
      type="button"
      class="t-app-trigger"
      aria-label="Switch portal"
      :aria-expanded="open"
      @click="toggle"
    >
      <svg
        width="16"
        height="16"
        viewBox="0 0 16 16"
        aria-hidden="true"
      >
        <g fill="currentColor">
          <rect
            x="2"
            y="2"
            width="3"
            height="3"
            rx="0.5"
          />
          <rect
            x="6.5"
            y="2"
            width="3"
            height="3"
            rx="0.5"
          />
          <rect
            x="11"
            y="2"
            width="3"
            height="3"
            rx="0.5"
          />
          <rect
            x="2"
            y="6.5"
            width="3"
            height="3"
            rx="0.5"
          />
          <rect
            x="6.5"
            y="6.5"
            width="3"
            height="3"
            rx="0.5"
          />
          <rect
            x="11"
            y="6.5"
            width="3"
            height="3"
            rx="0.5"
          />
          <rect
            x="2"
            y="11"
            width="3"
            height="3"
            rx="0.5"
          />
          <rect
            x="6.5"
            y="11"
            width="3"
            height="3"
            rx="0.5"
          />
          <rect
            x="11"
            y="11"
            width="3"
            height="3"
            rx="0.5"
          />
        </g>
      </svg>
    </button>

    <Teleport to="body">
      <div
        v-if="open"
        class="t-app-menu"
        role="menu"
      >
        <div class="t-app-grid">
          <a
            v-for="app in apps"
            :key="app.id"
            :href="app.url ?? '#'"
            class="t-app-tile"
            :class="{
              'is-current': app.id === currentId,
              'is-disabled': !app.url,
            }"
            :style="{ '--tile-accent': app.accent }"
            @click="!app.url && $event.preventDefault()"
          >
            <span class="t-app-swatch" />
            <span class="t-app-name">{{ app.name }}</span>
            <span class="t-app-sub">{{ app.subtitle }}</span>
          </a>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.t-app-switcher {
  position: relative;
  display: inline-block;
}

.t-app-trigger {
  width: 26px;
  height: 26px;
  border-radius: var(--radius-sm);
  background: var(--bg-base);
  border: 1px solid var(--border);
  color: var(--text-muted);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
}

.t-app-trigger:hover {
  color: var(--text-primary);
}

.t-app-trigger:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: 2px;
}

.t-app-menu {
  position: fixed;
  top: calc(var(--topbar-h) + 4px);
  right: var(--space-3);
  z-index: var(--z-modal);
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  padding: var(--space-2);
  box-shadow: var(--shadow-lg);
}

.t-app-grid {
  display: grid;
  grid-template-columns: repeat(3, 90px);
  gap: var(--space-1);
}

.t-app-tile {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  padding: var(--space-2);
  border-radius: var(--radius-sm);
  background: var(--bg-elevated);
  color: var(--text-primary);
  text-decoration: none;
  border: 1px solid transparent;
  position: relative;
}

.t-app-tile:hover:not(.is-disabled) {
  background: var(--bg-hover);
}

.t-app-tile:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: 2px;
}

.t-app-tile.is-current {
  border-color: var(--tile-accent);
}

.t-app-tile.is-disabled {
  opacity: 0.35;
  cursor: not-allowed;
}

.t-app-swatch {
  width: 8px;
  height: 8px;
  border-radius: 2px;
  background: var(--tile-accent);
}

.t-app-name {
  font-family: var(--font-display);
  font-size: 0.82rem;
  font-weight: 600;
  letter-spacing: -0.01em;
}

.t-app-sub {
  font-size: 0.58rem;
  color: var(--text-muted);
}
</style>
