<script setup lang="ts">
export interface NavItem {
  href: string;
  label: string;
  icon?: string;
  badge?: string;
}
export interface NavSection {
  label?: string;
  items: NavItem[];
}

defineProps<{
  nav: NavSection[];
  portalTitle: string;
  portalSubtitle: string;
  currentHref: string;
}>();
</script>

<template>
  <nav
    class="t-sidebar"
    aria-label="Primary"
  >
    <div class="t-logo">
      <div class="t-logo-img">
        T
      </div>
      <div class="t-logo-txt">
        <span class="t-logo-title">{{ portalTitle }}</span>
        <span class="t-logo-sub">{{ portalSubtitle }}</span>
      </div>
    </div>

    <div class="t-nav">
      <template
        v-for="(section, idx) in nav"
        :key="idx"
      >
        <div
          v-if="section.label"
          class="t-nav-section"
        >
          {{ section.label }}
        </div>
        <a
          v-for="item in section.items"
          :key="item.href"
          :href="item.href"
          class="t-nav-item"
          :class="{ 'is-active': item.href === currentHref }"
        >
          <span
            class="t-nav-ico"
            aria-hidden="true"
          />
          <span class="t-nav-label">{{ item.label }}</span>
          <span
            v-if="item.badge"
            class="t-nav-badge"
          >{{ item.badge }}</span>
        </a>
      </template>
    </div>

    <footer class="t-side-foot">
      <slot name="footer" />
    </footer>
  </nav>
</template>

<style scoped>
.t-sidebar {
  width: var(--sidebar-w);
  background: var(--bg-surface);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  position: fixed;
  left: 0;
  top: 0;
  bottom: 0;
  z-index: var(--z-sidebar);
}

.t-logo {
  padding: var(--space-3) var(--space-3);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: var(--space-2);
  position: relative;
}

.t-logo::before {
  content: '';
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 3px;
  background: var(--portal-accent);
}

.t-logo-img {
  width: 28px;
  height: 28px;
  border-radius: var(--radius-sm);
  background: linear-gradient(135deg, var(--portal-accent), var(--accent));
  color: var(--bg-base);
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: var(--font-display);
  font-weight: 700;
  font-size: 0.95rem;
  letter-spacing: -0.04em;
}

.t-logo-txt {
  display: flex;
  flex-direction: column;
  gap: 1px;
  line-height: 1.1;
}

.t-logo-title {
  font-family: var(--font-display);
  font-weight: 600;
  font-size: 0.96rem;
  letter-spacing: -0.02em;
  color: var(--text-primary);
}

.t-logo-sub {
  font-size: 0.56rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text-muted);
  font-weight: 500;
}

.t-nav {
  padding: var(--space-2) 0;
  flex: 1;
  overflow-y: auto;
}

.t-nav-section {
  font-size: 0.54rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--text-subtle);
  font-weight: 500;
  padding: var(--space-3) var(--space-3) var(--space-1);
}

.t-nav-item {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-2) var(--space-3);
  color: var(--text-muted);
  text-decoration: none;
  font-size: 0.76rem;
  font-weight: 400;
  border-left: 2px solid transparent;
  transition: all var(--motion-hover) var(--ease);
}

.t-nav-item:hover {
  color: var(--text-primary);
  background: color-mix(in srgb, var(--text-primary) 3%, transparent);
}

.t-nav-item:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: -2px;
}

.t-nav-item.is-active {
  color: var(--portal-accent);
  background: color-mix(in srgb, var(--portal-accent) 10%, transparent);
  border-left-color: var(--portal-accent);
  font-weight: 500;
}

.t-nav-ico {
  width: 14px;
  height: 14px;
  border-radius: 2px;
  background: currentColor;
  opacity: 0.55;
}

.t-nav-item.is-active .t-nav-ico {
  opacity: 1;
}

.t-nav-label {
  flex: 1;
}

.t-nav-badge {
  font-size: 0.58rem;
  padding: 1px var(--space-2);
  border-radius: var(--radius-pill);
  background: var(--accent-muted);
  color: var(--accent-strong);
}

.t-side-foot {
  padding: var(--space-3) var(--space-3);
  border-top: 1px solid var(--border);
}
</style>
