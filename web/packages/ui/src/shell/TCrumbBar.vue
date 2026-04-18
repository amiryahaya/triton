<script setup lang="ts">
export interface Crumb { label: string; href?: string }
defineProps<{ crumbs: Crumb[] }>();
</script>

<template>
  <nav
    class="t-crumb-bar"
    aria-label="Breadcrumb"
  >
    <template
      v-for="(c, i) in crumbs"
      :key="i"
    >
      <a
        v-if="c.href && i !== crumbs.length - 1"
        :href="c.href"
        class="t-crumb"
      >{{ c.label }}</a>
      <strong
        v-else
        class="t-crumb is-current"
      >{{ c.label }}</strong>
      <span
        v-if="i !== crumbs.length - 1"
        class="t-crumb-sep"
      >›</span>
    </template>
  </nav>
</template>

<style scoped>
.t-crumb-bar {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  font-size: 0.72rem;
  color: var(--text-muted);
}

.t-crumb {
  color: var(--text-muted);
  text-decoration: none;
  border-radius: var(--radius-sm);
}

.t-crumb:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: 2px;
}

.t-crumb.is-current {
  color: var(--text-primary);
  font-weight: 500;
}

.t-crumb-sep {
  color: var(--border-strong);
}
</style>
