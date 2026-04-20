<script setup lang="ts">
import { onMounted } from 'vue';
import { useSettingsStore } from '../stores/settings';

const settings = useSettingsStore();

onMounted(() => {
  void settings.fetch();
});
</script>

<template>
  <section class="settings-view">
    <header class="settings-head">
      <div>
        <h1>Settings</h1>
        <p class="settings-sub">
          Runtime configuration for this Manage Server instance.
          Read-only in this release.
        </p>
      </div>
    </header>

    <div class="settings-panel">
      <dl
        v-if="settings.settings"
        class="settings-dl"
      >
        <dt>Parallelism</dt>
        <dd>{{ settings.settings.parallelism }}</dd>
        <dt>Gateway listen</dt>
        <dd>
          <code>{{ settings.settings.gatewayListen }}</code>
        </dd>
        <dt>Gateway hostname</dt>
        <dd>
          <code>{{ settings.settings.gatewayHostname }}</code>
        </dd>
        <dt>Report server URL</dt>
        <dd>
          <code v-if="settings.settings.reportServerURL">{{ settings.settings.reportServerURL }}</code>
          <span
            v-else
            class="settings-none"
          >—</span>
        </dd>
        <dt>Instance ID</dt>
        <dd>
          <code v-if="settings.settings.instanceID">{{ settings.settings.instanceID }}</code>
          <span
            v-else
            class="settings-none"
          >—</span>
        </dd>
      </dl>
      <p
        v-else
        class="settings-loading"
      >
        Loading…
      </p>
      <p class="settings-note">
        A follow-up PR exposes <code>GET /v1/admin/settings</code> so
        operators can edit these values in-portal. Today, changes
        require a restart with updated environment variables.
      </p>
    </div>
  </section>
</template>

<style scoped>
.settings-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.settings-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.settings-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.settings-panel {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: var(--space-4);
  background: var(--bg-surface);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.settings-dl {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: var(--space-2) var(--space-4);
  margin: 0;
  font-size: 0.85rem;
}
.settings-dl dt {
  color: var(--text-muted);
}
.settings-dl dd {
  margin: 0;
}
.settings-dl code {
  font-family: var(--font-mono);
  font-size: 0.78rem;
  padding: 1px 4px;
  background: var(--bg-code, var(--bg));
  border-radius: var(--radius-sm);
}
.settings-none {
  color: var(--text-muted);
}
.settings-loading {
  margin: 0;
  color: var(--text-muted);
  font-size: 0.82rem;
}
.settings-note {
  margin: 0;
  color: var(--text-muted);
  font-size: 0.78rem;
  line-height: 1.5;
}
.settings-note code {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  padding: 1px 4px;
  background: var(--bg-code, var(--bg));
  border-radius: var(--radius-sm);
}
</style>
