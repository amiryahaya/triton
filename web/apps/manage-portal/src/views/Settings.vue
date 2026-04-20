<script setup lang="ts">
import { onMounted } from 'vue';
import { TPanel } from '@triton/ui';
import { useSettingsStore } from '../stores/settings';

const settings = useSettingsStore();
onMounted(() => settings.fetch());
</script>

<template>
  <section class="view">
    <h1>Settings</h1>
    <div v-if="settings.loading">Loading…</div>
    <div
      v-else-if="settings.error"
      class="err"
    >
      {{ settings.error }}
    </div>
    <TPanel
      v-else-if="settings.settings"
      title="Runtime config"
    >
      <dl>
        <dt>Manage listen</dt>
        <dd class="mono">{{ settings.settings.manage_listen }}</dd>
        <dt>Gateway listen</dt>
        <dd class="mono">{{ settings.settings.gateway_listen }}</dd>
        <dt>Gateway hostname</dt>
        <dd class="mono">{{ settings.settings.gateway_hostname || '—' }}</dd>
        <dt>Report Server URL</dt>
        <dd class="mono">{{ settings.settings.report_server_url || '—' }}</dd>
        <dt>Parallelism</dt>
        <dd>{{ settings.settings.parallelism }}</dd>
        <dt>Instance ID</dt>
        <dd class="mono">{{ settings.settings.instance_id }}</dd>
        <dt>Version</dt>
        <dd class="mono">{{ settings.settings.version }}</dd>
      </dl>
    </TPanel>
  </section>
</template>

<style scoped>
.view {
  padding: var(--space-4);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
dl {
  display: grid;
  grid-template-columns: 160px 1fr;
  gap: var(--space-1) var(--space-3);
}
dt {
  color: var(--text-muted);
}
dd {
  font-family: var(--font-mono);
}
.mono {
  font-family: var(--font-mono);
}
.err {
  color: var(--danger);
}
</style>
