<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue';
import { TStatCard, TPanel } from '@triton/ui';
import { usePushStatusStore } from '../stores/pushstatus';

const ps = usePushStatusStore();

onMounted(() => ps.startPolling());
onUnmounted(() => ps.stopPolling());

function fmtAge(sec: number): string {
  if (sec < 0) return 'never';
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  return `${Math.floor(sec / 3600)}h`;
}

// Truncate the push error blob to 400 chars for display. Anything
// longer is likely a stack trace — the operator can pull the full
// error from server logs if needed.
const errorExcerpt = computed(() => {
  const err = ps.status?.last_push_error ?? '';
  if (!err) return '';
  return err.length > 400 ? err.slice(0, 400) : err;
});
</script>

<template>
  <section class="pushstatus-view">
    <header class="pushstatus-head">
      <h1>Push Status</h1>
      <p class="pushstatus-sub">
        Report-server push pipeline health. Polls every 5 seconds.
      </p>
    </header>
    <div class="grid">
      <TStatCard
        label="Queue depth"
        :value="ps.status?.queue_depth ?? '—'"
      />
      <TStatCard
        label="Oldest row"
        :value="ps.status ? fmtAge(ps.status.oldest_row_age_seconds) : '—'"
      />
      <TStatCard
        label="Consecutive failures"
        :value="ps.status?.consecutive_failures ?? 0"
      />
      <TStatCard
        label="Last pushed"
        :value="ps.status?.last_pushed_at ?? 'never'"
      />
    </div>
    <TPanel
      v-if="errorExcerpt"
      title="Last push error"
    >
      <pre class="err">{{ errorExcerpt }}</pre>
    </TPanel>
  </section>
</template>

<style scoped>
.pushstatus-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.pushstatus-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.pushstatus-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: var(--space-3);
}
.err {
  font-family: var(--font-mono);
  font-size: 0.78rem;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--unsafe, var(--text-primary));
  margin: 0;
}
</style>
