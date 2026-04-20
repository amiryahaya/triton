<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue';
import { TStatCard } from '@triton/ui';
import { useDashboardStore } from '../stores/dashboard';

const dash = useDashboardStore();

onMounted(() => dash.startPolling());
onUnmounted(() => dash.stopPolling());

function fmtAge(sec: number): string {
  if (sec < 0) return 'never';
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  return `${Math.floor(sec / 3600)}h ago`;
}

// TStatCard has no `hint` prop — it exposes `delta` for the sub-line. We
// route the last-push age through `delta` (neutral direction) so the text
// still renders under the value without pulling a semantic up/down colour.
const lastPushDelta = computed(() =>
  dash.stats ? `last push: ${fmtAge(dash.stats.lastPushAgeSeconds)}` : undefined
);
</script>

<template>
  <section class="dashboard-view">
    <header class="dashboard-head">
      <h1>Dashboard</h1>
      <p class="dashboard-sub">Live overview of agents, scan jobs, and push pipeline.</p>
    </header>
    <div class="grid">
      <TStatCard
        label="Hosts"
        :value="dash.stats?.hostsCount ?? '—'"
      />
      <TStatCard
        label="Active agents"
        :value="dash.stats?.activeAgents ?? '—'"
      />
      <TStatCard
        label="Running + queued jobs"
        :value="(dash.stats?.runningJobs ?? 0) + (dash.stats?.queuedJobs ?? 0)"
      />
      <TStatCard
        label="Failed today"
        :value="dash.stats?.failedJobsToday ?? '—'"
      />
      <TStatCard
        label="Push queue"
        :value="dash.stats?.pushQueueDepth ?? '—'"
        :delta="lastPushDelta"
      />
    </div>
  </section>
</template>

<style scoped>
.dashboard-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.dashboard-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.dashboard-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: var(--space-3);
}
</style>
