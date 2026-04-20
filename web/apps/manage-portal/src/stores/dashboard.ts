import { defineStore } from 'pinia';
import { ref } from 'vue';
import { useApiClient } from './apiClient';

export interface DashboardStats {
  hostsCount: number;
  activeAgents: number;
  runningJobs: number;
  queuedJobs: number;
  failedJobsToday: number;
  pushQueueDepth: number;
  lastPushAgeSeconds: number;
}

export const useDashboardStore = defineStore('dashboard', () => {
  const stats = ref<DashboardStats | null>(null);
  const loading = ref(false);
  let pollHandle: number | null = null;

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try {
      const [hosts, agents, jobs, push] = await Promise.all([
        api.listHosts(),
        api.listAgents(),
        api.listScanJobs({ limit: 500 }),
        api.getPushStatus(),
      ]);
      const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
      const failedToday = jobs.filter(j =>
        j.status === 'failed' && j.finished_at && new Date(j.finished_at) >= todayStart
      ).length;
      stats.value = {
        hostsCount: hosts.length,
        activeAgents: agents.filter(a => a.status === 'active').length,
        runningJobs: jobs.filter(j => j.status === 'running').length,
        queuedJobs: jobs.filter(j => j.status === 'queued').length,
        failedJobsToday: failedToday,
        pushQueueDepth: push.queue_depth,
        lastPushAgeSeconds: push.last_pushed_at
          ? Math.floor((Date.now() - new Date(push.last_pushed_at).getTime()) / 1000)
          : -1,
      };
    } finally { loading.value = false; }
  }

  function startPolling() {
    if (pollHandle) return;
    fetch();
    pollHandle = window.setInterval(() => {
      if (document.hidden) return;
      fetch();
    }, 5000);
  }
  function stopPolling() {
    if (pollHandle) { clearInterval(pollHandle); pollHandle = null; }
  }

  return { stats, loading, fetch, startPolling, stopPolling };
});
