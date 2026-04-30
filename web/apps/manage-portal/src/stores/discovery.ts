import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import type { DiscoveryJob, DiscoveryCandidate } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useDiscoveryStore = defineStore('discovery', () => {
  const job = ref<DiscoveryJob | null>(null);
  const candidates = ref<DiscoveryCandidate[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  const isRunning = computed(() =>
    job.value?.status === 'running' || job.value?.status === 'queued'
  );
  const isDone = computed(() =>
    ['completed', 'failed', 'cancelled'].includes(job.value?.status ?? '')
  );
  const progress = computed(() => {
    if (!job.value || job.value.total_ips === 0) return 0;
    return job.value.scanned_ips / job.value.total_ips;
  });

  async function load() {
    const api = useApiClient().get();
    loading.value = true;
    error.value = null;
    try {
      const status = await api.getDiscovery();
      job.value = status.job;
      candidates.value = status.candidates;
      if (isRunning.value) startPolling();
    } catch (e: unknown) {
      // 404 means no job yet — not an error
      if (isHttpError(e, 404)) {
        job.value = null;
        candidates.value = [];
      } else {
        error.value = String(e);
      }
    } finally {
      loading.value = false;
    }
  }

  async function start(cidr: string, sshPort: number) {
    const api = useApiClient().get();
    error.value = null;
    try {
      job.value = await api.startDiscovery({ cidr, ssh_port: sshPort });
      candidates.value = [];
      startPolling();
    } catch (e: unknown) {
      const msg = extractErrorMessage(e) ?? 'Failed to start discovery';
      error.value = msg;
      useToast().error({ title: 'Scan failed to start', description: msg });
      throw e;
    }
  }

  async function cancel() {
    const api = useApiClient().get();
    try {
      await api.cancelDiscovery();
    } catch (e: unknown) {
      useToast().error({ title: 'Cancel failed', description: String(e) });
    }
  }

  async function importCandidates(items: { id: string; hostname: string }[]) {
    const api = useApiClient().get();
    return api.importDiscovery({ candidates: items });
  }

  function startPolling() {
    if (pollTimer !== null) return;
    pollTimer = setInterval(async () => {
      try {
        const status = await useApiClient().get().getDiscovery();
        job.value = status.job;
        candidates.value = status.candidates;
        if (!isRunning.value) stopPolling();
      } catch {
        // silently ignore transient poll errors
      }
    }, 2000);
  }

  function stopPolling() {
    if (pollTimer !== null) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  // Utility: check if an error is an HTTP error with a given status code.
  // The api-client typically throws objects with a `status` field.
  function isHttpError(e: unknown, status: number): boolean {
    return typeof e === 'object' && e !== null && (e as Record<string, unknown>).status === status;
  }

  function extractErrorMessage(e: unknown): string | null {
    if (typeof e === 'object' && e !== null) {
      const obj = e as Record<string, unknown>;
      if (typeof obj.message === 'string') return obj.message;
      if (typeof obj.error === 'string') return obj.error;
    }
    return null;
  }

  return {
    job, candidates, loading, error,
    isRunning, isDone, progress,
    load, start, cancel, importCandidates,
    startPolling, stopPolling,
  };
});
