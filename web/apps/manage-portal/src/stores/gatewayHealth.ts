import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { GatewayHealthResponse } from '@triton/api-client';
import { useApiClient } from './apiClient';

// Polls GET /v1/admin/gateway-health every 60 s (skipping when the tab
// is hidden) and exposes the raw response as `state`. The cert warning
// pill in App.vue reads cert_days_remaining and hides the pill when the
// fetch fails — non-fatal, swallowed in the catch block.
export const useGatewayHealthStore = defineStore('gatewayHealth', () => {
  const state = ref<GatewayHealthResponse | null>(null);
  const loading = ref(false);
  let pollHandle: number | null = null;

  async function fetch() {
    loading.value = true;
    try {
      state.value = await useApiClient().get().getGatewayHealth();
    } catch (e) {
      // Non-fatal — the pill just hides. Log in dev so a misconfigured
      // endpoint or broken auth token is detectable.
      if (import.meta.env.DEV) console.warn('[gatewayHealth] fetch failed:', e);
    } finally {
      loading.value = false;
    }
  }

  function startPolling() {
    if (pollHandle !== null) return;
    fetch();
    pollHandle = window.setInterval(() => {
      if (document.hidden) return;
      fetch();
    }, 60_000);
  }

  function stopPolling() {
    if (pollHandle !== null) {
      clearInterval(pollHandle);
      pollHandle = null;
    }
  }

  return { state, loading, fetch, startPolling, stopPolling };
});
