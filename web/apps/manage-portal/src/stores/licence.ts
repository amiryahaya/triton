import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { LicenceSummary } from '@triton/api-client';
import { useApiClient } from './apiClient';

// Pinia store for the /v1/admin/licence summary. Mirrors the backend
// wire shape 1:1 — no normalisation layer — so views read the same
// field names the Go handler emits (tier, features, limits, etc.).
//
// error is a plain message string; 503 from the backend surfaces as
// "licence inactive" and the view branches on that to show the
// re-activate nudge.
export const useLicenceStore = defineStore('licence', () => {
  const summary = ref<LicenceSummary | null>(null);
  const loading = ref(false);
  const error = ref('');

  async function fetch() {
    loading.value = true;
    error.value = '';
    try {
      summary.value = await useApiClient().get().getLicence();
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'failed to load licence';
    } finally {
      loading.value = false;
    }
  }

  return { summary, loading, error, fetch };
});
