import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { SettingsSummary } from '@triton/api-client';
import { useApiClient } from './apiClient';

// Pinia store for the /v1/admin/settings read-only runtime config.
// Mirrors the backend wire shape 1:1 — no normalisation — so the view
// reads the same field names the Go handler emits.
//
// This replaces the earlier static placeholder from B2.2; Batch F wired
// the real endpoint.
export const useSettingsStore = defineStore('settings', () => {
  const settings = ref<SettingsSummary | null>(null);
  const loading = ref(false);
  const error = ref('');

  async function fetch() {
    loading.value = true;
    error.value = '';
    try {
      settings.value = await useApiClient().get().getSettings();
    } catch (e) {
      error.value = e instanceof Error ? e.message : 'failed to load settings';
    } finally {
      loading.value = false;
    }
  }

  return { settings, loading, error, fetch };
});
