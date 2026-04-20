import { defineStore } from 'pinia';
import { ref } from 'vue';
import { useApiClient } from './apiClient';

export interface LicenceSummary {
  tier: string;
  features: Record<string, boolean>;
  limits: Record<string, unknown>;
  expiresAt: string | null;
  licenseServerURL: string | null;
}

export const useLicenceStore = defineStore('licence', () => {
  const summary = ref<LicenceSummary | null>(null);
  const loading = ref(false);

  async function fetch() {
    loading.value = true;
    try {
      // Licence data is embedded in /v1/me response on Manage Server.
      await useApiClient().get().me();
      // For this MVP, we expose role only; a dedicated /admin/licence
      // endpoint can back a richer summary in a follow-up. Until then
      // the view surfaces "active" when me() succeeds and "inactive"
      // otherwise.
      summary.value = {
        tier: 'active', // placeholder — see above
        features: {}, limits: {}, expiresAt: null, licenseServerURL: null,
      };
    } finally { loading.value = false; }
  }

  return { summary, loading, fetch };
});
