import { defineStore } from 'pinia';
import { ref } from 'vue';

export interface ManageSettings {
  parallelism: number;
  gatewayListen: string;
  gatewayHostname: string;
  reportServerURL: string;
  instanceID: string;
}

export const useSettingsStore = defineStore('settings', () => {
  const settings = ref<ManageSettings | null>(null);
  const loading = ref(false);

  async function fetch() {
    // No dedicated endpoint in B2.2; show a static placeholder. A
    // follow-up PR exposes GET /v1/admin/settings returning the
    // runtime config (parallelism, gateway host, etc.).
    loading.value = true;
    settings.value = {
      parallelism: 10,
      gatewayListen: ':8443',
      gatewayHostname: 'localhost',
      reportServerURL: '',
      instanceID: '',
    };
    loading.value = false;
  }

  return { settings, loading, fetch };
});
