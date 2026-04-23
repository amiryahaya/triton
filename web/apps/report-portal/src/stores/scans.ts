import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { ScanSummary, ScanDetail, Finding } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useScansStore = defineStore('scans', () => {
  const items = ref<ScanSummary[]>([]);
  const detail = ref<ScanDetail | null>(null);
  const findings = ref<Finding[]>([]);
  const loading = ref(false);
  const detailLoading = ref(false);

  async function fetch(): Promise<void> {
    const api = useApiClient().get();
    loading.value = true;
    try {
      items.value = await api.listScans();
    } catch (e) {
      useToast().error({
        title: 'Failed to load scans',
        description: String(e),
      });
    } finally {
      loading.value = false;
    }
  }

  async function fetchDetail(id: string): Promise<void> {
    const api = useApiClient().get();
    detailLoading.value = true;
    try {
      const [d, f] = await Promise.all([api.getScan(id), api.getFindings(id)]);
      detail.value = d;
      findings.value = f;
    } catch (e) {
      useToast().error({
        title: `Failed to load scan ${id}`,
        description: String(e),
      });
    } finally {
      detailLoading.value = false;
    }
  }

  return { items, detail, findings, loading, detailLoading, fetch, fetchDetail };
});
