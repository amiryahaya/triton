import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { Agent } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useAgentsStore = defineStore('agents', () => {
  const items = ref<Agent[]>([]);
  const loading = ref(false);

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listAgents(); }
    catch (e) { useToast().error({ title: 'Failed to load agents', description: String(e) }); }
    finally { loading.value = false; }
  }

  /**
   * enrol calls /admin/enrol/agent, receives the tar.gz Blob, and
   * triggers a browser download. The private key inside the bundle is
   * never stored server-side, so we only get ONE shot — fire the
   * download synchronously in the same tick the Blob is received.
   *
   * After the download triggers, we refresh the list so the new row
   * (status=pending) appears. Returns the filename used so the caller
   * can surface it in the toast.
   */
  async function enrol(req: { name: string }): Promise<string> {
    const api = useApiClient().get();
    const blob = await api.enrolAgent(req);
    const filename = `agent-${req.name.replace(/\W+/g, '_')}-${Date.now()}.tar.gz`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
    await fetch();
    return filename;
  }

  async function revoke(id: string) {
    await useApiClient().get().revokeAgent(id);
    await fetch();
  }

  return { items, loading, fetch, enrol, revoke };
});
