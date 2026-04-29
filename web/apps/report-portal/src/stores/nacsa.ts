import { defineStore } from 'pinia';
import { ref, reactive } from 'vue';
import type {
  NacsaSummary, NacsaServerRow, NacsaHostRow,
  NacsaCBOMRow, NacsaRiskRow, NacsaMigResponse,
} from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export interface NacsaDrillScope {
  manageServerId: string;
  manageServerName: string;
  hostname: string;
}

export const useNacsaStore = defineStore('nacsa', () => {
  // Drill scope — shared breadcrumb state
  const scope = reactive<NacsaDrillScope>({
    manageServerId: '',
    manageServerName: '',
    hostname: '',
  });

  // Data refs
  const summary = ref<NacsaSummary | null>(null);
  const servers = ref<NacsaServerRow[]>([]);
  const hosts = ref<NacsaHostRow[]>([]);
  const cbom = ref<NacsaCBOMRow[]>([]);
  const risk = ref<NacsaRiskRow[]>([]);
  const migration = ref<NacsaMigResponse | null>(null);

  // Counter-based loading flag: true whenever any fetch is in-flight.
  const loading = ref(false);
  let _pending = 0;
  function _startLoad() { _pending++; loading.value = true; }
  function _endLoad() { if (--_pending <= 0) { _pending = 0; loading.value = false; } }

  function drillToServer(id: string, name: string) {
    scope.manageServerId = id;
    scope.manageServerName = name;
    scope.hostname = '';
    hosts.value = [];
  }

  function drillToHost(hostname: string) {
    scope.hostname = hostname;
    cbom.value = [];
    risk.value = [];
  }

  function clearDrill() {
    scope.manageServerId = '';
    scope.manageServerName = '';
    scope.hostname = '';
    hosts.value = [];
    cbom.value = [];
    risk.value = [];
  }

  async function fetchSummary() {
    const api = useApiClient().get();
    _startLoad();
    try {
      summary.value = await api.nacsaSummary({
        manage_server_id: scope.manageServerId || undefined,
        hostname: scope.hostname || undefined,
      });
    } catch (e) {
      useToast().error({ title: 'Failed to load NACSA summary', description: String(e) });
    } finally {
      _endLoad();
    }
  }

  async function fetchServers() {
    const api = useApiClient().get();
    _startLoad();
    try {
      servers.value = await api.nacsaServers();
    } catch (e) {
      useToast().error({ title: 'Failed to load servers', description: String(e) });
    } finally {
      _endLoad();
    }
  }

  async function fetchHosts() {
    if (!scope.manageServerId) { hosts.value = []; return; }
    const api = useApiClient().get();
    _startLoad();
    try {
      hosts.value = await api.nacsaHosts(scope.manageServerId);
    } catch (e) {
      useToast().error({ title: 'Failed to load hosts', description: String(e) });
    } finally {
      _endLoad();
    }
  }

  async function fetchCBOM(statusFilter?: string) {
    if (!scope.hostname) { cbom.value = []; return; }
    const api = useApiClient().get();
    _startLoad();
    try {
      cbom.value = await api.nacsaCBOM(scope.hostname, { status: statusFilter });
    } catch (e) {
      useToast().error({ title: 'Failed to load CBOM', description: String(e) });
    } finally {
      _endLoad();
    }
  }

  async function fetchRisk(sortBy?: string) {
    if (!scope.hostname) { risk.value = []; return; }
    const api = useApiClient().get();
    _startLoad();
    try {
      risk.value = await api.nacsaRisk(scope.hostname, { sort: sortBy });
    } catch (e) {
      useToast().error({ title: 'Failed to load risk', description: String(e) });
    } finally {
      _endLoad();
    }
  }

  async function fetchMigration() {
    const api = useApiClient().get();
    _startLoad();
    try {
      migration.value = await api.nacsaMigration();
    } catch (e) {
      useToast().error({ title: 'Failed to load migration', description: String(e) });
    } finally {
      _endLoad();
    }
  }

  return {
    scope, summary, servers, hosts, cbom, risk, migration, loading,
    drillToServer, drillToHost, clearDrill,
    fetchSummary, fetchServers, fetchHosts, fetchCBOM, fetchRisk, fetchMigration,
  };
});
