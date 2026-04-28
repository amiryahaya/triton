<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRouter } from 'vue-router';
import { TButton, TFormField, useToast } from '@triton/ui';
import type { DiscoveryCandidate } from '@triton/api-client';
import { useDiscoveryStore } from '../stores/discovery';

const store = useDiscoveryStore();
const router = useRouter();
const toast = useToast();

// Scan form
const cidr = ref('');
const portsRaw = ref('22, 443, 3389, 5555, 5985, 5986, 8008, 8009');
const formError = ref('');

// Selected candidate IDs
const selected = ref<Set<string>>(new Set());

// Inline hostname edits keyed by candidate.id
const hostnameOverrides = ref<Record<string, string>>({});

// Initialise hostnameOverride when a new candidate arrives
function hostnameFor(c: DiscoveryCandidate): string {
  if (hostnameOverrides.value[c.id] !== undefined) return hostnameOverrides.value[c.id];
  return c.hostname ?? c.ip;
}

// Only show candidates not already in inventory.
const newCandidates = computed(() =>
  store.candidates.filter(c => !c.existing_host_id)
);

// Whether all selected candidates have a hostname (from DNS or override)
const importReady = computed(() =>
  selected.value.size > 0 &&
  [...selected.value].every(id => {
    const c = store.candidates.find(x => x.id === id);
    return c && (hostnameFor(c) !== '');
  })
);

// Parse ports from comma-separated string
function parsePorts(): number[] {
  return portsRaw.value
    .split(',')
    .map(s => parseInt(s.trim(), 10))
    .filter(n => !isNaN(n) && n > 0 && n <= 65535);
}

async function onStart() {
  formError.value = '';
  if (!cidr.value.trim()) { formError.value = 'CIDR is required'; return; }
  try {
    await store.start(cidr.value.trim(), parsePorts());
  } catch {
    // error already set in store
  }
}

async function onStop() {
  await store.cancel();
}

function toggleSelect(id: string, isExisting: boolean) {
  if (isExisting) return;
  if (selected.value.has(id)) selected.value.delete(id);
  else selected.value.add(id);
}

async function onImport() {
  const items = [...selected.value].map(id => {
    const c = store.candidates.find(x => x.id === id)!;
    return { id, hostname: hostnameFor(c) };
  });
  try {
    const result = await store.importCandidates(items);
    toast.success({
      title: `Imported ${result.imported} host${result.imported === 1 ? '' : 's'}`,
      description: result.skipped > 0 ? `${result.skipped} already in inventory` : undefined,
    });
    await router.push('/inventory/hosts');
  } catch (e) {
    toast.error({ title: 'Import failed', description: String(e) });
  }
}

onMounted(() => store.load());
onUnmounted(() => store.stopPolling());
</script>

<template>
  <div class="discovery-page">
    <div class="discovery-header">
      <TButton variant="secondary" size="sm" @click="router.push('/inventory/hosts')">
        ← Back to Hosts
      </TButton>
      <h1 class="page-title">Network Discovery</h1>
    </div>

    <!-- Error banner (failed job) -->
    <div v-if="store.job?.status === 'failed'" class="alert-error">
      <span>Scan failed: {{ store.job.error_message }}</span>
      <TButton variant="secondary" @click="store.job = null">Dismiss</TButton>
    </div>

    <!-- Scan form -->
    <section class="scan-form card">
      <TFormField label="CIDR Range" :error="formError">
        <input
          v-model="cidr"
          type="text"
          placeholder="192.168.1.0/24"
          :disabled="store.isRunning"
          class="text-input"
        />
      </TFormField>
      <TFormField label="Ports">
        <input
          v-model="portsRaw"
          type="text"
          placeholder="22, 443, 3389"
          :disabled="store.isRunning"
          class="text-input"
        />
      </TFormField>
      <div class="form-actions">
        <TButton v-if="!store.isRunning" variant="primary" @click="onStart" :loading="store.loading">
          Start Scan
        </TButton>
        <TButton v-else variant="danger" @click="onStop">Stop Scan</TButton>
      </div>
    </section>

    <!-- Progress (running) -->
    <section v-if="store.isRunning" class="progress-section card">
      <div class="progress-label">
        Scanning: {{ store.job?.scanned_ips?.toLocaleString() }} / {{ store.job?.total_ips?.toLocaleString() }} IPs
      </div>
      <progress class="progress-bar" :value="store.progress" max="1" />
    </section>

    <!-- Results table -->
    <section v-if="newCandidates.length > 0" class="results-section card">
      <h2 class="section-title">New Hosts ({{ newCandidates.length }})</h2>
      <table class="results-table">
        <thead>
          <tr>
            <th class="col-check"></th>
            <th class="col-ip">IP Address</th>
            <th class="col-mac">MAC</th>
            <th class="col-mdns">mDNS Name</th>
            <th class="col-hostname">Hostname</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="c in newCandidates"
            :key="c.id"
          >
            <td class="col-check">
              <input
                type="checkbox"
                :checked="selected.has(c.id)"
                @change="toggleSelect(c.id, false)"
              />
            </td>
            <td class="col-ip mono">{{ c.ip }}</td>
            <td class="col-mac mono">{{ c.mac_address || '—' }}</td>
            <td class="col-mdns">{{ c.mdns_name || '—' }}</td>
            <td class="col-hostname">
              <input
                type="text"
                :value="hostnameFor(c)"
                @input="hostnameOverrides[c.id] = ($event.target as HTMLInputElement).value"
                placeholder="hostname or IP"
                class="hostname-input"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </section>
    <section v-else-if="store.isDone && store.candidates.length > 0" class="results-section card">
      <p class="all-known">All discovered hosts are already in inventory.</p>
    </section>

    <!-- Import bar (shown when done) -->
    <div v-if="store.isDone && newCandidates.length > 0" class="import-bar card">
      <span class="import-count">{{ selected.size }} host{{ selected.size === 1 ? '' : 's' }} selected</span>
      <TButton variant="primary" :disabled="!importReady" @click="onImport">
        Import Selected
      </TButton>
    </div>
  </div>
</template>

<style scoped>
.discovery-page {
  max-width: 1000px;
  margin: 0 auto;
  padding: 1.5rem;
}

.discovery-header {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.discovery-header .page-title {
  margin-bottom: 0;
}

.page-title {
  font-size: 1.5rem;
  font-weight: 600;
  margin-bottom: 1.5rem;
}

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 0.5rem;
  padding: 1.25rem;
  margin-bottom: 1rem;
}

.scan-form .form-actions {
  margin-top: 1rem;
}

.text-input {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: 0.375rem;
  background: var(--bg);
  color: var(--text);
  font-size: 0.875rem;
}

.progress-bar {
  width: 100%;
  height: 12px;
  border-radius: 6px;
}

.progress-label {
  font-size: 0.875rem;
  color: var(--text-muted);
  margin-bottom: 0.5rem;
}

.section-title {
  font-size: 1rem;
  font-weight: 600;
  margin-bottom: 1rem;
}

.results-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

th,
td {
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid var(--border);
  text-align: left;
}

.mono {
  font-family: monospace;
}

.all-known {
  color: var(--text-muted);
  font-size: 0.875rem;
  margin: 0;
}


.hostname-input {
  width: 100%;
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 0.2rem 0.4rem;
  font-size: 0.875rem;
  background: var(--bg);
}

.import-bar {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.import-count {
  color: var(--text-muted);
  font-size: 0.875rem;
}

.alert-error {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 0.75rem 1rem;
  background: #fee2e2;
  border: 1px solid #fca5a5;
  border-radius: 0.5rem;
  margin-bottom: 1rem;
  color: #991b1b;
}

.col-mac { min-width: 140px; font-size: 0.8rem; }
.col-mdns { min-width: 140px; }

</style>
