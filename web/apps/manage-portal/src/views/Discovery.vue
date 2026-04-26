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
const portsRaw = ref('22, 443, 3389, 5985, 5986');
const formError = ref('');

// Selected candidate IDs
const selected = ref<Set<string>>(new Set());

// Inline hostname edits keyed by candidate.id
const hostnameOverrides = ref<Record<string, string>>({});

// Initialise hostnameOverride when a new candidate arrives
function hostnameFor(c: DiscoveryCandidate): string {
  if (hostnameOverrides.value[c.id] !== undefined) return hostnameOverrides.value[c.id];
  return c.hostname ?? '';
}

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
    <h1 class="page-title">Network Discovery</h1>

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
    <section v-if="store.candidates.length > 0" class="results-section card">
      <h2 class="section-title">Discovered Hosts ({{ store.candidates.length }})</h2>
      <table class="results-table">
        <thead>
          <tr>
            <th class="col-check"></th>
            <th class="col-ip">IP Address</th>
            <th class="col-hostname">Hostname</th>
            <th class="col-ports">Open Ports</th>
            <th class="col-status">Status</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="c in store.candidates"
            :key="c.id"
            :class="{ 'row-existing': c.existing_host_id }"
          >
            <td class="col-check">
              <input
                type="checkbox"
                :checked="selected.has(c.id)"
                :disabled="!!c.existing_host_id"
                @change="toggleSelect(c.id, !!c.existing_host_id)"
              />
            </td>
            <td class="col-ip mono">{{ c.ip }}</td>
            <td class="col-hostname">
              <input
                v-if="!c.existing_host_id"
                type="text"
                :value="hostnameFor(c)"
                @input="hostnameOverrides[c.id] = ($event.target as HTMLInputElement).value"
                placeholder="enter hostname…"
                class="hostname-input"
              />
              <span v-else class="dimmed">{{ c.hostname ?? c.ip }}</span>
            </td>
            <td class="col-ports">
              <span v-for="p in c.open_ports" :key="p" class="port-badge">{{ p }}</span>
            </td>
            <td class="col-status">
              <span v-if="c.existing_host_id" class="badge badge-grey">Already in inventory</span>
              <span v-else class="badge badge-blue">New</span>
            </td>
          </tr>
        </tbody>
      </table>
    </section>

    <!-- Import bar (shown when done) -->
    <div v-if="store.isDone && store.candidates.length > 0" class="import-bar card">
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

.row-existing {
  opacity: 0.6;
}

.port-badge {
  display: inline-block;
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  background: var(--accent-muted, #e0e7ff);
  color: var(--accent);
  font-size: 0.75rem;
  margin-right: 0.25rem;
}

.badge {
  padding: 0.15rem 0.5rem;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 500;
}

.badge-blue {
  background: #dbeafe;
  color: #1d4ed8;
}

.badge-grey {
  background: #f1f5f9;
  color: #64748b;
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

.dimmed {
  color: var(--text-muted);
}
</style>
