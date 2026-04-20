<script setup lang="ts">
import { computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { TButton, TStatCard, TPanel } from '@triton/ui';
import { useLicenceStore } from '../stores/licence';

const router = useRouter();
const licence = useLicenceStore();

onMounted(() => {
  void licence.fetch();
});

function reactivate() {
  router.push('/setup/license');
}

// -1 cap = "no cap configured" by the Guard contract. Render as a
// thin dash in the Cap column and skip the % utilised gauge (it would
// divide by zero anyway).
function fmtCap(cap: number): string {
  return cap < 0 ? '—' : String(cap);
}

function pct(used: number, cap: number): string {
  if (cap <= 0) return '—';
  const p = Math.round((used / cap) * 100);
  return `${p}%`;
}

// Shorten a full URL to "<host>" so the heartbeat panel stays readable
// when the licence server lives behind a long path. Gracefully falls
// back to the raw string on a non-URL input.
function shortURL(raw: string): string {
  if (!raw) return '—';
  try {
    return new URL(raw).host;
  } catch {
    return raw;
  }
}

// Heartbeat is "healthy" when we have a last_push_at AND no error AND
// consecutive_failures === 0. The error panel only surfaces when at
// least one of those signals is dirty.
const showError = computed(() => {
  const s = licence.summary;
  if (!s) return false;
  return !!s.last_push_error || s.consecutive_failures > 0;
});

// Truncate the error blob to 400 chars (matches PushStatus.vue).
const errorExcerpt = computed(() => {
  const err = licence.summary?.last_push_error ?? '';
  if (!err) return '';
  return err.length > 400 ? err.slice(0, 400) : err;
});

// Limits rows as an array so the template renders one <tr> per metric
// without duplicating markup per-field.
interface Row {
  label: string;
  cap: number;
  used: number;
  extra?: string; // optional "soft buffer: N" suffix for scans
}
const rows = computed<Row[]>(() => {
  const lim = licence.summary?.limits;
  if (!lim) return [];
  return [
    { label: 'Seats', cap: lim.seats.cap, used: lim.seats.used },
    { label: 'Hosts', cap: lim.hosts.cap, used: lim.hosts.used },
    { label: 'Agents', cap: lim.agents.cap, used: lim.agents.used },
    {
      label: 'Scans (monthly)',
      cap: lim.scans.cap,
      used: lim.scans.used,
      extra:
        lim.scans.soft_buffer_ceiling > 0
          ? `soft buffer: ${lim.scans.soft_buffer_ceiling}`
          : undefined,
    },
  ];
});
</script>

<template>
  <section class="licence-view">
    <header class="licence-head">
      <div>
        <h1>Licence</h1>
        <p class="licence-sub">
          Activation status for this Manage Server instance.
        </p>
      </div>
      <TButton
        variant="secondary"
        size="sm"
        @click="reactivate"
      >
        Re-activate
      </TButton>
    </header>

    <p
      v-if="licence.error"
      class="licence-inactive"
    >
      Licence inactive — re-activate to restore manage features.
      <span class="licence-inactive-reason">{{ licence.error }}</span>
    </p>

    <template v-if="licence.summary">
      <div class="grid">
        <TStatCard
          label="Tier"
          :value="licence.summary.tier"
        />
        <TStatCard
          label="Manage feature"
          :value="licence.summary.features.manage ? 'enabled' : 'disabled'"
        />
      </div>

      <TPanel title="Limits">
        <table class="limits">
          <thead>
            <tr>
              <th>Metric</th>
              <th>Cap</th>
              <th>Used</th>
              <th>% utilised</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="r in rows"
              :key="r.label"
            >
              <td>
                {{ r.label }}
                <span
                  v-if="r.extra"
                  class="extra"
                >{{ r.extra }}</span>
              </td>
              <td>{{ fmtCap(r.cap) }}</td>
              <td>{{ r.used }}</td>
              <td>{{ pct(r.used, r.cap) }}</td>
            </tr>
          </tbody>
        </table>
      </TPanel>

      <TPanel title="Heartbeat">
        <dl class="heartbeat">
          <dt>Last pushed</dt>
          <dd>{{ licence.summary.last_pushed_at ?? 'never' }}</dd>
          <dt>Licence server</dt>
          <dd>{{ shortURL(licence.summary.license_server_url) }}</dd>
          <dt>Instance ID</dt>
          <dd class="mono">
            {{ licence.summary.instance_id }}
          </dd>
        </dl>
      </TPanel>

      <TPanel
        v-if="showError"
        title="Push failure"
        class="licence-error-panel"
      >
        <p class="fail-count">
          Consecutive failures: <strong>{{ licence.summary.consecutive_failures }}</strong>
        </p>
        <pre
          v-if="errorExcerpt"
          class="err"
        >{{ errorExcerpt }}</pre>
      </TPanel>
    </template>
  </section>
</template>

<style scoped>
.licence-view {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-4);
}
.licence-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.licence-head h1 {
  font-family: var(--font-display);
  font-size: 1.4rem;
  margin: 0;
}
.licence-sub {
  color: var(--text-muted);
  font-size: 0.78rem;
  margin: var(--space-1) 0 0;
}
.licence-inactive {
  padding: var(--space-3);
  border: 1px solid var(--warn);
  border-radius: var(--radius);
  background: var(--bg-surface);
  color: var(--text-primary);
  font-size: 0.82rem;
  margin: 0;
}
.licence-inactive-reason {
  display: block;
  color: var(--text-muted);
  font-family: var(--font-mono);
  font-size: 0.72rem;
  margin-top: var(--space-1);
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: var(--space-3);
}
.limits {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.82rem;
}
.limits th,
.limits td {
  text-align: left;
  padding: var(--space-2) var(--space-3);
  border-bottom: 1px solid var(--border);
}
.limits th {
  color: var(--text-muted);
  font-weight: 500;
  font-size: 0.72rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.limits tbody tr:last-child td {
  border-bottom: none;
}
.extra {
  display: block;
  font-size: 0.68rem;
  color: var(--text-subtle);
  margin-top: 2px;
}
.heartbeat {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: var(--space-2) var(--space-4);
  margin: 0;
  font-size: 0.85rem;
}
.heartbeat dt {
  color: var(--text-muted);
}
.heartbeat dd {
  margin: 0;
}
.mono {
  font-family: var(--font-mono);
  font-size: 0.78rem;
}
.licence-error-panel {
  border-color: var(--unsafe, var(--warn));
}
.fail-count {
  margin: 0 0 var(--space-2);
  font-size: 0.85rem;
}
.err {
  font-family: var(--font-mono);
  font-size: 0.78rem;
  white-space: pre-wrap;
  word-break: break-all;
  color: var(--unsafe, var(--text-primary));
  margin: 0;
}
</style>
