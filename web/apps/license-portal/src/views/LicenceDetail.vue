<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';
import {
  TStatCard, TPanel, TButton, TConfirmDialog, TPill, TDataTable,
  useToast, type Column, type PillVariant,
} from '@triton/ui';
import type { Licence, Activation } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const route = useRoute();
const id = computed(() => String(route.params.id));

const licence = ref<Licence | null>(null);
const activations = ref<Activation[]>([]);
const revokeOpen = ref(false);

interface ActRow {
  id: string;
  hostname: string;
  activationType: string;
  displayName: string;
  machineIDShort: string;
  platform: string;
  activatedAt: string;
  lastSeenAt: string;
  active: boolean;
  [key: string]: unknown;
}

const actColumns: Column<ActRow>[] = [
  { key: 'hostname',       label: 'Hostname',   width: '1.2fr' },
  { key: 'activationType', label: 'Type',       width: '110px' },
  { key: 'displayName',    label: 'Name',       width: '1fr'   },
  { key: 'machineIDShort', label: 'Machine ID', width: '1fr'   },
  { key: 'platform',       label: 'OS/Arch',    width: '0.8fr' },
  { key: 'activatedAt',    label: 'Activated',  width: '1fr'   },
  { key: 'lastSeenAt',     label: 'Last seen',  width: '1fr'   },
  { key: 'active',         label: 'Status',     width: '100px' },
];

const actRows = computed<ActRow[]>(() =>
  activations.value.map((a) => ({
    id:             a.id,
    hostname:       a.hostname,
    activationType: a.activationType,
    displayName:    a.displayName,
    machineIDShort: a.machineID.slice(0, 12),
    platform:       `${a.os}/${a.arch}`,
    activatedAt:    a.activatedAt,
    lastSeenAt:     a.lastSeenAt,
    active:         a.active,
  })),
);

const status = computed(() => {
  if (!licence.value) return 'Active' as const;
  if (licence.value.revoked) return 'Revoked' as const;
  if (new Date(licence.value.expiresAt).getTime() < Date.now())
    return 'Expired' as const;
  return 'Active' as const;
});

function statusVariant(s: string): PillVariant {
  if (s === 'Active') return 'safe';
  if (s === 'Revoked') return 'unsafe';
  return 'warn';
}

function daysRemaining(expiresAt: string): number {
  return Math.max(
    0,
    Math.floor((new Date(expiresAt).getTime() - Date.now()) / 864e5),
  );
}

async function load() {
  try {
    const [l, a] = await Promise.all([
      api.get().licence(id.value),
      api.get().activations(id.value),
    ]);
    licence.value = l;
    activations.value = a;
  } catch (err) {
    toast.error({ title: 'Load failed', description: String(err) });
  }
}

onMounted(load);

async function revoke() {
  try {
    await api.get().revokeLicence(id.value);
    toast.success({ title: 'Licence revoked' });
    revokeOpen.value = false;
    await load();
  } catch (err) {
    toast.error({ title: 'Revoke failed', description: String(err) });
  }
}

async function copyID() {
  if (!licence.value) return;
  await navigator.clipboard.writeText(licence.value.id);
  toast.success({ title: 'Licence ID copied' });
}

const visibleLimits = computed(() => licence.value?.limits ?? []);
</script>

<template>
  <div
    v-if="licence"
    class="detail"
  >
    <section class="head">
      <div class="head-body">
        <div class="label">Licence ID</div>
        <div class="key">{{ licence.id }}</div>
        <div class="meta">
          <span>Org <b>{{ licence.orgName }}</b></span>
          <span>Tier <b>{{ licence.tier }}</b></span>
          <span>Scope <b>{{ licence.product_scope }}</b></span>
          <span>Issued <b>{{ licence.issuedAt }}</b></span>
          <span>Expires <b>{{ licence.expiresAt }}</b></span>
          <span>Status
            <TPill :variant="statusVariant(status)">{{ status }}</TPill>
          </span>
        </div>
      </div>
      <div class="actions">
        <TButton size="sm" variant="secondary" @click="copyID">
          Copy licence ID
        </TButton>
        <TButton
          size="sm"
          variant="danger"
          :disabled="licence.revoked"
          @click="revokeOpen = true"
        >
          Revoke
        </TButton>
      </div>
    </section>

    <div class="stats">
      <TStatCard
        label="Seats used"
        :value="`${licence.seatsUsed} / ${licence.seats === 0 ? '∞' : licence.seats}`"
        accent="var(--violet)"
      />
      <TStatCard
        label="Tier"
        :value="licence.tier"
        accent="var(--accent)"
      />
      <TStatCard
        label="Days remaining"
        :value="daysRemaining(licence.expiresAt)"
        accent="var(--warn)"
      />
    </div>

    <TPanel title="Limits">
      <table v-if="visibleLimits.length" class="limits">
        <thead>
          <tr><th>Metric</th><th>Window</th><th>Cap</th></tr>
        </thead>
        <tbody>
          <tr v-for="(l, i) in visibleLimits" :key="i">
            <td>{{ l.metric }}</td>
            <td>{{ l.window }}</td>
            <td class="mono">{{ l.cap === 0 ? '∞' : l.cap }}</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted">No caps set (seats only).</p>
    </TPanel>

    <TPanel
      title="Activations"
      :subtitle="`· ${actRows.filter(r => r.active).length} active`"
    >
      <TDataTable
        :columns="actColumns"
        :rows="actRows"
        row-key="id"
        empty-text="No activations yet."
      >
        <template #[`cell:activationType`]="{ row }">
          <TPill
            :variant="row.activationType === 'report_server' ? 'info' : row.activationType === 'manage_server' ? 'warn' : 'neutral'"
            :dot="false"
          >
            {{ row.activationType === 'report_server' ? 'Report Server' : row.activationType === 'manage_server' ? 'Manage Server' : 'Agent' }}
          </TPill>
        </template>
        <template #[`cell:displayName`]="{ row }">
          <span v-if="row.displayName" class="name-cell">{{ row.displayName }}</span>
          <span v-else class="muted">—</span>
        </template>
        <template #[`cell:active`]="{ row }">
          <TPill :variant="row.active ? 'safe' : 'neutral'">
            {{ row.active ? 'Active' : 'Inactive' }}
          </TPill>
        </template>
      </TDataTable>
    </TPanel>
  </div>

  <TConfirmDialog
    :open="revokeOpen"
    title="Revoke licence?"
    :message="`Revoking ${licence?.id ?? ''} will deactivate all seats. This can't be undone.`"
    confirm-label="Revoke"
    variant="danger"
    @confirm="revoke"
    @cancel="revokeOpen = false"
  />
</template>

<style scoped>
.detail { display: flex; flex-direction: column; gap: var(--space-3); }
.head {
  background: linear-gradient(
    135deg,
    color-mix(in srgb, var(--portal-accent) 14%, transparent),
    color-mix(in srgb, var(--accent-strong) 4%, transparent)
  );
  border: 1px solid color-mix(in srgb, var(--portal-accent) 30%, var(--border));
  border-radius: var(--radius-lg);
  padding: var(--space-4) var(--space-5);
  display: flex;
  gap: var(--space-4);
  align-items: flex-start;
}
.head-body { flex: 1; }
.label {
  font-size: 0.62rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--portal-accent);
  font-weight: 500;
}
.key {
  font-family: var(--font-mono);
  font-size: 1rem;
  color: var(--text-primary);
  margin: 4px 0;
}
.meta {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-3);
  margin-top: var(--space-2);
  font-size: 0.74rem;
  color: var(--text-muted);
  align-items: center;
}
.meta b {
  color: var(--text-primary);
  font-family: var(--font-display);
  font-weight: 500;
}
.actions {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}
.stats {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--space-2);
}
.muted { color: var(--text-muted); font-size: 0.78rem; }
.name-cell { color: var(--text-primary); }
.limits {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.76rem;
}
.limits th {
  text-align: left;
  padding: var(--space-2);
  border-bottom: 1px solid var(--border);
  color: var(--text-subtle);
  font-weight: 500;
  font-size: 0.66rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.limits td {
  padding: var(--space-2);
  border-bottom: 1px solid var(--border);
}
.limits tr:last-child td { border-bottom: none; }
.mono { font-family: var(--font-mono); }
</style>
