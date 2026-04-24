<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { TButton, TStatCard, TPanel } from '@triton/ui';
import { useLicenceStore } from '../stores/licence';
import { useApiClient } from '../stores/apiClient';

const router = useRouter();
const licence = useLicenceStore();
const apiClient = useApiClient();

onMounted(() => {
  void licence.fetch();
});

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

// ---------------------------------------------------------------------------
// Refresh action
// ---------------------------------------------------------------------------
const refreshBusy = ref(false);
const refreshMsg = ref('');
const refreshErr = ref('');

async function onRefresh() {
  if (refreshBusy.value) return;
  refreshBusy.value = true;
  refreshMsg.value = '';
  refreshErr.value = '';
  try {
    const api = apiClient.get();
    await api.refreshLicence();
    refreshMsg.value = 'Licence refreshed.';
    await licence.fetch();
  } catch (e) {
    refreshErr.value = e instanceof Error ? e.message : 'Refresh failed.';
  } finally {
    refreshBusy.value = false;
    setTimeout(() => {
      refreshMsg.value = '';
      refreshErr.value = '';
    }, 3000);
  }
}

// ---------------------------------------------------------------------------
// Replace Key modal
// ---------------------------------------------------------------------------
const showReplace = ref(false);
const replaceKey = ref('');
const replaceBusy = ref(false);
const replaceErr = ref('');

function openReplaceModal() {
  replaceKey.value = '';
  replaceErr.value = '';
  showReplace.value = true;
}

function closeReplaceModal() {
  showReplace.value = false;
}

async function onReplaceSubmit() {
  if (!replaceKey.value.trim()) {
    replaceErr.value = 'Licence key is required.';
    return;
  }
  replaceBusy.value = true;
  replaceErr.value = '';
  try {
    const api = apiClient.get();
    await api.replaceLicenceKey({ license_key: replaceKey.value.trim() });
    showReplace.value = false;
    await licence.fetch();
  } catch (e) {
    replaceErr.value = e instanceof Error ? e.message : 'Replace failed.';
  } finally {
    replaceBusy.value = false;
  }
}

// ---------------------------------------------------------------------------
// Deactivate modal
// ---------------------------------------------------------------------------
const showDeactivate = ref(false);
const deactivateBusy = ref(false);
const deactivateErr = ref('');

function openDeactivateModal() {
  deactivateErr.value = '';
  showDeactivate.value = true;
}

function closeDeactivateModal() {
  showDeactivate.value = false;
}

async function onDeactivateConfirm() {
  deactivateBusy.value = true;
  deactivateErr.value = '';
  try {
    const api = apiClient.get();
    const resp = await api.deactivateLicence();
    if (resp.pending) {
      // Scheduled deactivation — scans still running
      showDeactivate.value = false;
      await licence.fetch();
    } else {
      // Immediate deactivation — redirect to setup
      void router.push('/setup/license');
    }
  } catch (e) {
    deactivateErr.value = e instanceof Error ? e.message : 'Deactivation failed.';
  } finally {
    deactivateBusy.value = false;
  }
}

// ---------------------------------------------------------------------------
// Cancel pending deactivation
// ---------------------------------------------------------------------------
async function onCancelDeactivation() {
  try {
    const api = apiClient.get();
    await api.cancelDeactivation();
    await licence.fetch();
  } catch {
    // Silently ignore — the banner will remain until next fetch succeeds.
  }
}
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
    </header>

    <!-- Pending deactivation banner -->
    <div
      v-if="licence.summary?.pending_deactivation"
      class="banner banner-warn"
    >
      <span>
        Deactivation pending — {{ licence.summary.active_scans }} active scan{{
          licence.summary.active_scans !== 1 ? 's' : ''
        }} still running.
      </span>
      <TButton
        data-testid="btn-cancel-deactivation"
        variant="secondary"
        size="sm"
        @click="onCancelDeactivation"
      >
        Cancel deactivation
      </TButton>
    </div>

    <p
      v-if="licence.error"
      class="licence-inactive"
    >
      Licence inactive — re-activate to restore manage features.
      <span class="licence-inactive-reason">{{ licence.error }}</span>
    </p>

    <!-- Refresh inline feedback -->
    <p
      v-if="refreshMsg"
      class="feedback feedback-ok"
    >
      {{ refreshMsg }}
    </p>
    <p
      v-if="refreshErr"
      class="feedback feedback-err"
    >
      {{ refreshErr }}
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

    <!-- Action buttons -->
    <div class="actions">
      <TButton
        data-testid="btn-refresh"
        variant="secondary"
        size="sm"
        :disabled="refreshBusy"
        @click="onRefresh"
      >
        Refresh
      </TButton>
      <TButton
        data-testid="btn-replace-key"
        variant="secondary"
        size="sm"
        @click="openReplaceModal"
      >
        Replace Key
      </TButton>
      <TButton
        data-testid="btn-deactivate"
        variant="danger"
        size="sm"
        @click="openDeactivateModal"
      >
        Deactivate
      </TButton>
    </div>

    <!-- Replace Key modal -->
    <dialog
      v-if="showReplace"
      data-testid="replace-key-modal"
      class="modal"
      open
    >
      <div class="modal-inner">
        <h2 class="modal-title">
          Replace Licence Key
        </h2>
        <p class="modal-desc">
          Enter the new licence key. The current key will be replaced immediately.
        </p>
        <div class="field">
          <label class="field-label">Licence server URL</label>
          <input
            class="field-input field-input-readonly"
            type="text"
            readonly
            :value="licence.summary?.license_server_url ?? ''"
          >
        </div>
        <div class="field">
          <label class="field-label">New licence key</label>
          <textarea
            v-model="replaceKey"
            class="field-input field-textarea"
            placeholder="Paste new licence key…"
            rows="4"
          />
        </div>
        <p
          v-if="replaceErr"
          class="modal-err"
        >
          {{ replaceErr }}
        </p>
        <div class="modal-actions">
          <TButton
            data-testid="btn-replace-cancel"
            variant="secondary"
            size="sm"
            @click="closeReplaceModal"
          >
            Cancel
          </TButton>
          <TButton
            data-testid="btn-replace-submit"
            variant="primary"
            size="sm"
            :disabled="replaceBusy"
            @click="onReplaceSubmit"
          >
            Replace
          </TButton>
        </div>
      </div>
    </dialog>

    <!-- Deactivate modal -->
    <dialog
      v-if="showDeactivate"
      data-testid="deactivate-modal"
      class="modal"
      open
    >
      <div class="modal-inner">
        <h2 class="modal-title">
          Deactivate Licence
        </h2>

        <!-- No active scans: immediate deactivation -->
        <template v-if="(licence.summary?.active_scans ?? 0) === 0">
          <p class="modal-desc modal-desc-danger">
            This will immediately deactivate the licence and redirect to setup.
            All manage features will be unavailable until you re-activate.
          </p>
          <p
            v-if="deactivateErr"
            class="modal-err"
          >
            {{ deactivateErr }}
          </p>
          <div class="modal-actions">
            <TButton
              data-testid="btn-deactivate-cancel"
              variant="secondary"
              size="sm"
              @click="closeDeactivateModal"
            >
              Cancel
            </TButton>
            <TButton
              data-testid="btn-confirm-deactivate"
              variant="danger"
              size="sm"
              :disabled="deactivateBusy"
              @click="onDeactivateConfirm"
            >
              Deactivate
            </TButton>
          </div>
        </template>

        <!-- Active scans running: schedule deactivation -->
        <template v-else>
          <p class="modal-desc modal-desc-warn">
            There {{ licence.summary!.active_scans === 1 ? 'is' : 'are' }}
            <strong>{{ licence.summary!.active_scans }}</strong>
            active scan{{ licence.summary!.active_scans !== 1 ? 's' : '' }} running.
            Deactivation will be scheduled and take effect once all scans complete.
          </p>
          <p
            v-if="deactivateErr"
            class="modal-err"
          >
            {{ deactivateErr }}
          </p>
          <div class="modal-actions">
            <TButton
              data-testid="btn-deactivate-cancel"
              variant="secondary"
              size="sm"
              @click="closeDeactivateModal"
            >
              Cancel
            </TButton>
            <TButton
              data-testid="btn-schedule-deactivate"
              variant="secondary"
              size="sm"
              :disabled="deactivateBusy"
              @click="onDeactivateConfirm"
            >
              Schedule Deactivation
            </TButton>
          </div>
        </template>
      </div>
    </dialog>
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

/* Pending deactivation banner */
.banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
  padding: var(--space-3) var(--space-4);
  border-radius: var(--radius);
  font-size: 0.85rem;
}
.banner-warn {
  background: color-mix(in srgb, var(--warn, #f59e0b) 12%, transparent);
  border: 1px solid var(--warn, #f59e0b);
  color: var(--text-primary);
}

/* Inline refresh feedback */
.feedback {
  padding: var(--space-2) var(--space-3);
  border-radius: var(--radius);
  font-size: 0.82rem;
  margin: 0;
}
.feedback-ok {
  background: color-mix(in srgb, var(--safe, #10b981) 12%, transparent);
  border: 1px solid var(--safe, #10b981);
}
.feedback-err {
  background: color-mix(in srgb, var(--unsafe, #ef4444) 12%, transparent);
  border: 1px solid var(--unsafe, #ef4444);
}

/* Action buttons row */
.actions {
  display: flex;
  gap: var(--space-2);
  flex-wrap: wrap;
}

/* Modal */
.modal {
  position: fixed;
  inset: 0;
  z-index: 100;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(0, 0, 0, 0.45);
  border: none;
  padding: 0;
  margin: 0;
  max-width: 100%;
  max-height: 100%;
  width: 100%;
  height: 100%;
}
.modal-inner {
  background: var(--bg-surface, #fff);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: var(--space-5);
  width: min(480px, 90vw);
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.modal-title {
  font-family: var(--font-display);
  font-size: 1.1rem;
  margin: 0;
}
.modal-desc {
  font-size: 0.85rem;
  margin: 0;
  color: var(--text-primary);
}
.modal-desc-danger {
  color: var(--unsafe, #ef4444);
}
.modal-desc-warn {
  color: var(--text-primary);
  padding: var(--space-2) var(--space-3);
  border-left: 3px solid var(--warn, #f59e0b);
}
.modal-err {
  font-size: 0.82rem;
  color: var(--unsafe, #ef4444);
  margin: 0;
}
.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-2);
}

/* Form fields */
.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}
.field-label {
  font-size: 0.78rem;
  color: var(--text-muted);
  font-weight: 500;
}
.field-input {
  font-family: var(--font-mono);
  font-size: 0.82rem;
  padding: var(--space-2) var(--space-3);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--bg-surface);
  color: var(--text-primary);
  width: 100%;
  box-sizing: border-box;
}
.field-input-readonly {
  background: var(--bg-base, #f9fafb);
  cursor: default;
}
.field-textarea {
  resize: vertical;
  min-height: 80px;
  font-family: var(--font-mono);
}
</style>
