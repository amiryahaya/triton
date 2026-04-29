<template>
  <div class="step-content">
    <h2 class="step-title">Summary</h2>

    <!-- Job types card -->
    <div class="summary-card">
      <div class="summary-row">
        <span class="summary-label">Job types</span>
        <span class="summary-value">{{ jobTypesLabel }}</span>
      </div>
      <div class="summary-row">
        <span class="summary-label">Profile</span>
        <span class="summary-value">{{ state.profile }}</span>
      </div>
      <button class="edit-link" @click="$emit('go-step', 1)">Edit</button>
    </div>

    <!-- Hosts card -->
    <div class="summary-card">
      <div class="summary-row">
        <span class="summary-label">Hosts</span>
        <span class="summary-value">{{ state.hostIDs.length }} selected</span>
      </div>
      <div class="chip-row">
        <span v-for="h in firstFourHosts" :key="h.id" class="chip">
          {{ credIcon(h) }} {{ h.hostname || h.ip }}
        </span>
        <span v-if="state.hostIDs.length > 4" class="chip muted">+{{ state.hostIDs.length - 4 }} more</span>
      </div>
      <button class="edit-link" @click="$emit('go-step', 2)">Edit</button>
    </div>

    <!-- Schedule card -->
    <div class="summary-card">
      <div class="summary-row">
        <span class="summary-label">Schedule</span>
        <span class="summary-value">{{ scheduleLabel }}</span>
      </div>
      <button class="edit-link" @click="$emit('go-step', 3)">Edit</button>
    </div>

    <!-- Resources card -->
    <div class="summary-card">
      <div class="summary-row">
        <span class="summary-label">Resources</span>
        <span class="summary-value">{{ resourcesLabel }}</span>
      </div>
      <button class="edit-link" @click="$emit('go-step', 4)">Edit</button>
    </div>

    <!-- Credential warning (amber) -->
    <div v-if="skippedHosts.length" class="credential-warning">
      <div class="warning-title">⚠ {{ skippedHosts.length }} filesystem job{{ skippedHosts.length !== 1 ? 's' : '' }} will be skipped</div>
      <div class="warning-body">
        These hosts have no SSH credential:
        <span v-for="h in skippedHosts" :key="h.id" class="chip amber">🟡 {{ h.hostname || h.ip }}</span>
      </div>
      <div class="warning-note">
        Port survey will still run for them.
        <button class="link-btn" @click="$emit('go-step', 2)">← Go back to fix</button>
      </div>
    </div>

    <!-- Job count summary line -->
    <div class="job-count-line">
      {{ jobCountLine }}
    </div>

    <!-- Enqueue button -->
    <button class="btn-primary enqueue-btn"
            :disabled="loading || plannedJobCount - skippedHosts.length === 0"
            @click="$emit('submit')">
      <span v-if="loading">Enqueueing…</span>
      <span v-else>{{ enqueueLabel }}</span>
    </button>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import type { Host } from '@triton/api-client';
import type { WizardState } from './wizardTypes';

const props = defineProps<{
  state: WizardState;
  allHosts: Host[];
  loading: boolean;
}>();

defineEmits<{
  'go-step': [number];
  submit: [];
}>();

function credIcon(h: Host) {
  if (h.credentials_ref && h.ssh_port > 0) return '🟢';
  return '🟡';
}

const selectedHosts = computed(() =>
  props.allHosts.filter(h => props.state.hostIDs.includes(h.id))
);

const firstFourHosts = computed(() => selectedHosts.value.slice(0, 4));

// Hosts that will have filesystem skipped (no cred + no agent connection)
const skippedHosts = computed(() => {
  if (!props.state.jobTypes.includes('filesystem')) return [];
  return selectedHosts.value.filter(
    h => !(h.credentials_ref && h.ssh_port > 0)
  );
});

const jobTypesLabel = computed(() => {
  const labels: Record<string, string> = {
    port_survey: 'Port Survey',
    filesystem: 'Filesystem (SSH)',
  };
  return props.state.jobTypes.map(jt => labels[jt] ?? jt).join(' + ') || '—';
});

const scheduleLabel = computed(() => {
  switch (props.state.scheduleKey) {
    case 'immediately': return 'Immediately';
    case 'once_at': return `Once at ${props.state.onceAt ?? '—'}`;
    case 'hourly':  return 'Hourly';
    case 'daily':   return `Daily ${props.state.dailyTime ?? ''}`;
    case 'weekly':  return `Weekly · ${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][props.state.weeklyDay ?? 1]} ${props.state.weeklyTime ?? ''}`;
    case 'monthly': return `Monthly · day ${props.state.monthlyDay ?? 1}`;
    default: return '—';
  }
});

const resourcesLabel = computed(() => {
  const parts = [];
  if (props.state.maxCPUPct)    parts.push(`${props.state.maxCPUPct}% CPU`);
  if (props.state.maxMemoryMB)  parts.push(`${(props.state.maxMemoryMB / 1024).toFixed(1)} GB`);
  if (props.state.maxDurationS) parts.push(`${Math.round(props.state.maxDurationS / 3600)}h max`);
  return parts.length ? parts.join(' · ') : 'Unlimited';
});

const isRecurring = computed(() =>
  props.state.scheduleKey !== 'immediately'
);

const plannedJobCount = computed(() => {
  const perHost = props.state.jobTypes.length;
  return selectedHosts.value.length * perHost;
});

const jobCountLine = computed(() => {
  const skip = skippedHosts.value.length;
  const total = plannedJobCount.value;
  if (skip === 0) return `${total} jobs will be created`;
  return `${total - skip} jobs will be created (${total} planned, ${skip} skipped)`;
});

const enqueueLabel = computed(() => {
  const n = plannedJobCount.value - skippedHosts.value.length;
  const base = skippedHosts.value.length > 0 ? `Enqueue ${n} jobs anyway` : `Enqueue ${n} jobs`;
  return isRecurring.value ? `Create schedule + ${base.toLowerCase()}` : base;
});
</script>

<style scoped>
.step-content {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.step-title {
  font-family: var(--font-display);
  font-size: 1.1rem;
  margin: 0;
}

.summary-card {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
  padding: var(--space-3);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  background: var(--bg-surface);
}

.summary-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.summary-label {
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--text-secondary);
}

.summary-value {
  font-size: 0.9rem;
  color: var(--text-primary);
  font-weight: 500;
}

.chip-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  align-items: center;
}

.chip {
  display: inline-block;
  padding: 0.25rem 0.6rem;
  background: var(--bg-muted, #f3f4f6);
  border-radius: 0.25rem;
  font-size: 0.8rem;
  color: var(--text-primary);
  white-space: nowrap;
}

.chip.muted {
  color: var(--text-muted);
  font-style: italic;
}

.chip.amber {
  background: #fef3c7;
  color: #92400e;
}

.edit-link {
  align-self: flex-start;
  background: none;
  border: none;
  color: var(--color-primary, #2563eb);
  font-size: 0.85rem;
  cursor: pointer;
  padding: 0;
  text-decoration: underline;
  transition: opacity 0.15s;
}

.edit-link:hover {
  opacity: 0.7;
}

.credential-warning {
  padding: var(--space-3);
  border-left: 4px solid #f59e0b;
  background: #fffbeb;
  border-radius: var(--radius-sm);
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.warning-title {
  font-size: 0.9rem;
  font-weight: 600;
  color: #92400e;
  margin: 0;
}

.warning-body {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  align-items: center;
  font-size: 0.85rem;
  color: #92400e;
}

.warning-note {
  font-size: 0.8rem;
  color: #92400e;
  display: flex;
  align-items: center;
  gap: var(--space-2);
}

.link-btn {
  background: none;
  border: none;
  color: #2563eb;
  cursor: pointer;
  padding: 0;
  font-size: 0.8rem;
  text-decoration: underline;
  transition: opacity 0.15s;
}

.link-btn:hover {
  opacity: 0.7;
}

.job-count-line {
  padding: var(--space-2) var(--space-3);
  background: var(--bg-muted, #f9fafb);
  border-radius: var(--radius-sm);
  font-size: 0.9rem;
  color: var(--text-secondary);
  text-align: center;
}

.btn-primary {
  padding: 0.6rem 1.2rem;
  background: var(--color-primary, #2563eb);
  color: white;
  border: none;
  border-radius: var(--radius-sm);
  font-size: 0.9rem;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.15s, background 0.15s;
}

.btn-primary:hover:not(:disabled) {
  background: color-mix(in srgb, var(--color-primary, #2563eb) 120%, transparent);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.enqueue-btn {
  align-self: stretch;
  padding: 0.8rem;
  margin-top: var(--space-2);
}
</style>
