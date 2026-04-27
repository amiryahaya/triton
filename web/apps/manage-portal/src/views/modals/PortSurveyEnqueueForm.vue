<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { TModal, TSelect, TFormField, TButton } from '@triton/ui';
import type { Host, ScanJobProfile, PortSurveyEnqueueReq } from '@triton/api-client';

const props = defineProps<{ open: boolean; hosts: Host[] }>();
const emit = defineEmits<{ close: []; submit: [req: PortSurveyEnqueueReq] }>();

const selectedHostIDs = ref<string[]>([]);
const profile = ref<ScanJobProfile>('standard');
const scheduleMode = ref<'now' | 'later'>('now');
const scheduledAt = ref('');
const portOverrideRaw = ref('');
const busy = ref(false);

watch(
  () => props.open,
  (o) => {
    if (!o) return;
    selectedHostIDs.value = [];
    profile.value = 'standard';
    scheduleMode.value = 'now';
    scheduledAt.value = '';
    portOverrideRaw.value = '';
    busy.value = false;
  }
);

// Validate and parse comma-separated port list. Returns the parsed array if
// valid, or null if the input is non-empty but invalid.
const parsedPorts = computed<number[] | null>(() => {
  const raw = portOverrideRaw.value.trim();
  if (!raw) return [];
  const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
  const ports: number[] = [];
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return null;
    ports.push(n);
  }
  return ports;
});

const portOverrideError = computed<string>(() => {
  const raw = portOverrideRaw.value.trim();
  if (!raw) return '';
  if (parsedPorts.value === null) {
    return 'Each port must be an integer between 1 and 65535.';
  }
  return '';
});

const showComprehensiveWarning = computed(() => profile.value === 'comprehensive');

const isFormValid = computed(
  () => selectedHostIDs.value.length > 0 && parsedPorts.value !== null
);

function onSubmit() {
  if (!isFormValid.value) return;
  busy.value = true;
  try {
    const req: PortSurveyEnqueueReq = {
      host_ids: selectedHostIDs.value,
      profile: profile.value,
    };
    if (scheduleMode.value === 'later' && scheduledAt.value) {
      req.scheduled_at = new Date(scheduledAt.value).toISOString();
    }
    const ports = parsedPorts.value;
    if (ports && ports.length > 0) {
      req.port_override = ports;
    }
    emit('submit', req);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <TModal
    :open="props.open"
    title="Port Survey"
    width="min(560px, 92vw)"
    @close="emit('close')"
  >
    <div class="enqueue-form">
      <TFormField
        label="Hosts (multi-select)"
        required
      >
        <select
          v-model="selectedHostIDs"
          multiple
          class="hosts-multi"
          size="6"
        >
          <option
            v-for="h in props.hosts"
            :key="h.id"
            :value="h.id"
          >
            {{ h.hostname || h.ip }}{{ h.ip && h.hostname ? ` (${h.ip})` : '' }}
          </option>
        </select>
        <p class="field-hint">{{ selectedHostIDs.length }} selected — hold Ctrl/Cmd to multi-select</p>
      </TFormField>

      <TFormField label="Aggressiveness">
        <TSelect v-model="profile">
          <option value="quick">
            Quick — top 100 ports
          </option>
          <option value="standard">
            Standard — top 1,000 ports
          </option>
          <option value="comprehensive">
            Comprehensive — top 10,000 ports
          </option>
        </TSelect>
      </TFormField>

      <div v-if="showComprehensiveWarning" class="warning-banner" role="alert">
        <svg class="warning-icon" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd" />
        </svg>
        <p class="warning-text">
          Comprehensive mode sends a large number of packets and may trigger IDS/IPS alerts or cause congestion on the target network segment. Only use this mode with explicit authorization.
        </p>
      </div>

      <TFormField label="Port Override">
        <input
          v-model="portOverrideRaw"
          type="text"
          class="text-input"
          :class="{ 'text-input--error': portOverrideError }"
          placeholder="e.g. 22,80,443,8080 (comma-separated, leave blank to use profile defaults)"
        />
        <p v-if="portOverrideError" class="field-error">{{ portOverrideError }}</p>
        <p v-else class="field-hint">Optional — overrides the profile's default port list.</p>
      </TFormField>

      <TFormField label="Schedule">
        <TSelect v-model="scheduleMode">
          <option value="now">
            Run now
          </option>
          <option value="later">
            Schedule for later
          </option>
        </TSelect>
      </TFormField>

      <TFormField v-if="scheduleMode === 'later'" label="Run at">
        <input
          v-model="scheduledAt"
          type="datetime-local"
          class="datetime-input"
        />
      </TFormField>
    </div>

    <template #footer>
      <TButton
        variant="ghost"
        size="sm"
        @click="emit('close')"
      >
        Cancel
      </TButton>
      <TButton
        variant="primary"
        size="sm"
        :disabled="!isFormValid || busy"
        @click="onSubmit"
      >
        {{ busy ? 'Enqueueing…' : `Queue ${selectedHostIDs.length} scan${selectedHostIDs.length === 1 ? '' : 's'}` }}
      </TButton>
    </template>
  </TModal>
</template>

<style scoped>
.enqueue-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.hosts-multi {
  width: 100%;
  padding: var(--space-2);
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-family: var(--font-body);
  font-size: 0.85rem;
  color: var(--text-primary);
}
.field-hint {
  font-size: 0.75rem;
  color: var(--text-muted);
  margin: 0.25rem 0 0;
}
.field-error {
  font-size: 0.75rem;
  color: var(--color-unsafe, #dc2626);
  margin: 0.25rem 0 0;
}
.datetime-input,
.text-input {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 0.875rem;
  background: var(--bg-surface);
  color: var(--text-primary);
  box-sizing: border-box;
}
.text-input--error {
  border-color: var(--color-unsafe, #dc2626);
}
.warning-banner {
  display: flex;
  align-items: flex-start;
  gap: var(--space-2);
  padding: 0.625rem 0.75rem;
  background: #fffbeb;
  border: 1px solid #f59e0b;
  border-radius: var(--radius-sm);
  color: #92400e;
}
.warning-icon {
  flex-shrink: 0;
  width: 1.1rem;
  height: 1.1rem;
  margin-top: 0.05rem;
  color: #d97706;
}
.warning-text {
  font-size: 0.8rem;
  line-height: 1.4;
  margin: 0;
}
</style>
