<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TSelect, TFormField, TButton } from '@triton/ui';
import type { Host, ScanJobProfile, PortSurveyEnqueueReq } from '@triton/api-client';

const props = defineProps<{ open: boolean; hosts: Host[] }>();
const emit = defineEmits<{ close: []; submit: [req: PortSurveyEnqueueReq] }>();

const selectedHostIDs = ref<string[]>([]);
const profile = ref<ScanJobProfile>('standard');
const scheduleMode = ref<'now' | 'later'>('now');
const scheduledAt = ref('');
const busy = ref(false);

watch(
  () => props.open,
  (o) => {
    if (!o) return;
    selectedHostIDs.value = [];
    profile.value = 'standard';
    scheduleMode.value = 'now';
    scheduledAt.value = '';
    busy.value = false;
  }
);

function onSubmit() {
  if (selectedHostIDs.value.length === 0) return;
  busy.value = true;
  try {
    const req: PortSurveyEnqueueReq = {
      host_ids: selectedHostIDs.value,
      profile: profile.value,
    };
    if (scheduleMode.value === 'later' && scheduledAt.value) {
      req.scheduled_at = new Date(scheduledAt.value).toISOString();
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
        :disabled="selectedHostIDs.length === 0 || busy"
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
.datetime-input {
  width: 100%;
  padding: 0.4rem 0.6rem;
  border: 1px solid var(--border);
  border-radius: var(--radius-sm);
  font-size: 0.875rem;
  background: var(--bg-surface);
  color: var(--text-primary);
}
</style>
