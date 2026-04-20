<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TFormField, TButton } from '@triton/ui';
import type { CreateHostReq } from '@triton/api-client';

const props = defineProps<{ open: boolean }>();

const emit = defineEmits<{
  close: [];
  submit: [hosts: CreateHostReq[]];
}>();

const text = ref('');
const error = ref('');

const placeholder = `[
  { "hostname": "web-01", "ip": "10.0.0.10", "os": "linux" },
  { "hostname": "db-01", "ip": "10.0.0.20", "os": "linux" }
]`;

watch(
  () => props.open,
  (o) => {
    if (o) {
      text.value = '';
      error.value = '';
    }
  }
);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function parseAndEmit() {
  error.value = '';
  if (!text.value.trim()) {
    error.value = 'Please paste a JSON array of host objects.';
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.value);
  } catch (e) {
    error.value = `Invalid JSON: ${String(e)}`;
    return;
  }
  if (!Array.isArray(parsed)) {
    error.value = 'Expected a JSON array of host objects.';
    return;
  }
  const out: CreateHostReq[] = [];
  for (let i = 0; i < parsed.length; i++) {
    const row = parsed[i];
    if (!isRecord(row) || typeof row.hostname !== 'string' || !row.hostname.trim()) {
      error.value = `Entry ${i}: missing or invalid "hostname".`;
      return;
    }
    out.push({
      hostname: row.hostname,
      ip: typeof row.ip === 'string' ? row.ip : undefined,
      zone_id: typeof row.zone_id === 'string' ? row.zone_id : undefined,
      os: typeof row.os === 'string' ? row.os : undefined,
    });
  }
  if (out.length === 0) {
    error.value = 'No hosts to import.';
    return;
  }
  emit('submit', out);
}
</script>

<template>
  <TModal
    :open="open"
    :title="'Bulk import hosts'"
    width="min(640px, 92vw)"
    @close="emit('close')"
  >
    <div class="bulk-form">
      <p class="bulk-hint">
        Paste a JSON array of host objects. Each entry must include
        <code>hostname</code>; <code>ip</code>, <code>zone_id</code>, and
        <code>os</code> are optional.
      </p>
      <TFormField
        label="JSON payload"
        required
        :error="error"
      >
        <textarea
          v-model="text"
          class="bulk-text"
          rows="10"
          spellcheck="false"
          :placeholder="placeholder"
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
        @click="parseAndEmit"
      >
        Import
      </TButton>
    </template>
  </TModal>
</template>

<style scoped>
.bulk-form {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}
.bulk-hint {
  font-size: 0.78rem;
  color: var(--text-muted);
  margin: 0;
}
.bulk-hint code {
  font-family: var(--font-mono);
  font-size: 0.72rem;
  padding: 1px 4px;
  background: var(--bg-elevated);
  border-radius: var(--radius-sm);
}
.bulk-text {
  font-family: var(--font-mono);
  font-size: 0.78rem;
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  color: var(--text-primary);
  border-radius: var(--radius-sm);
  padding: var(--space-2);
  width: 100%;
  resize: vertical;
}
.bulk-text:focus {
  outline: none;
  border-color: var(--accent-strong);
  box-shadow: 0 0 0 2px var(--accent-muted);
}
</style>
