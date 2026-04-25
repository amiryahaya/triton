<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TFormField, TButton } from '@triton/ui';
import type { CreateHostReq } from '@triton/api-client';

const props = defineProps<{ open: boolean }>();

const emit = defineEmits<{
  close: [];
  submit: [hosts: CreateHostReq[]];
}>();

// ── tab state ────────────────────────────────────────────────────────────────
const activeTab = ref<'csv' | 'json'>('csv');

// ── JSON tab ─────────────────────────────────────────────────────────────────
const jsonText = ref('');
const jsonError = ref('');

const jsonPlaceholder = `[
  { "hostname": "web-01", "ip": "10.0.0.10", "os": "linux" },
  { "hostname": "db-01", "ip": "10.0.0.20", "os": "linux" }
]`;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function parseJSON(): CreateHostReq[] | null {
  jsonError.value = '';
  if (!jsonText.value.trim()) {
    jsonError.value = 'Please paste a JSON array of host objects.';
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText.value);
  } catch (e) {
    jsonError.value = `Invalid JSON: ${String(e)}`;
    return null;
  }
  if (!Array.isArray(parsed)) {
    jsonError.value = 'Expected a JSON array of host objects.';
    return null;
  }
  const out: CreateHostReq[] = [];
  for (let i = 0; i < parsed.length; i++) {
    const row = parsed[i];
    if (!isRecord(row) || typeof row.hostname !== 'string' || !row.hostname.trim()) {
      jsonError.value = `Entry ${i}: missing or invalid "hostname".`;
      return null;
    }
    out.push({
      hostname: row.hostname,
      ip: typeof row.ip === 'string' ? row.ip : undefined,
      os: typeof row.os === 'string' ? row.os : undefined,
      tag_ids: Array.isArray(row.tag_ids)
        ? (row.tag_ids as unknown[]).filter((x): x is string => typeof x === 'string')
        : undefined,
      tags: Array.isArray(row.tags)
        ? (row.tags as unknown[]).filter((x): x is string => typeof x === 'string')
        : undefined,
    });
  }
  if (out.length === 0) {
    jsonError.value = 'No hosts to import.';
    return null;
  }
  return out;
}

// ── CSV tab ──────────────────────────────────────────────────────────────────
interface CsvRow {
  hostname: string;
  ip?: string;
  os?: string;
  tags?: string[];
  _error?: string;
}

const csvInput = ref('');
const csvParseError = ref('');
const preview = ref<CsvRow[]>([]);

/**
 * Minimal CSV cell splitter. Handles quoted fields containing commas
 * but not embedded newlines (which would require multi-line handling).
 */
function splitCSVLine(line: string): string[] {
  const cells: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        // Escaped double-quote inside a quoted field
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === ',' && !inQuotes) {
      cells.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  cells.push(current);
  return cells;
}

function parseCSV(raw: string): void {
  csvParseError.value = '';
  preview.value = [];

  const lines = raw.split('\n').map(l => l.trimEnd());
  const nonEmpty = lines.filter(l => l.trim());
  if (nonEmpty.length < 2) {
    csvParseError.value = 'CSV must have a header row and at least one data row.';
    return;
  }

  const headers = splitCSVLine(nonEmpty[0]).map(h => h.trim().toLowerCase());
  const hostnameIdx = headers.indexOf('hostname');
  if (hostnameIdx === -1) {
    csvParseError.value = 'CSV must have a "hostname" column.';
    return;
  }
  const ipIdx = headers.indexOf('ip');
  const osIdx = headers.indexOf('os');
  const tagsIdx = headers.indexOf('tags');

  const rows: CsvRow[] = [];
  for (let i = 1; i < nonEmpty.length; i++) {
    const cells = splitCSVLine(nonEmpty[i]);
    const hostname = cells[hostnameIdx]?.trim() ?? '';
    const row: CsvRow = { hostname };
    if (!hostname) {
      row._error = 'hostname is required';
    }
    if (ipIdx !== -1 && cells[ipIdx]?.trim()) row.ip = cells[ipIdx].trim();
    if (osIdx !== -1 && cells[osIdx]?.trim()) row.os = cells[osIdx].trim();
    if (tagsIdx !== -1 && cells[tagsIdx]?.trim()) {
      row.tags = cells[tagsIdx].trim().split(',').map(t => t.trim()).filter(Boolean);
    }
    rows.push(row);
  }
  preview.value = rows;
}

function onCSVInput(): void {
  parseCSV(csvInput.value);
}

function validRows(): CsvRow[] {
  return preview.value.filter(r => !r._error);
}

// ── shared ───────────────────────────────────────────────────────────────────
watch(
  () => props.open,
  (o) => {
    if (o) {
      jsonText.value = '';
      jsonError.value = '';
      csvInput.value = '';
      csvParseError.value = '';
      preview.value = [];
      activeTab.value = 'csv';
    }
  }
);

function onSubmit(): void {
  if (activeTab.value === 'csv') {
    csvParseError.value = '';
    const rows = validRows();
    if (!rows.length) {
      csvParseError.value = preview.value.length
        ? 'No valid rows to import (fix errors above).'
        : 'Paste CSV data above.';
      return;
    }
    emit('submit', rows.map(r => ({
      hostname: r.hostname,
      ip: r.ip,
      os: r.os,
      tags: r.tags,
    })));
  } else {
    const out = parseJSON();
    if (out) emit('submit', out);
  }
}
</script>

<template>
  <TModal
    :open="open"
    title="Bulk import hosts"
    width="min(640px, 92vw)"
    @close="emit('close')"
  >
    <div class="bulk-form">
      <!-- Tab bar -->
      <div class="bulk-tabs">
        <button
          class="bulk-tab"
          :class="{ active: activeTab === 'csv' }"
          type="button"
          @click="activeTab = 'csv'"
        >
          CSV
        </button>
        <button
          class="bulk-tab"
          :class="{ active: activeTab === 'json' }"
          type="button"
          @click="activeTab = 'json'"
        >
          JSON
        </button>
      </div>

      <!-- CSV tab -->
      <div
        v-if="activeTab === 'csv'"
        class="bulk-tab-panel"
      >
        <p class="bulk-hint">
          Columns: <code>hostname</code> (required), <code>ip</code>, <code>os</code>,
          <code>tags</code> (comma-separated tag names; quote if multiple:
          <code>"production,web"</code>)
        </p>
        <TFormField
          label="CSV data"
          required
          :error="csvParseError"
        >
          <textarea
            v-model="csvInput"
            class="bulk-text"
            rows="8"
            spellcheck="false"
            placeholder="hostname,ip,os,tags&#10;web-01,10.0.0.10,linux,&quot;production,web&quot;"
            @input="onCSVInput"
          />
        </TFormField>
        <div
          v-if="preview.length"
          class="csv-preview"
        >
          <div
            v-for="(row, i) in preview"
            :key="i"
            class="csv-preview-row"
            :class="{ 'csv-preview-row--error': row._error }"
          >
            <span
              v-if="row._error"
              class="row-error"
            >Row {{ i + 1 }}: {{ row._error }}</span>
            <span v-else>
              {{ row.hostname }}<span
                v-if="row.ip"
                class="muted"
              > — {{ row.ip }}</span>
              <span
                v-if="row.tags?.length"
                class="muted"
              > [{{ row.tags.join(', ') }}]</span>
            </span>
          </div>
          <p class="preview-summary">
            {{ validRows().length }} valid /
            {{ preview.length - validRows().length }} error{{ preview.length - validRows().length === 1 ? '' : 's' }}
          </p>
        </div>
      </div>

      <!-- JSON tab -->
      <div
        v-else
        class="bulk-tab-panel"
      >
        <p class="bulk-hint">
          Paste a JSON array of host objects. Each entry must include
          <code>hostname</code>; <code>ip</code>, <code>os</code>, <code>tag_ids</code>
          (UUID array), and <code>tags</code> (name array) are optional.
        </p>
        <TFormField
          label="JSON payload"
          required
          :error="jsonError"
        >
          <textarea
            v-model="jsonText"
            class="bulk-text"
            rows="10"
            spellcheck="false"
            :placeholder="jsonPlaceholder"
          />
        </TFormField>
      </div>
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
        :disabled="activeTab === 'csv' && validRows().length === 0"
        @click="onSubmit"
      >
        <template v-if="activeTab === 'csv' && validRows().length > 0">
          Import {{ validRows().length }} host{{ validRows().length === 1 ? '' : 's' }}
        </template>
        <template v-else>Import</template>
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

/* Tab bar */
.bulk-tabs {
  display: flex;
  gap: 0;
  border-bottom: 1px solid var(--border-strong);
}
.bulk-tab {
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  padding: var(--space-2) var(--space-3);
  font-size: 0.85rem;
  font-weight: 500;
  color: var(--text-muted);
  cursor: pointer;
  margin-bottom: -1px;
  transition: color 0.15s, border-color 0.15s;
}
.bulk-tab:hover {
  color: var(--text-primary);
}
.bulk-tab.active {
  color: var(--accent-strong);
  border-bottom-color: var(--accent-strong);
}

.bulk-tab-panel {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

/* Textarea */
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

/* CSV preview */
.csv-preview {
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  overflow: hidden;
  font-size: 0.78rem;
}
.csv-preview-row {
  padding: var(--space-1) var(--space-2);
  border-bottom: 1px solid var(--border-weak, var(--border-strong));
}
.csv-preview-row:last-child {
  border-bottom: none;
}
.csv-preview-row--error {
  background: var(--bg-danger-subtle, rgba(239,68,68,0.08));
}
.row-error {
  color: var(--text-danger, #ef4444);
}
.preview-summary {
  padding: var(--space-1) var(--space-2);
  font-size: 0.72rem;
  color: var(--text-muted);
  background: var(--bg-elevated);
  margin: 0;
  border-top: 1px solid var(--border-strong);
}
.muted {
  color: var(--text-muted);
}
</style>
