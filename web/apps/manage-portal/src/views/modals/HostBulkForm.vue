<script setup lang="ts">
import { ref, computed, watch } from 'vue';
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
  { "ip": "10.0.0.10", "hostname": "web-01", "os": "linux" },
  { "ip": "10.0.0.20", "hostname": "db-01" }
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
    if (!isRecord(row) || typeof row.ip !== 'string' || !row.ip.trim()) {
      jsonError.value = `Entry ${i}: missing or invalid "ip".`;
      return null;
    }
    out.push({
      ip: row.ip,
      hostname: typeof row.hostname === 'string' ? row.hostname : undefined,
      os: typeof row.os === 'string' ? row.os : undefined,
      tag_ids: Array.isArray(row.tag_ids)
        ? (row.tag_ids as unknown[]).filter((x): x is string => typeof x === 'string')
        : undefined,
      tags: Array.isArray(row.tags)
        ? (row.tags as unknown[]).filter((x): x is string => typeof x === 'string').map(t => t.trim().toLowerCase()).filter(Boolean)
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
  ip: string;        // required
  hostname?: string; // optional
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
  if (!raw.trim()) return;

  const lines = raw.split('\n').map(l => l.trimEnd());
  const nonEmpty = lines.filter(l => l.trim());
  if (nonEmpty.length < 2) {
    csvParseError.value = 'CSV must have a header row and at least one data row.';
    return;
  }

  const headers = splitCSVLine(nonEmpty[0]).map(h => h.trim().toLowerCase());
  const ipIdx = headers.indexOf('ip');
  if (ipIdx === -1) {
    csvParseError.value = 'CSV must have an "ip" column.';
    return;
  }
  const hostnameIdx = headers.indexOf('hostname');
  const osIdx = headers.indexOf('os');
  const tagsIdx = headers.indexOf('tags');

  const rows: CsvRow[] = [];
  for (let i = 1; i < nonEmpty.length; i++) {
    const cells = splitCSVLine(nonEmpty[i]);
    const ip = cells[ipIdx]?.trim() ?? '';
    const row: CsvRow = { ip };
    if (!ip) {
      row._error = 'ip is required';
    }
    if (hostnameIdx !== -1 && cells[hostnameIdx]?.trim()) row.hostname = cells[hostnameIdx].trim();
    if (osIdx !== -1 && cells[osIdx]?.trim()) row.os = cells[osIdx].trim();
    if (tagsIdx !== -1 && cells[tagsIdx]?.trim()) {
      row.tags = cells[tagsIdx].trim().split(',').map(t => t.trim().toLowerCase()).filter(Boolean);
    }
    rows.push(row);
  }
  preview.value = rows;
}

function onCSVInput(): void {
  parseCSV(csvInput.value);
}

const validRows = computed(() => preview.value.filter(r => !r._error));

// ── template download ─────────────────────────────────────────────────────────
const CSV_TEMPLATE = `ip,hostname,tags
10.0.0.10,web-01,"production,web"
10.0.0.20,db-01,production
10.0.0.30,,
`;

const JSON_TEMPLATE = JSON.stringify([
  { ip: '10.0.0.10', hostname: 'web-01', tags: ['production', 'web'] },
  { ip: '10.0.0.20', hostname: 'db-01', tags: ['production'] },
  { ip: '10.0.0.30' },
], null, 2) + '\n';

function downloadTemplate() {
  const isCSV = activeTab.value === 'csv';
  const content = isCSV ? CSV_TEMPLATE : JSON_TEMPLATE;
  const mime = isCSV ? 'text/csv' : 'application/json';
  const filename = isCSV ? 'hosts-template.csv' : 'hosts-template.json';
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
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
    const rows = validRows.value;
    if (!rows.length) {
      csvParseError.value = preview.value.length
        ? 'No valid rows to import (fix errors above).'
        : 'Paste CSV data above.';
      return;
    }
    emit('submit', rows.map(r => ({
      ip: r.ip,
      hostname: r.hostname,
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
        <div class="bulk-hint-row">
          <p class="bulk-hint">
            Columns: <code>ip</code> (required), <code>hostname</code>,
            <code>tags</code> (comma-separated names; quote if multiple:
            <code>"production,web"</code>). Tag names are matched by name —
            new tags are created automatically with a default color.
          </p>
          <button
            type="button"
            class="template-btn"
            @click="downloadTemplate"
          >
            ↓ Download template
          </button>
        </div>
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
            placeholder="ip,hostname,os,tags&#10;10.0.0.10,web-01,linux,&quot;production,web&quot;"
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
              {{ row.ip }}<span
                v-if="row.hostname"
                class="muted"
              > — {{ row.hostname }}</span>
              <span
                v-if="row.tags?.length"
                class="muted"
              > [{{ row.tags.join(', ') }}]</span>
            </span>
          </div>
          <p class="preview-summary">
            {{ validRows.length }} valid /
            {{ preview.length - validRows.length }} error{{ preview.length - validRows.length === 1 ? '' : 's' }}
          </p>
        </div>
      </div>

      <!-- JSON tab -->
      <div
        v-else
        class="bulk-tab-panel"
      >
        <div class="bulk-hint-row">
          <p class="bulk-hint">
            Paste a JSON array of host objects. Each entry must include
            <code>ip</code>; <code>hostname</code> and <code>tags</code>
            (name array) are optional. Tag names are matched by name —
            new tags are created automatically with a default color.
          </p>
          <button
            type="button"
            class="template-btn"
            @click="downloadTemplate"
          >
            ↓ Download template
          </button>
        </div>
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
        :disabled="activeTab === 'csv' && validRows.length === 0"
        @click="onSubmit"
      >
        <template v-if="activeTab === 'csv' && validRows.length > 0">
          Import {{ validRows.length }} host{{ validRows.length === 1 ? '' : 's' }}
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
.bulk-hint-row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-3);
}
.bulk-hint {
  font-size: 0.78rem;
  color: var(--text-muted);
  margin: 0;
  flex: 1;
}
.template-btn {
  flex-shrink: 0;
  background: none;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-sm);
  padding: 3px var(--space-2);
  font-size: 0.72rem;
  font-family: var(--font-body);
  color: var(--accent-strong);
  cursor: pointer;
  white-space: nowrap;
}
.template-btn:hover {
  background: var(--bg-sunken);
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
