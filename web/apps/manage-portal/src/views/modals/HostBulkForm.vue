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
  { "hostname": "web-01.prod", "ip": "10.0.0.10", "os": "linux", "ssh_port": 22 },
  { "hostname": "db-01.prod", "ip": "10.0.0.20", "ssh_port": 22 }
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
  const errors: string[] = [];
  for (let i = 0; i < parsed.length; i++) {
    const row = parsed[i];
    if (!isRecord(row)) {
      errors.push(`Entry ${i}: must be an object.`);
      continue;
    }
    if (typeof row.hostname !== 'string' || !row.hostname.trim()) {
      errors.push(`Entry ${i}: "hostname" is required.`);
    }
    if (typeof row.ip !== 'string' || !row.ip.trim()) {
      errors.push(`Entry ${i}: "ip" is required.`);
    }
    if (errors.length === 0) {
      out.push({
        hostname: (row.hostname as string).trim(),
        ip: (row.ip as string).trim(),
        os: typeof row.os === 'string' ? row.os : undefined,
        ssh_port: typeof row.ssh_port === 'number' ? row.ssh_port : undefined,
        tag_ids: Array.isArray(row.tag_ids)
          ? (row.tag_ids as unknown[]).filter((x): x is string => typeof x === 'string')
          : undefined,
        tags: Array.isArray(row.tags)
          ? (row.tags as unknown[]).filter((x): x is string => typeof x === 'string')
          : undefined,
      });
    }
  }
  if (errors.length > 0) {
    jsonError.value = errors.join('\n');
    return null;
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
  ip: string;
  os?: string;
  ssh_port?: number;
  tags?: string[];
  _error?: string;
}

const csvInput = ref('');
const csvParseError = ref('');
const preview = ref<CsvRow[]>([]);

const CSV_TEMPLATE =
  'hostname,ip,os,ssh_port,tags\n' +
  'web-01.prod,10.0.0.1,linux,22,"production,web"\n';

function downloadTemplate(): void {
  const blob = new Blob([CSV_TEMPLATE], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'hosts-template.csv';
  a.click();
  URL.revokeObjectURL(url);
}

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

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/;

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
  const hostnameIdx = headers.indexOf('hostname');
  const ipIdx = headers.indexOf('ip');

  if (hostnameIdx === -1) {
    csvParseError.value = 'CSV must have a "hostname" column.';
    return;
  }
  if (ipIdx === -1) {
    csvParseError.value = 'CSV must have an "ip" column.';
    return;
  }

  const osIdx = headers.indexOf('os');
  const sshPortIdx = headers.indexOf('ssh_port');
  const tagsIdx = headers.indexOf('tags');

  const rows: CsvRow[] = [];
  for (let i = 1; i < nonEmpty.length; i++) {
    const lineNum = i + 1;
    const cells = splitCSVLine(nonEmpty[i]);
    const hostname = cells[hostnameIdx]?.trim() ?? '';
    const ip = cells[ipIdx]?.trim() ?? '';
    const row: CsvRow = { hostname, ip };

    if (!hostname) {
      row._error = `Row ${lineNum}: hostname is required`;
    } else if (!ip) {
      row._error = `Row ${lineNum}: ip is required`;
    } else if (!IP_RE.test(ip)) {
      row._error = `Row ${lineNum}: invalid IP address "${ip}"`;
    } else if (sshPortIdx !== -1 && cells[sshPortIdx]?.trim()) {
      const raw = cells[sshPortIdx].trim();
      const p = parseInt(raw, 10);
      if (isNaN(p) || p < 1 || p > 65535) {
        row._error = `Row ${lineNum}: ssh_port must be 1–65535, got "${raw}"`;
      } else {
        row.ssh_port = p;
      }
    }

    if (!row._error) {
      if (osIdx !== -1 && cells[osIdx]?.trim()) row.os = cells[osIdx].trim();
      if (tagsIdx !== -1 && cells[tagsIdx]?.trim()) {
        row.tags = cells[tagsIdx].trim().split(',').map(t => t.trim()).filter(Boolean);
      }
    }

    rows.push(row);
  }

  // Duplicate detection within the file
  const seenHostnames = new Map<string, number>();
  const seenIPs = new Map<string, number>();
  for (let i = 0; i < rows.length; i++) {
    if (rows[i]._error) continue;
    const { hostname, ip } = rows[i];
    const lineNum = i + 2;
    if (seenHostnames.has(hostname)) {
      rows[i]._error = `Row ${lineNum}: duplicate hostname "${hostname}" (first seen at row ${seenHostnames.get(hostname)! + 1})`;
    } else {
      seenHostnames.set(hostname, i + 1);
    }
    if (!rows[i]._error) {
      if (seenIPs.has(ip)) {
        rows[i]._error = `Row ${lineNum}: duplicate IP "${ip}" (first seen at row ${seenIPs.get(ip)! + 1})`;
      } else {
        seenIPs.set(ip, i + 1);
      }
    }
  }

  preview.value = rows;
}

function onCSVInput(): void {
  parseCSV(csvInput.value);
}

const validRows = computed(() => preview.value.filter(r => !r._error));

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
      hostname: r.hostname,
      ip: r.ip,
      os: r.os,
      ssh_port: r.ssh_port,
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
        <div class="csv-header">
          <p class="bulk-hint">
            Columns: <code>hostname</code> (required), <code>ip</code> (required),
            <code>os</code>, <code>ssh_port</code> (default 22),
            <code>tags</code> (comma-separated; quote if multiple:
            <code>"production,web"</code>)
          </p>
          <button
            type="button"
            class="template-link"
            @click="downloadTemplate"
          >
            Download CSV template
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
            placeholder="hostname,ip,os,ssh_port,tags&#10;web-01.prod,10.0.0.10,linux,22,&quot;production,web&quot;"
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
            >{{ row._error }}</span>
            <span v-else>
              {{ row.hostname }} — {{ row.ip }}<span
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
        <p class="bulk-hint">
          Paste a JSON array. Each entry requires <code>hostname</code> and <code>ip</code>.
          Optional: <code>os</code>, <code>ssh_port</code>, <code>tag_ids</code> (UUID array),
          <code>tags</code> (name array).
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
.csv-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-2);
}
.template-link {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 0.78rem;
  color: var(--accent-strong);
  text-decoration: underline;
  white-space: nowrap;
  padding: 0;
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
