<script setup lang="ts" generic="T extends Record<string, unknown>">
import { computed } from 'vue';

/**
 * Column descriptor for TDataTable. Always parameterised with your row type:
 *
 *   interface License { id: string; org: string; seats: number; }
 *   const columns: Column<License>[] = [...]
 *
 * Use `numeric: true` for columns whose values should render with the
 * display font's tabular numerals and right alignment in tables.
 */
export interface Column<R> {
  key: keyof R & string;
  label: string;
  width?: string;
  align?: 'left' | 'right' | 'center';
  numeric?: boolean;
}

const props = withDefaults(
  defineProps<{
    columns: Column<T>[];
    rows: T[];
    rowKey: keyof T & string;
    selectable?: boolean;
    selected?: Array<T[keyof T & string]>;
    emptyText?: string;
  }>(),
  { selectable: false, selected: () => [], emptyText: 'No data.' }
);

const emit = defineEmits<{
  'row-click': [row: T];
  'update:selected': [ids: Array<T[keyof T & string]>];
}>();

const selectedSet = computed(() => new Set(props.selected ?? []));

const gridCols = computed(() => {
  const parts = props.columns.map((c) => c.width ?? '1fr');
  return props.selectable ? `32px ${parts.join(' ')}` : parts.join(' ');
});

function toggle(id: T[keyof T & string]) {
  const next = new Set(selectedSet.value);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  emit('update:selected', Array.from(next));
}

function toggleAll() {
  if (selectedSet.value.size === props.rows.length) {
    emit('update:selected', []);
  } else {
    emit(
      'update:selected',
      props.rows.map((r) => r[props.rowKey] as T[keyof T & string])
    );
  }
}

function cellValue(row: T, col: Column<T>): string {
  const v = row[col.key];
  return v == null ? '' : String(v);
}
</script>

<template>
  <div class="t-tbl">
    <div
      class="t-tbl-head"
      :style="{ gridTemplateColumns: gridCols }"
    >
      <span
        v-if="selectable"
        class="t-tbl-check-wrap"
      >
        <button
          type="button"
          class="t-tbl-check"
          :class="{
            'is-checked': selectedSet.size === rows.length && rows.length > 0,
          }"
          :aria-label="
            selectedSet.size === rows.length ? 'Deselect all' : 'Select all'
          "
          @click="toggleAll"
        />
      </span>
      <span
        v-for="col in columns"
        :key="col.key"
        class="t-tbl-h"
        :class="{
          'is-right': col.align === 'right',
          'is-center': col.align === 'center',
        }"
      >{{ col.label }}</span>
    </div>

    <template v-if="rows.length === 0">
      <div class="t-tbl-empty">
        {{ emptyText }}
      </div>
    </template>

    <template v-else>
      <div
        v-for="row in rows"
        :key="String(row[rowKey])"
        class="t-tbl-row"
        :class="{ 'is-selected': selectedSet.has(row[rowKey] as never) }"
        :style="{ gridTemplateColumns: gridCols }"
        @click="emit('row-click', row)"
      >
        <span
          v-if="selectable"
          class="t-tbl-check-wrap"
          @click.stop
        >
          <button
            type="button"
            class="t-tbl-check"
            :class="{ 'is-checked': selectedSet.has(row[rowKey] as never) }"
            @click="toggle(row[rowKey] as never)"
          />
        </span>
        <span
          v-for="col in columns"
          :key="col.key"
          class="t-tbl-c"
          :class="{
            'is-right': col.align === 'right',
            'is-center': col.align === 'center',
            'is-num': col.numeric,
          }"
        >
          <slot
            :name="`cell:${col.key}`"
            :row="row"
            :value="row[col.key]"
          >
            {{ cellValue(row, col) }}
          </slot>
        </span>
      </div>
    </template>
  </div>
</template>

<style scoped>
.t-tbl {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  font-size: 0.72rem;
  font-family: var(--font-body);
}
.t-tbl-head {
  display: grid;
  padding: var(--space-2) var(--space-3);
  background: color-mix(in srgb, var(--bg-base) 50%, transparent);
  color: var(--text-subtle);
  border-bottom: 1px solid var(--border);
  font-size: 0.54rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  font-weight: 500;
}
.t-tbl-row {
  display: grid;
  padding: var(--space-2) var(--space-3);
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  color: var(--text-secondary);
  transition: background var(--motion-hover) var(--ease);
}
.t-tbl-row:hover { background: var(--accent-muted); }
.t-tbl-row.is-selected { background: var(--accent-muted); }
.t-tbl-row:last-child { border-bottom: none; }
.t-tbl-c,
.t-tbl-h { display: flex; align-items: center; min-width: 0; }
.t-tbl-c.is-num {
  font-family: var(--font-display);
  font-variant-numeric: tabular-nums;
  color: var(--text-primary);
}
.is-right { justify-content: flex-end; }
.is-center { justify-content: center; }

.t-tbl-empty {
  padding: var(--space-6) var(--space-4);
  text-align: center;
  color: var(--text-muted);
  font-size: 0.78rem;
}

.t-tbl-check-wrap { display: flex; align-items: center; }
.t-tbl-check {
  width: 13px;
  height: 13px;
  border: 1px solid var(--border-strong);
  border-radius: 3px;
  background: transparent;
  cursor: pointer;
  padding: 0;
  position: relative;
}
.t-tbl-check:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: 2px;
}
.t-tbl-check.is-checked {
  background: var(--accent);
  border-color: var(--accent);
}
.t-tbl-check.is-checked::after {
  content: '✓';
  position: absolute;
  top: -4px;
  left: 1px;
  color: var(--bg-base);
  font-family: var(--font-body);
  font-size: 0.72rem;
  font-weight: 700;
}
</style>
