import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TDataTable, { type Column } from '../src/composite/TDataTable.vue';

interface Row extends Record<string, unknown> {
  id: string;
  name: string;
  count: number;
}

const columns: Column<Row>[] = [
  { key: 'name', label: 'Name', width: '2fr' },
  { key: 'count', label: 'Count', width: '1fr', align: 'right', numeric: true },
];

const rows: Row[] = [
  { id: 'a', name: 'Alpha', count: 10 },
  { id: 'b', name: 'Bravo', count: 42 },
  { id: 'c', name: 'Charlie', count: 7 },
];

describe('TDataTable', () => {
  it('renders one row per item', () => {
    const w = mount(TDataTable, { props: { columns, rows, rowKey: 'id' } });
    expect(w.findAll('.t-tbl-row')).toHaveLength(3);
  });

  it('renders header labels', () => {
    const w = mount(TDataTable, { props: { columns, rows, rowKey: 'id' } });
    expect(w.find('.t-tbl-head').text()).toContain('Name');
    expect(w.find('.t-tbl-head').text()).toContain('Count');
  });

  it('emits row-click with the row object', async () => {
    const w = mount(TDataTable, { props: { columns, rows, rowKey: 'id' } });
    await w.findAll('.t-tbl-row')[0]!.trigger('click');
    const ev = w.emitted('row-click')?.[0]?.[0];
    expect(ev).toEqual(rows[0]);
  });

  it('with selectable=true renders a select column and checkbox', () => {
    const w = mount(TDataTable, {
      props: { columns, rows, rowKey: 'id', selectable: true, selected: [] },
    });
    expect(w.findAll('.t-tbl-check')).toHaveLength(rows.length + 1); // + header
  });

  it('emits update:selected when a row checkbox is clicked', async () => {
    const w = mount(TDataTable, {
      props: { columns, rows, rowKey: 'id', selectable: true, selected: [] },
    });
    const rowCheckboxes = w.findAll('.t-tbl-row .t-tbl-check');
    await rowCheckboxes[1]!.trigger('click');
    const ev = w.emitted('update:selected')?.[0]?.[0];
    expect(ev).toEqual(['b']);
  });

  it('empty state renders when rows empty', () => {
    const w = mount(TDataTable, {
      props: { columns, rows: [], rowKey: 'id', emptyText: 'No hosts yet' },
    });
    expect(w.text()).toContain('No hosts yet');
  });
});
