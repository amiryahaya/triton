import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Overview from '../../src/views/Overview.vue';
import { useOverviewStore } from '../../src/stores/overview';

beforeEach(() => {
  vi.clearAllMocks();
});

const SUMMARY = {
  readiness: {
    readiness_pct: 67,
    safe_count: 120,
    transitional_count: 45,
    deprecated_count: 18,
    unsafe_count: 7,
    total_findings: 190,
    machine_count: 12,
  },
  trend: {
    monthly_points: [
      { month: '2026-01', readiness_pct: 55, safe_count: 90, unsafe_count: 10 },
      { month: '2026-02', readiness_pct: 60, safe_count: 100, unsafe_count: 9 },
      { month: '2026-03', readiness_pct: 67, safe_count: 120, unsafe_count: 7 },
    ],
    direction: 'improving' as const,
    delta_pct: 12,
  },
  projection: {
    target_pct: 80,
    deadline_year: 2030,
    est_completion_year: 2029,
    on_track: true,
  },
  policy_verdicts: [
    { policy_name: 'nacsa-2030', policy_label: 'NACSA-2030', verdict: 'PASS' as const, violation_count: 0, findings_checked: 190 },
    { policy_name: 'cnsa-2.0',   policy_label: 'CNSA-2.0',   verdict: 'WARN' as const, violation_count: 3, findings_checked: 190 },
  ],
  top_blockers: [
    { subject: 'rsa-1024-key', hostname: 'app01', algorithm: 'RSA-1024', pqc_status: 'UNSAFE' as const, migration_priority: 95, file_path: '/etc/ssl/old.key', category: 'key' },
  ],
  machine_health: { red: 2, yellow: 4, green: 6 },
};

function mountWithSummary(summary: typeof SUMMARY | null = SUMMARY) {
  return mount(Overview, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          stubActions: true,
          initialState: { overview: { summary, loading: false } },
        }),
      ],
      stubs: { TLineChart: true, TDataTable: true },
    },
  });
}

describe('Overview view', () => {
  it('calls fetch on mount and renders readiness + policy verdict chips', async () => {
    const wrapper = mountWithSummary();
    const store = useOverviewStore();
    await flushPromises();

    expect(store.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('67');        // readiness_pct
    expect(html).toContain('NACSA-2030');
    expect(html).toContain('CNSA-2.0');
    wrapper.unmount();
  });

  it('renders stat cards with machine_health + readiness counts', async () => {
    const wrapper = mountWithSummary();
    await flushPromises();

    const html = wrapper.html();
    expect(html).toContain('120'); // safe_count
    expect(html).toContain('45');  // transitional_count
    expect(html).toContain('18');  // deprecated_count
    expect(html).toContain('7');   // unsafe_count
    expect(html).toContain('12');  // machine_count
    wrapper.unmount();
  });

  it('renders empty state when summary is null', async () => {
    const wrapper = mountWithSummary(null);
    await flushPromises();

    const html = wrapper.html();
    expect(html).toMatch(/no data/i);
    wrapper.unmount();
  });
});
