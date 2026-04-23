import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';
import Machines from '../../src/views/Machines.vue';
import { useMachinesStore } from '../../src/stores/machines';

beforeEach(() => {
  vi.clearAllMocks();
});

const HOST_A = {
  hostname: 'app01', readiness_pct: 72,
  safe_count: 40, transitional_count: 10, deprecated_count: 4, unsafe_count: 2,
  sparkline: [], trend_direction: 'improving' as const, trend_delta_pct: 5,
  refreshed_at: '2026-04-22T10:00:00Z',
};
const HOST_B = {
  hostname: 'db01', readiness_pct: 45,
  safe_count: 20, transitional_count: 18, deprecated_count: 12, unsafe_count: 5,
  sparkline: [], trend_direction: 'declining' as const, trend_delta_pct: -3,
  refreshed_at: '2026-04-22T10:05:00Z',
};
const SCAN_1 = {
  id: 'scan-1', hostname: 'app01', org_id: 'o1', created_at: '2026-04-20T10:00:00Z',
  finding_count: 56, pqc_safe: 40, pqc_transitional: 10, pqc_deprecated: 4, pqc_unsafe: 2, readiness_pct: 72,
};

function makeRouter(path: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/machines', name: 'machines', component: { template: '<div/>' } },
      { path: '/machines/:hostname', name: 'machine', component: { template: '<div/>' } },
      { path: '/scans/:id', name: 'scan', component: { template: '<div/>' } },
      { path: '/', component: { template: '<div/>' } },
    ],
  });
  void router.push(path);
  return router;
}

async function mountAt(path: string, state: { items?: unknown[]; history?: unknown[] } = {}) {
  const router = makeRouter(path);
  await router.isReady();
  return mount(Machines, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          stubActions: true,
          initialState: {
            machines: {
              items: state.items ?? [],
              history: state.history ?? [],
              loading: false,
              historyLoading: false,
            },
          },
        }),
        router,
      ],
      stubs: { TLineChart: true },
    },
  });
}

describe('Machines view — list mode', () => {
  it('calls fetch on mount and renders hostname rows', async () => {
    const wrapper = await mountAt('/machines', { items: [HOST_A, HOST_B] });
    const store = useMachinesStore();
    await flushPromises();

    expect(store.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('app01');
    expect(html).toContain('db01');
    expect(html).toContain('72');  // readiness_pct
    wrapper.unmount();
  });

  it('clicking a row navigates to /machines/:hostname', async () => {
    const wrapper = await mountAt('/machines', { items: [HOST_A] });
    await flushPromises();

    const row = wrapper.find('[data-test="machine-row-app01"]');
    expect(row.exists()).toBe(true);
    await row.trigger('click');
    await flushPromises();

    expect(wrapper.vm.$route.path).toBe('/machines/app01');
    wrapper.unmount();
  });
});

describe('Machines view — detail mode', () => {
  it('calls fetchHistory on mount with hostname from route param', async () => {
    const wrapper = await mountAt('/machines/app01', { history: [SCAN_1] });
    const store = useMachinesStore();
    await flushPromises();

    expect(store.fetchHistory).toHaveBeenCalledWith('app01');
    wrapper.unmount();
  });

  it('renders stat cards + findings from latest history entry', async () => {
    const wrapper = await mountAt('/machines/app01', { history: [SCAN_1] });
    await flushPromises();

    const html = wrapper.html();
    expect(html).toContain('40'); // safe
    expect(html).toContain('10'); // transitional
    expect(html).toContain('4');  // deprecated
    expect(html).toContain('2');  // unsafe
    wrapper.unmount();
  });
});
