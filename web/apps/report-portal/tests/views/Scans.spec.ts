import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';
import Scans from '../../src/views/Scans.vue';
import { useScansStore } from '../../src/stores/scans';

beforeEach(() => {
  vi.clearAllMocks();
});

const SCAN_1 = {
  id: 'scan-1', hostname: 'app01', org_id: 'o1', created_at: '2026-04-20T10:00:00Z',
  finding_count: 56, pqc_safe: 40, pqc_transitional: 10, pqc_deprecated: 4, pqc_unsafe: 2, readiness_pct: 72,
};
const SCAN_2 = {
  id: 'scan-2', hostname: 'db01', org_id: 'o1', created_at: '2026-04-21T10:00:00Z',
  finding_count: 55, pqc_safe: 20, pqc_transitional: 18, pqc_deprecated: 12, pqc_unsafe: 5, readiness_pct: 45,
};
const FINDING_A = {
  id: 'f-1', scan_id: 'scan-1', finding_index: 0,
  subject: 'rsa-2048-key', algorithm: 'RSA-2048', key_size: 2048,
  pqc_status: 'TRANSITIONAL' as const, file_path: '/etc/ssl/cert.key',
  category: 'key', migration_priority: 70,
};
const DETAIL_1 = { ...SCAN_1, result: {} };

function makeRouter(path: string) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/scans', name: 'scans', component: { template: '<div/>' } },
      { path: '/scans/:id', name: 'scan', component: { template: '<div/>' } },
      { path: '/', component: { template: '<div/>' } },
    ],
  });
  void router.push(path);
  return router;
}

async function mountAt(path: string, state: { items?: unknown[]; detail?: unknown; findings?: unknown[] } = {}) {
  const router = makeRouter(path);
  await router.isReady();
  return mount(Scans, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          stubActions: true,
          initialState: {
            scans: {
              items: state.items ?? [],
              detail: state.detail ?? null,
              findings: state.findings ?? [],
              loading: false,
              detailLoading: false,
            },
          },
        }),
        router,
      ],
    },
  });
}

describe('Scans view — list mode', () => {
  it('calls fetch on mount and renders scan rows', async () => {
    const wrapper = await mountAt('/scans', { items: [SCAN_1, SCAN_2] });
    const store = useScansStore();
    await flushPromises();

    expect(store.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('app01');
    expect(html).toContain('db01');
    wrapper.unmount();
  });

  it('clicking a row navigates to /scans/:id', async () => {
    const wrapper = await mountAt('/scans', { items: [SCAN_1] });
    await flushPromises();

    const row = wrapper.find('[data-test="scan-row-scan-1"]');
    expect(row.exists()).toBe(true);
    await row.trigger('click');
    await flushPromises();

    expect(wrapper.vm.$route.path).toBe('/scans/scan-1');
    wrapper.unmount();
  });
});

describe('Scans view — detail mode', () => {
  it('calls fetchDetail on mount with scan id from route param', async () => {
    const wrapper = await mountAt('/scans/scan-1', { detail: DETAIL_1, findings: [FINDING_A] });
    const store = useScansStore();
    await flushPromises();

    expect(store.fetchDetail).toHaveBeenCalledWith('scan-1');
    wrapper.unmount();
  });

  it('renders stat cards + findings table from stubbed detail', async () => {
    const wrapper = await mountAt('/scans/scan-1', { detail: DETAIL_1, findings: [FINDING_A] });
    await flushPromises();

    const html = wrapper.html();
    expect(html).toContain('RSA-2048');
    expect(html).toContain('rsa-2048-key');
    expect(html).toContain('40'); // pqc_safe
    wrapper.unmount();
  });
});
