import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';
import LicenceDetail from '../../src/views/LicenceDetail.vue';
import { useApiClient } from '../../src/stores/apiClient';

beforeEach(() => { vi.clearAllMocks(); });

const LIC = {
  id: 'L1', orgID: 'O1', orgName: 'Acme',
  tier: 'pro', seats: 5, seatsUsed: 2,
  issuedAt: '2026-04-01T00:00:00Z',
  expiresAt: '2027-04-01T00:00:00Z',
  revoked: false, revokedAt: null, notes: '', createdAt: '2026-04-01',
  features: {
    report: true, manage: false, comprehensive_profile: false,
    diff_trend: true, custom_policy: false, sso: false,
  },
  limits: [{ metric: 'scans', window: 'total', cap: 1000 }],
  soft_buffer_pct: 10,
  product_scope: 'report',
  schedule: '',
  scheduleJitterSeconds: 0,
};

const ACTIVATIONS = [
  {
    id: 'A1', licenseID: 'L1', machineID: 'mach-1',
    hostname: 'host1', os: 'linux', arch: 'amd64',
    token: 'tok', activatedAt: '2026-04-02', lastSeenAt: '2026-04-20',
    deactivatedAt: null, active: true,
  },
];

async function mountDetail() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/licenses/:id', component: { template: '<div/>' } }],
  });
  await router.push('/licenses/L1');
  await router.isReady();

  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  // Wire the spy BEFORE mounting so onMounted picks it up.
  const w0 = mount(LicenceDetail, { global: { plugins: [pinia, router] } });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue({
    licence: vi.fn().mockResolvedValue(LIC),
    activations: vi.fn().mockResolvedValue(ACTIVATIONS),
    revokeLicence: vi.fn().mockResolvedValue(undefined),
    downloadAgentYaml: vi.fn().mockResolvedValue('instance_id: x\n'),
  } as unknown as ReturnType<typeof client.get>);
  w0.unmount();
  return mount(LicenceDetail, { global: { plugins: [pinia, router] } });
}

describe('LicenceDetail view', () => {
  it('renders the licence UUID hero (not a fictional key field)', async () => {
    const w = await mountDetail();
    await flushPromises();
    await flushPromises();

    const html = w.html();
    expect(html).toContain('L1');
    expect(html).toContain('Acme');
    expect(html).toContain('Copy licence ID');
    expect(html).not.toContain('Copy key');
    w.unmount();
  });

  it('renders the activations from a bare array', async () => {
    const w = await mountDetail();
    await flushPromises();
    await flushPromises();

    const html = w.html();
    expect(html).toContain('host1');
    expect(html).toContain('linux');
    w.unmount();
  });

  it('clicking Revoke opens the confirm dialog', async () => {
    const w = await mountDetail();
    await flushPromises();
    await flushPromises();

    const btns = w.findAll('button');
    const revokeBtn = btns.find((b) => b.text().trim() === 'Revoke');
    expect(revokeBtn).toBeTruthy();
    await revokeBtn!.trigger('click');
    await flushPromises();

    expect(document.body.textContent).toMatch(/revoke/i);
    w.unmount();
  });
});
