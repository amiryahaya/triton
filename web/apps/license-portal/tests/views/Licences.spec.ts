import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Licences from '../../src/views/Licences.vue';
import { useApiClient } from '../../src/stores/apiClient';

beforeEach(() => { vi.clearAllMocks(); });

const LICENCES = [
  {
    id: 'L1', orgID: 'O1', orgName: 'Acme',
    tier: 'pro', seats: 5, seatsUsed: 2,
    issuedAt: '2026-04-01', expiresAt: '2027-04-01',
    revoked: false, revokedAt: null, notes: '', createdAt: '2026-04-01',
    features: {
      report: true, manage: false, comprehensive_profile: false,
      diff_trend: false, custom_policy: false, sso: false,
    },
    limits: [{ metric: 'scans', window: 'total', cap: 1000 }],
    soft_buffer_pct: 10,
    product_scope: 'report',
    schedule: '',
    scheduleJitterSeconds: 0,
  },
];

const ORGS = [
  { id: 'O1', name: 'Acme', contact: '', notes: '',
    createdAt: '2026-04-01', updatedAt: '2026-04-01' },
];

function mountWith() {
  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  const w = mount(Licences, {
    global: { plugins: [pinia] },
  });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue({
    licences: vi.fn().mockResolvedValue(LICENCES),
    orgs: vi.fn().mockResolvedValue(ORGS),
    createLicence: vi.fn().mockResolvedValue(LICENCES[0]),
  } as unknown as ReturnType<typeof client.get>);
  // Re-mount so onMounted fires after the spy is in place.
  w.unmount();
  return mount(Licences, { global: { plugins: [pinia] } });
}

describe('Licences view', () => {
  it('renders rows from bare array response', async () => {
    const w = mountWith();
    await flushPromises();
    await flushPromises();
    const html = w.html();
    expect(html).toContain('Acme');
    expect(html).toContain('pro');
    expect(html).toContain('1000');
    w.unmount();
  });

  it('opens LicenceForm when New licence is clicked', async () => {
    const w = mountWith();
    await flushPromises();
    await flushPromises();

    const btns = w.findAll('button');
    const newBtn = btns.find((b) => b.text().includes('New licence'));
    expect(newBtn).toBeTruthy();
    await newBtn!.trigger('click');
    await flushPromises();

    expect(document.body.textContent).toContain('Create licence');
    w.unmount();
  });
});
