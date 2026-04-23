import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Dashboard from '../../src/views/Dashboard.vue';
import { useApiClient } from '../../src/stores/apiClient';

beforeEach(() => { vi.clearAllMocks(); });

const STATS = {
  totalOrgs: 7,
  totalLicenses: 4,
  activeLicenses: 3,
  revokedLicenses: 1,
  expiredLicenses: 0,
  totalActivations: 12,
  activeSeats: 9,
};

describe('Dashboard view', () => {
  it('fetches stats on mount and renders all 7 stat cards', async () => {
    // We mount first, then swap the client mock before onMounted's async
    // fetch resolves. Simpler pattern: mount with the spy already wired.
    const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
    const wrapper = mount(Dashboard, {
      global: { plugins: [pinia] },
    });
    const client = useApiClient();
    vi.spyOn(client, 'get').mockReturnValue({
      dashboard: vi.fn().mockResolvedValue(STATS),
    } as unknown as ReturnType<typeof client.get>);

    // Unmount the first mount (its onMounted ran before we wired the spy)
    // and re-mount so onMounted now picks up the stubbed client.
    wrapper.unmount();
    const w2 = mount(Dashboard, {
      global: { plugins: [pinia] },
    });
    await flushPromises();
    await flushPromises();

    const html = w2.html();
    expect(html).toContain('7');   // totalOrgs
    expect(html).toContain('4');   // totalLicenses
    expect(html).toContain('3');   // activeLicenses
    expect(html).toContain('12');  // totalActivations
    expect(html).toContain('9');   // activeSeats
    w2.unmount();
  });
});
