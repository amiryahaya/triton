import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Licence from '../../src/views/Licence.vue';
import { useLicenceStore } from '../../src/stores/licence';

// Stub vue-router's useRouter so we can assert on the push spy without
// having to wire up a full router. We expose the spy on the returned
// object so tests can assert directly.
const pushSpy = vi.fn();
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: pushSpy }),
}));

beforeEach(() => {
  vi.clearAllMocks();
  pushSpy.mockClear();
});

describe('Licence view', () => {
  it('fetches the licence summary on mount and shows Active when loaded', async () => {
    const wrapper = mount(Licence, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              licence: {
                summary: {
                  tier: 'active',
                  features: {},
                  limits: {},
                  expiresAt: null,
                  licenseServerURL: null,
                },
                loading: false,
              },
            },
          }),
        ],
      },
    });
    const licence = useLicenceStore();
    await flushPromises();

    expect(licence.fetch).toHaveBeenCalledTimes(1);
    const html = wrapper.html();
    expect(html).toContain('Active');
    // TPill renders a variant-suffixed class.
    expect(html).toMatch(/t-pill--safe/);
    wrapper.unmount();
  });

  it('navigates to /setup/license when Re-activate is clicked', async () => {
    const wrapper = mount(Licence, {
      global: {
        plugins: [createTestingPinia({ createSpy: vi.fn })],
      },
    });
    await flushPromises();

    const btn = wrapper
      .findAll('button')
      .find((b) => b.text().includes('Re-activate'));
    expect(btn).toBeTruthy();
    await btn!.trigger('click');
    expect(pushSpy).toHaveBeenCalledTimes(1);
    expect(pushSpy).toHaveBeenCalledWith('/setup/license');
    wrapper.unmount();
  });
});
