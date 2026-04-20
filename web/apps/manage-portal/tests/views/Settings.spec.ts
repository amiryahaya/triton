import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Settings from '../../src/views/Settings.vue';
import { useSettingsStore } from '../../src/stores/settings';

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Settings view', () => {
  it('calls settings.fetch on mount and renders all five fields', async () => {
    const wrapper = mount(Settings, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              settings: {
                settings: {
                  parallelism: 10,
                  gatewayListen: ':8443',
                  gatewayHostname: 'localhost',
                  reportServerURL: 'https://report.example.com',
                  instanceID: 'inst-abc123',
                },
                loading: false,
              },
            },
          }),
        ],
      },
    });
    const store = useSettingsStore();
    await flushPromises();

    expect(store.fetch).toHaveBeenCalledTimes(1);

    const html = wrapper.html();
    expect(html).toContain('Parallelism');
    expect(html).toContain('10');
    expect(html).toContain('Gateway listen');
    expect(html).toContain(':8443');
    expect(html).toContain('Gateway hostname');
    expect(html).toContain('localhost');
    expect(html).toContain('Report server URL');
    expect(html).toContain('https://report.example.com');
    expect(html).toContain('Instance ID');
    expect(html).toContain('inst-abc123');
    wrapper.unmount();
  });

  it('shows a loading placeholder when settings is null', async () => {
    const wrapper = mount(Settings, {
      global: {
        plugins: [
          createTestingPinia({
            createSpy: vi.fn,
            initialState: {
              settings: { settings: null, loading: true },
            },
          }),
        ],
      },
    });
    await flushPromises();
    expect(wrapper.html()).toContain('Loading…');
    wrapper.unmount();
  });
});
