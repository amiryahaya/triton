import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Licence from '../../src/views/Licence.vue';
import type { LicenceSummary } from '@triton/api-client';
import { useApiClient } from '../../src/stores/apiClient';

// Stub vue-router's useRouter so we can assert on the push spy without
// having to wire up a full router.
const pushSpy = vi.fn();
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: pushSpy }),
}));

// Mock API methods — these will be set up on the apiClient store.get() spy.
const mockApi = {
  getLicence: vi.fn(),
  refreshLicence: vi.fn(),
  replaceLicenceKey: vi.fn(),
  deactivateLicence: vi.fn(),
  cancelDeactivation: vi.fn(),
};

beforeEach(() => {
  vi.clearAllMocks();
  pushSpy.mockClear();
  mockApi.getLicence.mockClear();
  mockApi.refreshLicence.mockClear();
  mockApi.replaceLicenceKey.mockClear();
  mockApi.deactivateLicence.mockClear();
  mockApi.cancelDeactivation.mockClear();
});

const stubs = {
  TStatCard: {
    props: ['label', 'value'],
    template:
      '<div class="t-stat-card-stub"><span class="label">{{ label }}</span><span class="value">{{ value }}</span></div>',
  },
  TPanel: {
    props: ['title'],
    template: '<section class="t-panel-stub" :data-title="title"><slot /></section>',
  },
  TButton: {
    template: '<button><slot /></button>',
  },
};

function makeSummary(overrides: Partial<LicenceSummary> = {}): LicenceSummary {
  return {
    tier: 'pro',
    features: { manage: true },
    limits: {
      seats: { cap: 5, used: 1 },
      hosts: { cap: 20, used: 3 },
      agents: { cap: 10, used: 2 },
      scans: { cap: 500, used: 100, soft_buffer_ceiling: 550 },
    },
    license_server_url: 'https://license.tritonscans.com',
    instance_id: 'inst-1',
    last_pushed_at: null,
    last_push_error: '',
    consecutive_failures: 0,
    pending_deactivation: false,
    active_scans: 0,
    ...overrides,
  };
}

function mountWithSummary(summary: LicenceSummary | null = makeSummary()) {
  const wrapper = mount(Licence, {
    global: {
      stubs,
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          initialState: {
            licence: {
              summary,
              loading: false,
              error: '',
            },
          },
        }),
      ],
    },
  });

  // Wire the apiClient store's get() spy to return our mock API.
  const apiClient = useApiClient();
  vi.mocked(apiClient.get).mockReturnValue(mockApi as never);

  return wrapper;
}

describe('Licence view — lifecycle actions', () => {
  it('shows Refresh, Replace Key, and Deactivate buttons', async () => {
    const wrapper = mountWithSummary();
    await flushPromises();

    expect(wrapper.find('[data-testid="btn-refresh"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="btn-replace-key"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="btn-deactivate"]').exists()).toBe(true);

    wrapper.unmount();
  });

  it('does not show pending deactivation banner when pending_deactivation=false', async () => {
    const wrapper = mountWithSummary(makeSummary({ pending_deactivation: false }));
    await flushPromises();

    expect(wrapper.text()).not.toContain('Deactivation pending');

    wrapper.unmount();
  });

  it('shows pending deactivation banner when pending_deactivation=true', async () => {
    const wrapper = mountWithSummary(makeSummary({ pending_deactivation: true, active_scans: 3 }));
    await flushPromises();

    expect(wrapper.text()).toContain('Deactivation pending');
    expect(wrapper.text()).toContain('3');

    wrapper.unmount();
  });

  it('shows Replace Key modal on Replace Key button click', async () => {
    const wrapper = mountWithSummary();
    await flushPromises();

    expect(wrapper.find('[data-testid="replace-key-modal"]').exists()).toBe(false);

    await wrapper.find('[data-testid="btn-replace-key"]').trigger('click');
    await wrapper.vm.$nextTick();

    expect(wrapper.find('[data-testid="replace-key-modal"]').exists()).toBe(true);

    wrapper.unmount();
  });

  it('shows Deactivate modal on Deactivate button click', async () => {
    const wrapper = mountWithSummary();
    await flushPromises();

    expect(wrapper.find('[data-testid="deactivate-modal"]').exists()).toBe(false);

    await wrapper.find('[data-testid="btn-deactivate"]').trigger('click');
    await wrapper.vm.$nextTick();

    expect(wrapper.find('[data-testid="deactivate-modal"]').exists()).toBe(true);

    wrapper.unmount();
  });

  it('calls cancelDeactivation and reloads on Cancel Deactivation click', async () => {
    mockApi.cancelDeactivation.mockResolvedValue({ ok: true });

    const wrapper = mountWithSummary(makeSummary({ pending_deactivation: true, active_scans: 2 }));
    await flushPromises();

    const licenceStore = (wrapper.vm as { licence: { fetch: ReturnType<typeof vi.fn> } }).licence;
    const fetchSpy = licenceStore.fetch as ReturnType<typeof vi.fn>;

    await wrapper.find('[data-testid="btn-cancel-deactivation"]').trigger('click');
    await flushPromises();

    expect(mockApi.cancelDeactivation).toHaveBeenCalledTimes(1);
    expect(fetchSpy).toHaveBeenCalled();

    wrapper.unmount();
  });

  it('deactivate modal shows red confirm path when active_scans = 0', async () => {
    const wrapper = mountWithSummary(makeSummary({ active_scans: 0 }));
    await flushPromises();

    await wrapper.find('[data-testid="btn-deactivate"]').trigger('click');
    await wrapper.vm.$nextTick();

    const modal = wrapper.find('[data-testid="deactivate-modal"]');
    expect(modal.find('[data-testid="btn-confirm-deactivate"]').exists()).toBe(true);
    expect(modal.find('[data-testid="btn-schedule-deactivate"]').exists()).toBe(false);

    wrapper.unmount();
  });

  it('deactivate modal shows amber schedule path when active_scans > 0', async () => {
    const wrapper = mountWithSummary(makeSummary({ active_scans: 2 }));
    await flushPromises();

    await wrapper.find('[data-testid="btn-deactivate"]').trigger('click');
    await wrapper.vm.$nextTick();

    const modal = wrapper.find('[data-testid="deactivate-modal"]');
    expect(modal.find('[data-testid="btn-schedule-deactivate"]').exists()).toBe(true);
    expect(modal.find('[data-testid="btn-confirm-deactivate"]').exists()).toBe(false);

    wrapper.unmount();
  });
});
