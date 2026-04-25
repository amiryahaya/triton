import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import TenantDetail from '../../src/views/TenantDetail.vue';

const mockGetTenant = vi.fn();
const mockRenewLicence = vi.fn();
const mockDeleteTenant = vi.fn();
const mockRouterBack = vi.fn();
const mockRouterPush = vi.fn();

vi.mock('../../src/stores/apiClient', () => ({
  useApiClient: () => ({
    get: () => ({
      getPlatformTenant: mockGetTenant,
      renewTenantLicence: mockRenewLicence,
      deletePlatformTenant: mockDeleteTenant,
    }),
  }),
}));

vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { id: 't-1' } }),
  useRouter: () => ({ back: mockRouterBack, push: mockRouterPush }),
}));

const TENANT = {
  id: 't-1',
  name: 'Acme Corp',
  licenceId: 'lk-abc',
  licenceStatus: 'active' as const,
  expiresAt: '2027-01-01T00:00:00Z',
  createdAt: '',
  updatedAt: '',
};

beforeEach(() => {
  vi.clearAllMocks();
  mockGetTenant.mockResolvedValue(TENANT);
  mockRenewLicence.mockResolvedValue({ status: 'ok' });
  mockDeleteTenant.mockResolvedValue(undefined);
  vi.spyOn(window, 'confirm').mockReturnValue(true);
});

describe('TenantDetail view', () => {
  it('loads and renders tenant details on mount', async () => {
    const wrapper = mount(TenantDetail);
    await flushPromises();

    expect(mockGetTenant).toHaveBeenCalledWith('t-1');
    expect(wrapper.html()).toContain('Acme Corp');
    expect(wrapper.html()).toContain('lk-abc');
  });

  it('shows error message when load fails', async () => {
    mockGetTenant.mockRejectedValue(new Error('not found'));
    const wrapper = mount(TenantDetail);
    await flushPromises();

    expect(wrapper.html()).toContain('not found');
  });

  it('calls renewTenantLicence with the input key on form submit', async () => {
    const wrapper = mount(TenantDetail);
    await flushPromises();

    await wrapper.find('input').setValue('new-licence-key');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(mockRenewLicence).toHaveBeenCalledWith('t-1', 'new-licence-key');
    expect(mockGetTenant).toHaveBeenCalledTimes(2); // initial load + reload after renew
  });

  it('shows renew error when renewTenantLicence throws', async () => {
    mockRenewLicence.mockRejectedValue(new Error('invalid key'));
    const wrapper = mount(TenantDetail);
    await flushPromises();

    await wrapper.find('input').setValue('bad-key');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(wrapper.html()).toContain('invalid key');
  });

  it('calls deletePlatformTenant and navigates away on confirm', async () => {
    const wrapper = mount(TenantDetail);
    await flushPromises();

    const dangerBtn = wrapper.find('button.danger');
    await dangerBtn.trigger('click');
    await flushPromises();

    expect(mockDeleteTenant).toHaveBeenCalledWith('t-1');
    expect(mockRouterPush).toHaveBeenCalledWith('/platform/tenants');
  });

  it('does not delete when user cancels confirm dialog', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    const wrapper = mount(TenantDetail);
    await flushPromises();

    await wrapper.find('button.danger').trigger('click');
    await flushPromises();

    expect(mockDeleteTenant).not.toHaveBeenCalled();
  });
});
