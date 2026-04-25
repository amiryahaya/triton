import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import PlatformTenants from '../../src/views/PlatformTenants.vue';

const mockList = vi.fn();
const mockCreate = vi.fn();

vi.mock('../../src/stores/apiClient', () => ({
  useApiClient: () => ({ get: () => ({ listPlatformTenants: mockList, createPlatformTenant: mockCreate }) }),
}));

const TENANT_A = { id: 't-1', name: 'Acme Corp', licenceId: 'lk-1', licenceStatus: 'active' as const, expiresAt: '2027-01-01T00:00:00Z', createdAt: '', updatedAt: '' };

beforeEach(() => {
  vi.clearAllMocks();
  mockList.mockResolvedValue([TENANT_A]);
  mockCreate.mockResolvedValue({ ...TENANT_A, id: 't-2', name: 'Beta Inc' });
});

describe('PlatformTenants view', () => {
  it('loads and renders tenant list on mount', async () => {
    const wrapper = mount(PlatformTenants);
    await flushPromises();

    expect(mockList).toHaveBeenCalledTimes(1);
    expect(wrapper.html()).toContain('Acme Corp');
  });

  it('shows active badge for active tenants', async () => {
    const wrapper = mount(PlatformTenants);
    await flushPromises();
    expect(wrapper.html()).toContain('active');
  });

  it('calls createPlatformTenant on form submit', async () => {
    const wrapper = mount(PlatformTenants);
    await flushPromises();

    // Open the create modal
    const addBtn = wrapper.findAll('button').find(b => b.text().includes('Add'));
    await addBtn!.trigger('click');
    await flushPromises();

    const modal = wrapper.find('.modal');
    const inputs = modal.findAll('input');
    await inputs[0].setValue('lk-abc123');  // licenceKey
    await inputs[1].setValue('Admin Name'); // adminName
    await inputs[2].setValue('admin@example.com'); // adminEmail
    await modal.find('form').trigger('submit');
    await flushPromises();

    expect(mockCreate).toHaveBeenCalledWith({ licenceKey: 'lk-abc123', adminName: 'Admin Name', adminEmail: 'admin@example.com' });
  });

  it('clears stale error on reload', async () => {
    mockList.mockRejectedValueOnce(new Error('db error'));
    mockList.mockResolvedValue([TENANT_A]);

    const wrapper = mount(PlatformTenants);
    await flushPromises();
    expect(wrapper.html()).toContain('db error');

    await (wrapper.vm as any).load();
    await flushPromises();
    expect(wrapper.html()).not.toContain('db error');
  });
});
