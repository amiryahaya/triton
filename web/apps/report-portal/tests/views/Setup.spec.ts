import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import Setup from '../../src/views/Setup.vue';

const mockFirstSetup = vi.fn();
const mockSetupStatus = vi.fn();
const mockRouterReplace = vi.fn();

vi.mock('../../src/stores/apiClient', () => ({
  useApiClient: () => ({
    get: () => ({
      firstSetup: mockFirstSetup,
      setupStatus: mockSetupStatus,
    }),
  }),
}));

vi.mock('vue-router', () => ({
  useRouter: () => ({ replace: mockRouterReplace }),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Setup view', () => {
  it('renders form inputs for name and email', () => {
    const wrapper = mount(Setup);
    expect(wrapper.find('input[name="name"]').exists()).toBe(true);
    expect(wrapper.find('input[name="email"]').exists()).toBe(true);
  });

  it('calls firstSetup with name and email on submit and shows tempPassword', async () => {
    mockFirstSetup.mockResolvedValue({ id: 'u-1', tempPassword: 'T3mp!pass' });
    const wrapper = mount(Setup);

    await wrapper.find('input[name="name"]').setValue('Admin');
    await wrapper.find('input[name="email"]').setValue('admin@example.com');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(mockFirstSetup).toHaveBeenCalledWith({ name: 'Admin', email: 'admin@example.com' });
    expect(wrapper.html()).toContain('T3mp!pass');
  });

  it('shows error message when API throws', async () => {
    mockFirstSetup.mockRejectedValue(new Error('email taken'));
    const wrapper = mount(Setup);

    await wrapper.find('input[name="name"]').setValue('Admin');
    await wrapper.find('input[name="email"]').setValue('a@b.com');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(wrapper.html()).toContain('email taken');
  });

  it('goToLogin navigates to / after setup completes', async () => {
    mockFirstSetup.mockResolvedValue({ id: 'u-1', tempPassword: 'pw' });
    const wrapper = mount(Setup);

    await wrapper.find('input[name="name"]').setValue('Admin');
    await wrapper.find('input[name="email"]').setValue('a@b.com');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    await wrapper.find('button').trigger('click');
    expect(mockRouterReplace).toHaveBeenCalledWith('/');
  });
});
