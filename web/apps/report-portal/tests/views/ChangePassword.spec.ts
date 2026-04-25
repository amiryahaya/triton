import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import ChangePassword from '../../src/views/ChangePassword.vue';

const mockChangePassword = vi.fn();
const mockSetToken = vi.fn();
const mockRouterReplace = vi.fn();

vi.mock('../../src/stores/apiClient', () => ({
  useApiClient: () => ({
    get: () => ({ changePassword: mockChangePassword }),
  }),
}));

vi.mock('../../src/stores/auth', () => ({
  useAuthStore: () => ({ setToken: mockSetToken }),
}));

vi.mock('vue-router', () => ({
  useRouter: () => ({ replace: mockRouterReplace }),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('ChangePassword view', () => {
  it('renders current and new password fields', () => {
    const wrapper = mount(ChangePassword);
    expect(wrapper.find('input[name="current_password"]').exists()).toBe(true);
    expect(wrapper.find('input[name="new_password"]').exists()).toBe(true);
  });

  it('calls changePassword with both fields and sets new token on success', async () => {
    mockChangePassword.mockResolvedValue({ token: 'new-jwt', expiresAt: '' });
    const wrapper = mount(ChangePassword);

    await wrapper.find('input[name="current_password"]').setValue('oldpw');
    await wrapper.find('input[name="new_password"]').setValue('newpw');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(mockChangePassword).toHaveBeenCalledWith({ current: 'oldpw', next: 'newpw' });
    expect(mockSetToken).toHaveBeenCalledWith('new-jwt');
    expect(mockRouterReplace).toHaveBeenCalledWith('/');
  });

  it('shows error message when API throws', async () => {
    mockChangePassword.mockRejectedValue(new Error('wrong password'));
    const wrapper = mount(ChangePassword);

    await wrapper.find('input[name="current_password"]').setValue('bad');
    await wrapper.find('input[name="new_password"]').setValue('newpw');
    await wrapper.find('form').trigger('submit');
    await flushPromises();

    expect(wrapper.html()).toContain('wrong password');
    expect(mockRouterReplace).not.toHaveBeenCalled();
  });
});
