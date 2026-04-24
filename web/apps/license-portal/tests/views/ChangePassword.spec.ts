import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';
import ChangePassword from '../../src/views/ChangePassword.vue';
import { useApiClient } from '../../src/stores/apiClient';
import { useAuthStore } from '../../src/stores/auth';

beforeEach(() => { vi.clearAllMocks(); });

async function mountCP() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/', component: { template: '<div/>' } }],
  });
  await router.push('/');
  await router.isReady();
  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  const w = mount(ChangePassword, { global: { plugins: [pinia, router] } });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue({
    changePassword: vi.fn().mockResolvedValue({
      token: 'new-jwt', expiresAt: '2026-04-25T00:00:00Z',
    }),
  } as unknown as ReturnType<typeof client.get>);
  w.unmount();
  return { w: mount(ChangePassword, { global: { plugins: [pinia, router] } }), router };
}

describe('ChangePassword view', () => {
  it('requires new + confirm to match before submit', async () => {
    const { w } = await mountCP();
    await flushPromises();
    await w.find('[data-test="cp-current"]').setValue('current-pw');
    await w.find('[data-test="cp-next"]').setValue('newPassword123!');
    await w.find('[data-test="cp-confirm"]').setValue('different');
    const submit = w.find('[data-test="cp-submit"]');
    expect((submit.element as HTMLButtonElement).disabled).toBe(true);
    w.unmount();
  });

  it('submit calls changePassword and rotates the JWT', async () => {
    const { w } = await mountCP();
    await flushPromises();
    await w.find('[data-test="cp-current"]').setValue('current-pw');
    await w.find('[data-test="cp-next"]').setValue('newPassword123!');
    await w.find('[data-test="cp-confirm"]').setValue('newPassword123!');
    await w.find('[data-test="cp-submit"]').trigger('click');
    await flushPromises();

    const client = useApiClient();
    expect(client.get().changePassword).toHaveBeenCalledWith({
      current: 'current-pw', next: 'newPassword123!',
    });
    const auth = useAuthStore();
    expect(auth.setToken).toHaveBeenCalledWith('new-jwt');
    w.unmount();
  });
});
