import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import { createRouter, createMemoryHistory } from 'vue-router';
import Setup from '../../src/views/Setup.vue';
import { useApiClient } from '../../src/stores/apiClient';

beforeEach(() => { vi.clearAllMocks(); });

async function mountSetup() {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/', component: { template: '<div/>' } }],
  });
  router.push('/');
  await router.isReady();
  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  const w = mount(Setup, { global: { plugins: [pinia, router] } });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue({
    setupFirstAdmin: vi.fn().mockResolvedValue({
      user: { id: 'U1', email: 'a@b', name: 'A', role: 'platform_admin',
              mustChangePassword: true, createdAt: '', updatedAt: '' },
      tempPassword: 'Xj3-abcd-ef',
      emailSent: true,
    }),
  } as unknown as ReturnType<typeof client.get>);
  w.unmount();
  return mount(Setup, { global: { plugins: [pinia, router] } });
}

describe('Setup view', () => {
  it('renders name + email fields', async () => {
    const w = await mountSetup();
    await flushPromises();
    expect(w.find('[data-test="setup-name"]').exists()).toBe(true);
    expect(w.find('[data-test="setup-email"]').exists()).toBe(true);
    w.unmount();
  });

  it('submit calls setupFirstAdmin and shows temp password', async () => {
    const w = await mountSetup();
    await flushPromises();

    await w.find('[data-test="setup-name"]').setValue('Alice');
    await w.find('[data-test="setup-email"]').setValue('alice@example.com');
    await w.find('[data-test="setup-submit"]').trigger('click');
    await flushPromises();

    const client = useApiClient();
    expect(client.get().setupFirstAdmin).toHaveBeenCalledWith({
      name: 'Alice',
      email: 'alice@example.com',
    });
    expect(w.html()).toContain('Xj3-abcd-ef');
    w.unmount();
  });
});
