import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Security from '../../src/views/Security.vue';
import { useSecurityStore } from '../../src/stores/security';

beforeEach(() => {
  vi.clearAllMocks();
});

const LOCKOUT_A = {
  email: 'alice@example.com',
  ip: '127.0.0.1',
  failures: 5,
  first_failure: '2026-04-22T08:45:12Z',
  last_failure: '2026-04-22T08:47:33Z',
  locked_until: '2026-04-22T09:00:12Z',
};
const LOCKOUT_B = {
  email: 'bob@example.com',
  ip: '10.0.0.1',
  failures: 7,
  first_failure: '2026-04-22T09:00:00Z',
  last_failure: '2026-04-22T09:01:00Z',
  locked_until: '2026-04-22T09:15:00Z',
};

function mountWithItems(items = [LOCKOUT_A, LOCKOUT_B]) {
  return mount(Security, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          stubActions: true,
          initialState: { security: { items, loading: false } },
        }),
      ],
    },
  });
}

describe('Security view', () => {
  it('renders rows from store items and calls fetch on mount', async () => {
    const wrapper = mountWithItems();
    const security = useSecurityStore();
    await flushPromises();

    expect(security.fetch).toHaveBeenCalledTimes(1);

    const html = wrapper.html();
    expect(html).toContain('alice@example.com');
    expect(html).toContain('bob@example.com');
    expect(html).toContain('127.0.0.1');
    expect(html).toContain('10.0.0.1');
    wrapper.unmount();
  });

  it('clicking Unlock opens the confirm dialog with email in the message', async () => {
    const wrapper = mountWithItems();
    await flushPromises();

    await wrapper.find('[data-test="unlock-alice@example.com|127.0.0.1"]').trigger('click');
    await flushPromises();

    const dialog = document.querySelector('[data-test="confirm-dialog"]');
    expect(dialog).not.toBeNull();
    expect(dialog!.textContent).toContain('alice@example.com');
    expect(dialog!.textContent).toContain('127.0.0.1');
    wrapper.unmount();
  });

  it('confirming unlock calls store.remove and closes the dialog', async () => {
    const wrapper = mountWithItems();
    const security = useSecurityStore();
    await flushPromises();

    await wrapper.find('[data-test="unlock-alice@example.com|127.0.0.1"]').trigger('click');
    await flushPromises();

    const okBtn = document.querySelector('.t-confirm-ok') as HTMLButtonElement | null;
    expect(okBtn).not.toBeNull();
    okBtn!.click();
    await flushPromises();

    expect(security.remove).toHaveBeenCalledWith('alice@example.com', '127.0.0.1');
    expect(document.querySelector('[data-test="confirm-dialog"]')).toBeNull();
    wrapper.unmount();
  });

  it('clicking Refresh calls store.fetch', async () => {
    const wrapper = mountWithItems();
    const security = useSecurityStore();
    await flushPromises();

    const refreshBtn = wrapper.findAll('button').find((b) => b.text().includes('Refresh'));
    expect(refreshBtn).toBeTruthy();
    await refreshBtn!.trigger('click');
    await flushPromises();

    expect(security.fetch).toHaveBeenCalledTimes(2);
    wrapper.unmount();
  });
});
