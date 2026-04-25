import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import PlatformAdmins from '../../src/views/PlatformAdmins.vue';

const mockList = vi.fn();
const mockInvite = vi.fn();
const mockDelete = vi.fn();

vi.mock('../../src/stores/apiClient', () => ({
  useApiClient: () => ({ get: () => ({ listPlatformAdmins: mockList, invitePlatformAdmin: mockInvite, deletePlatformAdmin: mockDelete }) }),
}));

// auth.claims.sub = current user id
vi.mock('../../src/stores/auth', () => ({
  useAuthStore: () => ({ claims: { sub: 'me-id' } }),
}));

const ADMIN_A = { id: 'a-1', org_id: null, email: 'alice@example.com', name: 'Alice', role: 'org_admin' as const, must_change_password: false, created_at: '' };
const ADMIN_B = { id: 'me-id', org_id: null, email: 'me@example.com', name: 'Me', role: 'org_admin' as const, must_change_password: false, created_at: '' };

beforeEach(() => {
  vi.clearAllMocks();
  mockList.mockResolvedValue([ADMIN_A, ADMIN_B]);
  mockInvite.mockResolvedValue({ ...ADMIN_A, id: 'a-2' });
  mockDelete.mockResolvedValue({});
});

describe('PlatformAdmins view', () => {
  it('loads and renders admin list on mount', async () => {
    const wrapper = mount(PlatformAdmins);
    await flushPromises();

    expect(mockList).toHaveBeenCalledTimes(1);
    expect(wrapper.html()).toContain('Alice');
    expect(wrapper.html()).toContain('Me');
  });

  it('disables delete button for the current user', async () => {
    const wrapper = mount(PlatformAdmins);
    await flushPromises();

    const rows = wrapper.findAll('tbody tr');
    // Row for ADMIN_B (me-id) should have disabled delete button
    const myRow = rows.find(r => r.html().includes('me@example.com'));
    expect(myRow?.find('button.danger').attributes('disabled')).toBeDefined();
    // Row for ADMIN_A should not be disabled
    const otherRow = rows.find(r => r.html().includes('alice@example.com'));
    expect(otherRow?.find('button.danger').attributes('disabled')).toBeUndefined();
  });

  it('shows invite form and calls invitePlatformAdmin on submit', async () => {
    const wrapper = mount(PlatformAdmins);
    await flushPromises();

    // Find the "Invite admin" button
    const inviteBtn = wrapper.findAll('button').find(b => b.text().includes('Invite'));
    await inviteBtn!.trigger('click');
    await flushPromises();
    // Fill form
    const modal = wrapper.find('.modal');
    const inputs = modal.findAll('input');
    await inputs[0].setValue('Bob');
    await inputs[1].setValue('bob@example.com');
    await modal.find('form').trigger('submit');
    await flushPromises();

    expect(mockInvite).toHaveBeenCalledWith({ name: 'Bob', email: 'bob@example.com' });
  });

  it('clears stale error on reload', async () => {
    mockList.mockRejectedValueOnce(new Error('network error'));
    mockList.mockResolvedValue([ADMIN_A]);

    const wrapper = mount(PlatformAdmins);
    await flushPromises();
    expect(wrapper.html()).toContain('network error');

    // Reload succeeds — error should be cleared
    await (wrapper.vm as any).load();
    await flushPromises();
    expect(wrapper.html()).not.toContain('network error');
  });
});
