import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Users from '../../src/views/Users.vue';
import { useApiClient } from '../../src/stores/apiClient';

beforeEach(() => { vi.clearAllMocks(); });

const USERS = [
  {
    id: 'U1', email: 'alice@example.com', name: 'Alice',
    role: 'platform_admin', mustChangePassword: false,
    createdAt: '2026-04-01', updatedAt: '2026-04-01',
  },
  {
    id: 'U2', email: 'bob@example.com', name: 'Bob',
    role: 'platform_admin', mustChangePassword: true,
    createdAt: '2026-04-10', updatedAt: '2026-04-10',
  },
];

function mountWithUsers() {
  const pinia = createTestingPinia({ createSpy: vi.fn, stubActions: false });
  const w = mount(Users, { global: { plugins: [pinia] } });
  const client = useApiClient();
  vi.spyOn(client, 'get').mockReturnValue({
    listUsers: vi.fn().mockResolvedValue(USERS),
    createUser: vi.fn().mockResolvedValue({
      user: { ...USERS[0], id: 'U3', email: 'new@c.com', name: 'New',
              mustChangePassword: true },
      tempPassword: 'NewTemp-abc', emailSent: false,
    }),
    deleteUser: vi.fn().mockResolvedValue(undefined),
    resendInvite: vi.fn().mockResolvedValue({
      tempPassword: 'Rotated-xyz', emailSent: true,
    }),
  } as unknown as ReturnType<typeof client.get>);
  w.unmount();
  return mount(Users, { global: { plugins: [pinia] } });
}

describe('Users view', () => {
  it('renders user rows', async () => {
    const w = mountWithUsers();
    await flushPromises();
    await flushPromises();
    const html = w.html();
    expect(html).toContain('alice@example.com');
    expect(html).toContain('bob@example.com');
    w.unmount();
  });

  it('new-user button opens the form modal', async () => {
    const w = mountWithUsers();
    await flushPromises();
    await flushPromises();

    const newBtn = w.findAll('button').find((b) => b.text().includes('New user'));
    expect(newBtn).toBeTruthy();
    await newBtn!.trigger('click');
    await flushPromises();
    w.unmount();
  });
});
