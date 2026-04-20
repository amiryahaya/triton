import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Users from '../../src/views/Users.vue';
import { useUsersStore } from '../../src/stores/users';

beforeEach(() => {
  vi.clearAllMocks();
});

function mountWithState() {
  return mount(Users, {
    global: {
      plugins: [
        createTestingPinia({
          createSpy: vi.fn,
          initialState: {
            users: {
              items: [
                {
                  id: 'u-1',
                  email: 'alice@example.com',
                  name: 'Alice Admin',
                  role: 'admin',
                  must_change_pw: false,
                  created_at: '2026-04-01T00:00:00Z',
                  updated_at: '2026-04-01T00:00:00Z',
                },
                {
                  id: 'u-2',
                  email: 'bob@example.com',
                  name: 'Bob Engineer',
                  role: 'network_engineer',
                  must_change_pw: true,
                  created_at: '2026-04-02T00:00:00Z',
                  updated_at: '2026-04-02T00:00:00Z',
                },
              ],
              loading: false,
            },
          },
        }),
      ],
    },
  });
}

describe('Users view', () => {
  it('calls users.fetch on mount and renders rows with role pills', async () => {
    const wrapper = mountWithState();
    const users = useUsersStore();
    await flushPromises();

    expect(users.fetch).toHaveBeenCalledTimes(1);

    const html = wrapper.html();
    expect(html).toContain('alice@example.com');
    expect(html).toContain('bob@example.com');
    expect(html).toContain('Alice Admin');
    // TPill renders a span with a variant-suffixed class.
    expect(html).toMatch(/t-pill--enterprise/);
    expect(html).toMatch(/t-pill--info/);
    // must_change_pw yes/no rendering.
    expect(html).toMatch(/yes/);
    expect(html).toMatch(/no/);
    wrapper.unmount();
  });

  it('opens UserCreatedResult with temp password after successful create', async () => {
    const wrapper = mountWithState();
    const users = useUsersStore();
    (users.create as ReturnType<typeof vi.fn>).mockResolvedValue({
      id: 'u-new',
      email: 'carol@example.com',
      role: 'network_engineer',
      temp_password: 'Sup3rSecretTemp!',
    });
    await flushPromises();

    // Open the create modal via the header "New user" button.
    const newBtn = wrapper
      .findAll('button')
      .find((b) => b.text().includes('New user'));
    expect(newBtn).toBeTruthy();
    await newBtn!.trigger('click');
    await flushPromises();

    // Fill email + name (teleported to body).
    const inputs = document.querySelectorAll('.t-modal input');
    // First input is email, second is name.
    const emailInput = inputs[0] as HTMLInputElement | undefined;
    const nameInput = inputs[1] as HTMLInputElement | undefined;
    expect(emailInput).toBeTruthy();
    expect(nameInput).toBeTruthy();
    emailInput!.value = 'carol@example.com';
    emailInput!.dispatchEvent(new Event('input'));
    nameInput!.value = 'Carol Op';
    nameInput!.dispatchEvent(new Event('input'));
    await flushPromises();

    // Submit via the modal footer's "Create" button.
    const submitBtn = Array.from(
      document.querySelectorAll('.t-modal-foot button'),
    ).find((b) => b.textContent?.trim() === 'Create') as HTMLButtonElement | undefined;
    expect(submitBtn).toBeTruthy();
    submitBtn!.click();
    await flushPromises();

    expect(users.create).toHaveBeenCalledTimes(1);
    expect(users.create).toHaveBeenCalledWith({
      email: 'carol@example.com',
      name: 'Carol Op',
      role: 'network_engineer',
    });

    // After create, the UserCreatedResult modal renders with the temp
    // password in a TCodeBlock <code> tag.
    const codeNodes = document.querySelectorAll('.t-modal code');
    const tempPasswordShown = Array.from(codeNodes).some(
      (c) => c.textContent?.includes('Sup3rSecretTemp!'),
    );
    expect(tempPasswordShown).toBe(true);
    wrapper.unmount();
  });
});
