import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import App from '../../src/App.vue';
import { createRouter, createMemoryHistory } from 'vue-router';

function makeRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/dashboard', component: { template: '<div>d</div>' } }],
  });
}

// TAuthGate must pass the slot through so the AppShell (and thus the
// topbar with the pill) is rendered in the test.
const authGateStub = { template: '<slot />' };

// Shared stubs: all heavy UI chrome is replaced with minimal fakes.
const sharedStubs = {
  TAuthGate: authGateStub,
  TAppShell: { template: '<div><slot name="topbar" /><slot /></div>' },
  TSidebar: true,
  TCrumbBar: true,
  TAppSwitcher: true,
  TThemeToggle: true,
  TUserMenu: true,
  TToastHost: true,
  TButton: true,
  TPill: {
    template: '<span class="pill-stub"><slot /></span>',
    props: ['variant', 'title'],
  },
};

describe('App.vue gateway cert pill', () => {
  it('hides the pill when cert_days_remaining >= 14', async () => {
    const pinia = createTestingPinia({
      createSpy: vi.fn,
      initialState: {
        auth: { token: 'valid' },
        gatewayHealth: {
          state: {
            ca_bootstrapped: true,
            listener_state: 'up',
            cert_expires_at: '2026-06-01T00:00:00Z',
            cert_days_remaining: 45,
          },
          loading: false,
        },
      },
    });

    const w = mount(App, {
      global: {
        plugins: [pinia, makeRouter()],
        stubs: sharedStubs,
      },
    });

    expect(w.html()).not.toContain('pill-stub');
    w.unmount();
  });

  it('shows the pill when cert_days_remaining < 14', async () => {
    const pinia = createTestingPinia({
      createSpy: vi.fn,
      initialState: {
        auth: { token: 'valid' },
        gatewayHealth: {
          state: {
            ca_bootstrapped: true,
            listener_state: 'up',
            cert_expires_at: '2026-04-28T00:00:00Z',
            cert_days_remaining: 7,
          },
          loading: false,
        },
      },
    });

    const w = mount(App, {
      global: {
        plugins: [pinia, makeRouter()],
        stubs: sharedStubs,
      },
    });

    expect(w.html()).toContain('pill-stub');
    // The pill content should include the remaining days count.
    expect(w.html()).toContain('7');
    w.unmount();
  });

  it('hides the pill when cert_days_remaining is exactly 0 (expired — no warning)', async () => {
    // cert_days_remaining <= 0 means the cert is already expired / not yet
    // issued; the pill hides and the admin must check the server logs.
    const pinia = createTestingPinia({
      createSpy: vi.fn,
      initialState: {
        auth: { token: 'valid' },
        gatewayHealth: {
          state: {
            ca_bootstrapped: false,
            listener_state: 'pending_setup',
            cert_expires_at: null,
            cert_days_remaining: 0,
          },
          loading: false,
        },
      },
    });

    const w = mount(App, {
      global: {
        plugins: [pinia, makeRouter()],
        stubs: sharedStubs,
      },
    });

    expect(w.html()).not.toContain('pill-stub');
    w.unmount();
  });

  it('hides the pill when gateway health state is null (fetch not yet complete)', async () => {
    const pinia = createTestingPinia({
      createSpy: vi.fn,
      initialState: {
        auth: { token: 'valid' },
        gatewayHealth: { state: null, loading: true },
      },
    });

    const w = mount(App, {
      global: {
        plugins: [pinia, makeRouter()],
        stubs: sharedStubs,
      },
    });

    expect(w.html()).not.toContain('pill-stub');
    w.unmount();
  });
});
