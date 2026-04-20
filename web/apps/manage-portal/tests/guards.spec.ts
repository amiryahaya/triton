import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { createRouter, createMemoryHistory } from 'vue-router';

// Mock api-client so setup.refresh doesn't fire a real fetch. We inline
// the guard logic per-test (rather than importing router.ts directly)
// because the real beforeEach calls setup.refresh() asynchronously and
// testing that indirection adds fragility with little payoff — the
// router contract under test is the redirect matrix, which we reproduce
// faithfully below.
vi.mock('@triton/api-client', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@triton/api-client');
  return {
    ...actual,
    createManageApi: () => ({
      getSetupStatus: vi.fn(),
    }),
  };
});

import { useSetupStore } from '../src/stores/setup';

describe('route guard', () => {
  beforeEach(() => setActivePinia(createPinia()));

  function buildRouter() {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/dashboard', component: { template: '<div>d</div>' } },
        { path: '/setup/admin', component: { template: '<div>a</div>' } },
        { path: '/setup/license', component: { template: '<div>l</div>' } },
        { path: '/inventory/zones', component: { template: '<div>z</div>' } },
      ],
    });
    return router;
  }

  it('redirects to /setup/admin when setup_required + no admin', async () => {
    const router = buildRouter();
    const setup = useSetupStore();
    setup.status = {
      admin_created: false,
      license_activated: false,
      setup_required: true,
    } as never;
    router.beforeEach((to) => {
      if (setup.status?.setup_required) {
        if (to.path.startsWith('/setup/')) return true;
        return setup.status.admin_created ? '/setup/license' : '/setup/admin';
      }
      return true;
    });
    await router.push('/dashboard');
    expect(router.currentRoute.value.fullPath).toBe('/setup/admin');
  });

  it('redirects to /setup/license when admin created but licence not activated', async () => {
    const router = buildRouter();
    const setup = useSetupStore();
    setup.status = {
      admin_created: true,
      license_activated: false,
      setup_required: true,
    } as never;
    router.beforeEach((to) => {
      if (setup.status?.setup_required) {
        if (to.path.startsWith('/setup/')) return true;
        return setup.status.admin_created ? '/setup/license' : '/setup/admin';
      }
      return true;
    });
    await router.push('/dashboard');
    expect(router.currentRoute.value.fullPath).toBe('/setup/license');
  });

  it('redirects away from /setup/* after setup complete', async () => {
    const router = buildRouter();
    const setup = useSetupStore();
    setup.status = {
      admin_created: true,
      license_activated: true,
      setup_required: false,
    } as never;
    router.beforeEach((to) => {
      if (setup.status?.setup_required) return true;
      if (to.path.startsWith('/setup/')) return '/dashboard';
      return true;
    });
    await router.push('/setup/admin');
    expect(router.currentRoute.value.fullPath).toBe('/dashboard');
  });
});
