import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router';
import { useAuthStore } from './stores/auth';
import { useSetupStore } from './stores/setup';

const Placeholder = () => import('./views/_Placeholder.vue');

const routes: RouteRecordRaw[] = [
  { path: '/',                             redirect: '/dashboard' },
  { path: '/dashboard',                    name: 'dashboard',   component: Placeholder },
  { path: '/setup/admin',                  name: 'setupAdmin',  component: () => import('./views/SetupAdmin.vue') },
  { path: '/setup/license',                name: 'setupLicense',component: () => import('./views/SetupLicense.vue') },
  { path: '/inventory/zones',              name: 'zones',       component: Placeholder },
  { path: '/inventory/hosts',              name: 'hosts',       component: Placeholder },
  { path: '/inventory/agents',             name: 'agents',      component: Placeholder },
  { path: '/operations/scan-jobs',         name: 'scanJobs',    component: Placeholder },
  { path: '/operations/scan-jobs/:id',     name: 'scanJob',     component: Placeholder },
  { path: '/operations/push-status',       name: 'pushStatus',  component: Placeholder },
  { path: '/admin/users',                  name: 'users',       component: Placeholder },
  { path: '/admin/licence',                name: 'licence',     component: Placeholder },
  { path: '/admin/settings',               name: 'settings',    component: Placeholder },
  { path: '/:pathMatch(.*)*',              redirect: '/dashboard' },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});

// Ensure both stores are referenced so this import is not dropped by the
// TS checker. Authentication is enforced by TAuthGate in App.vue, not the
// router; keeping the import here documents the store dependency and
// leaves room for a future refinement that handles 401s in the guard.
void useAuthStore;

router.beforeEach(async (to) => {
  const setup = useSetupStore();

  // 1. Ensure we have setup status at least once per session load. The
  //    store's loading flag prevents concurrent refreshes.
  if (!setup.status && !setup.loading) {
    await setup.refresh();
  }

  // 2. If setup is required, force everything to /setup/admin or
  //    /setup/license depending on progress.
  if (setup.status?.setup_required) {
    if (to.path.startsWith('/setup/')) return true;
    if (setup.status.admin_created) return { path: '/setup/license' };
    return { path: '/setup/admin' };
  }

  // 3. Setup complete — anywhere under /setup is stale; redirect home.
  if (to.path.startsWith('/setup/')) {
    return { path: '/dashboard' };
  }

  // 4. JWT is enforced via TAuthGate in App.vue.
  return true;
});
