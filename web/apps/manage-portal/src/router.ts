import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router';
import { useAuthStore } from './stores/auth';
import { useSetupStore } from './stores/setup';

const routes: RouteRecordRaw[] = [
  { path: '/',                             redirect: '/dashboard' },
  { path: '/dashboard',                    name: 'dashboard',   component: () => import('./views/Dashboard.vue') },
  { path: '/setup/admin',                  name: 'setupAdmin',  component: () => import('./views/SetupAdmin.vue') },
  { path: '/setup/license',                name: 'setupLicense',component: () => import('./views/SetupLicense.vue') },
  { path: '/auth/change-password',         name: 'changePassword', component: () => import('./views/ChangePassword.vue') },
  { path: '/inventory/hosts',              name: 'hosts',       component: () => import('./views/Hosts.vue') },
  { path: '/inventory/tags',               name: 'tags',        component: () => import('./views/Tags.vue') },
  { path: '/inventory/agents',             name: 'agents',      component: () => import('./views/Agents.vue') },
  { path: '/inventory/credentials',         name: 'credentials', component: () => import('./views/Credentials.vue') },
  { path: '/inventory/discover',           name: 'discover',    component: () => import('./views/Discovery.vue') },
  { path: '/operations/scan-jobs',         name: 'scanJobs',    component: () => import('./views/ScanJobs.vue') },
  { path: '/operations/scan-jobs/new',     name: 'scanJobsNew', component: () => import('./views/EnqueueWizard.vue') },
  { path: '/operations/scan-jobs/:id',     name: 'scanJob',     component: () => import('./views/ScanJobs.vue') },
  { path: '/operations/push-status',       name: 'pushStatus',  component: () => import('./views/PushStatus.vue') },
  { path: '/admin/users',                  name: 'users',       component: () => import('./views/Users.vue') },
  { path: '/admin/security',               name: 'security',    component: () => import('./views/Security.vue') },
  { path: '/admin/licence',                name: 'licence',     component: () => import('./views/Licence.vue') },
  { path: '/admin/settings',               name: 'settings',    component: () => import('./views/Settings.vue') },
  { path: '/:pathMatch(.*)*',              redirect: '/dashboard' },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});

router.beforeEach(async (to) => {
  const setup = useSetupStore();
  const auth = useAuthStore();

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

  // 4. Forced-change: a logged-in user with must_change_password=true is
  //    trapped on /auth/change-password until they comply. The endpoint
  //    is reachable; everything else redirects there.
  const tokenLive = Boolean(auth.token) && !auth.isExpired;
  if (tokenLive && auth.claims?.mustChangePassword) {
    if (to.path === '/auth/change-password') return true;
    return { path: '/auth/change-password' };
  }

  // 5. JWT is enforced via TAuthGate in App.vue.
  return true;
});
