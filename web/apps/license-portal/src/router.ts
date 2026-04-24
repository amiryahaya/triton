import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  { path: '/setup',           component: () => import('./views/Setup.vue'),              name: 'setup' },
  { path: '/change-password', component: () => import('./views/ChangePassword.vue'),     name: 'change-password' },
  { path: '/',                component: () => import('./views/Dashboard.vue'),           name: 'dashboard' },
  { path: '/orgs',            component: () => import('./views/Organisations.vue'),       name: 'orgs' },
  { path: '/orgs/:id',        component: () => import('./views/OrganisationDetail.vue'),  name: 'org' },
  { path: '/licenses',        component: () => import('./views/Licences.vue'),            name: 'licences' },
  { path: '/licenses/:id',    component: () => import('./views/LicenceDetail.vue'),       name: 'licence' },
  { path: '/audit',           component: () => import('./views/AuditLog.vue'),            name: 'audit' },
  { path: '/admin/users',     component: () => import('./views/Users.vue'),               name: 'users' },
  { path: '/:pathMatch(.*)*', redirect: '/' },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});

// setupChecked is reset on hard refresh. After logout, a new
// /setup/status probe happens on next SPA load (page refresh).
// Resetting it in-process would re-probe on every navigation after
// logout which is unnecessary — logout always triggers a full
// redirect to '/' which resets state via page reload.
let setupChecked = false;

router.beforeEach(async (to) => {
  if (to.path === '/setup') return true;

  if (!setupChecked) {
    setupChecked = true;
    try {
      const { useApiClient } = await import('./stores/apiClient');
      const { needsSetup } = await useApiClient().get().setupStatus();
      if (needsSetup) return { path: '/setup' };
    } catch {
      // proceed if probe fails
    }
  }

  const { useAuthStore } = await import('./stores/auth');
  const auth = useAuthStore();
  if (auth.mustChangePassword && to.path !== '/change-password') {
    return { path: '/change-password' };
  }

  return true;
});
