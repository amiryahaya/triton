import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router';
import { useAuthStore } from './stores/auth';

// Hash routing matches the spec §10.1: deployed HTML behind //go:embed
// resolves on any basePath without server rewrites. Deep links land here.
const routes: RouteRecordRaw[] = [
  { path: '/setup',                name: 'setup',                 component: () => import('./views/Setup.vue'),          meta: { public: true } },
  { path: '/change-password',      name: 'change-password',       component: () => import('./views/ChangePassword.vue'), meta: { public: true } },
  { path: '/',                     name: 'overview',              component: () => import('./views/Overview.vue') },
  { path: '/machines',             name: 'machines',              component: () => import('./views/Machines.vue') },
  { path: '/machines/:hostname',   name: 'machine',               component: () => import('./views/Machines.vue') },
  { path: '/scans',                name: 'scans',                 component: () => import('./views/Scans.vue') },
  { path: '/scans/:id',            name: 'scan',                  component: () => import('./views/Scans.vue') },
  { path: '/nacsa',                name: 'nacsa',                 component: () => import('./views/NacsaArahan9.vue') },
  { path: '/priority',             name: 'priority',              component: () => import('./views/Priority.vue') },
  { path: '/inventory',            name: 'inventory',             component: () => import('./views/Inventory.vue') },
  { path: '/certificates',         name: 'certificates',          component: () => import('./views/Certificates.vue') },
  { path: '/trend',                name: 'trend',                 component: () => import('./views/MigrationTrend.vue') },
  { path: '/diff',                 name: 'diff',                  component: () => import('./views/ScanDiff.vue') },
  { path: '/admin/users',          name: 'users',                 component: () => import('./views/Users.vue') },
  { path: '/admin/tenants',        name: 'tenants',               component: () => import('./views/Tenants.vue') },
  { path: '/admin/audit',          name: 'audit',                 component: () => import('./views/AuditLog.vue') },
  { path: '/platform/admins',      name: 'platform-admins',       component: () => import('./views/PlatformAdmins.vue') },
  { path: '/platform/tenants',     name: 'platform-tenants',      component: () => import('./views/PlatformTenants.vue') },
  { path: '/platform/tenants/:id', name: 'platform-tenant-detail', component: () => import('./views/TenantDetail.vue') },
  { path: '/:pathMatch(.*)*', redirect: '/' },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});

// If the user must change their password, redirect to the change-password
// view on every navigation until they comply.
router.beforeEach((to) => {
  const auth = useAuthStore();
  if (auth.claims?.mustChangePassword && to.name !== 'change-password') {
    return { name: 'change-password' };
  }
});

// Guard /platform/* routes: only platform_admin may access them.
// Any other authenticated role (org_admin, org_user, etc.) is redirected
// to the root overview. Unauthenticated users fall through to TAuthGate.
router.beforeEach((to) => {
  if (!to.path.startsWith('/platform')) return;
  const auth = useAuthStore();
  if (auth.claims && auth.claims.role !== 'platform_admin') {
    return { path: '/' };
  }
});
