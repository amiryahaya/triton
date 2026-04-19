import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router';

// Hash routing matches the spec §10.1: deployed HTML behind //go:embed
// resolves on any basePath without server rewrites. Deep links land here.
const routes: RouteRecordRaw[] = [
  { path: '/',                     name: 'overview',     component: () => import('./views/Overview.vue') },
  { path: '/machines',             name: 'machines',     component: () => import('./views/Machines.vue') },
  { path: '/machines/:hostname',   name: 'machine',      component: () => import('./views/Machines.vue') },
  { path: '/scans',                name: 'scans',        component: () => import('./views/Scans.vue') },
  { path: '/scans/:id',            name: 'scan',         component: () => import('./views/Scans.vue') },
  { path: '/nacsa',                name: 'nacsa',        component: () => import('./views/NacsaArahan9.vue') },
  { path: '/priority',             name: 'priority',     component: () => import('./views/Priority.vue') },
  { path: '/inventory',            name: 'inventory',    component: () => import('./views/Inventory.vue') },
  { path: '/certificates',         name: 'certificates', component: () => import('./views/Certificates.vue') },
  { path: '/trend',                name: 'trend',        component: () => import('./views/MigrationTrend.vue') },
  { path: '/diff',                 name: 'diff',         component: () => import('./views/ScanDiff.vue') },
  { path: '/admin/users',          name: 'users',        component: () => import('./views/Users.vue') },
  { path: '/admin/tenants',        name: 'tenants',      component: () => import('./views/Tenants.vue') },
  { path: '/admin/audit',          name: 'audit',        component: () => import('./views/AuditLog.vue') },
  { path: '/:pathMatch(.*)*', redirect: '/' },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});
