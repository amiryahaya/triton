import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router';

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
