import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  { path: '/',             component: () => import('./views/Dashboard.vue'),          name: 'dashboard' },
  { path: '/orgs',         component: () => import('./views/Organisations.vue'),      name: 'orgs' },
  { path: '/orgs/:id',     component: () => import('./views/OrganisationDetail.vue'), name: 'org' },
  { path: '/licenses',     component: () => import('./views/Licences.vue'),           name: 'licences' },
  { path: '/licenses/:id', component: () => import('./views/LicenceDetail.vue'),      name: 'licence' },
  { path: '/audit',        component: () => import('./views/AuditLog.vue'),           name: 'audit' },
  { path: '/superadmins',  component: () => import('./views/Superadmins.vue'),        name: 'superadmins' },
  { path: '/:pathMatch(.*)*', redirect: '/' },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});
