<script setup lang="ts">
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  TAppShell,
  TSidebar,
  TThemeToggle,
  TAppSwitcher,
  TCrumbBar,
  TUserMenu,
  TToastHost,
  useTheme,
  type Crumb,
} from '@triton/ui';
import { TAuthGate } from '@triton/auth';
import { nav, apps, PORTAL_ACCENT } from './nav';
import { useAuthStore } from './stores/auth';

useTheme();
const route = useRoute();
const router = useRouter();
const auth = useAuthStore();

const currentHref = computed(() => `#${route.path}`);

const crumbs = computed<Crumb[]>(() => {
  const segments = route.path.split('/').filter(Boolean);
  if (segments.length === 0) return [{ label: 'Dashboard' }];
  const first = segments[0]!;
  const labels: Record<string, string> = {
    orgs: 'Organisations',
    licenses: 'Licences',
    audit: 'Audit log',
    superadmins: 'Superadmins',
  };
  const parent = labels[first] ?? first;
  if (segments.length === 1) return [{ label: parent }];
  return [
    { label: parent, href: `#/${first}` },
    { label: segments.slice(1).join(' / ') },
  ];
});

function signOut() {
  auth.clear();
  router.replace('/');
}
</script>

<template>
  <TAuthGate type="adminKey">
    <TAppShell :portal-accent="PORTAL_ACCENT">
      <template #sidebar>
        <TSidebar
          :nav="nav"
          portal-title="Triton"
          portal-subtitle="Licence"
          :current-href="currentHref"
        >
          <template #footer>
            <div class="foot">
              <strong>Superadmin</strong>
              <span>ops@triton</span>
            </div>
          </template>
        </TSidebar>
      </template>

      <template #topbar>
        <TCrumbBar :crumbs="crumbs" />
        <div class="top-right">
          <TAppSwitcher
            :apps="apps"
            current-id="license"
          />
          <TThemeToggle />
          <TUserMenu
            name="ops@triton"
            role="Superadmin"
            @sign-out="signOut"
          />
        </div>
      </template>

      <router-view />
    </TAppShell>
  </TAuthGate>
  <TToastHost />
</template>

<style scoped>
.foot {
  display: flex;
  flex-direction: column;
  font-size: 0.7rem;
  color: var(--text-muted);
}
.foot strong {
  color: var(--text-primary);
  font-family: var(--font-display);
  font-weight: 500;
  font-size: 0.78rem;
}
.top-right {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: var(--space-2);
}
</style>
