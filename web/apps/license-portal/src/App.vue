<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  TAppShell, TSidebar, TThemeToggle, TAppSwitcher, TCrumbBar, TUserMenu,
  TToastHost, useTheme, useToast, type Crumb,
} from '@triton/ui';
import { TAuthGate } from '@triton/auth';
import { nav, apps, PORTAL_ACCENT } from './nav';
import { useAuthStore } from './stores/auth';
import { useApiClient } from './stores/apiClient';

useTheme();
const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const api = useApiClient();
const toast = useToast();

const currentHref = computed(() => `#${route.path}`);

const crumbs = computed<Crumb[]>(() => {
  const segments = route.path.split('/').filter(Boolean);
  if (segments.length === 0) return [{ label: 'Dashboard' }];
  const first = segments[0]!;
  const labels: Record<string, string> = {
    orgs: 'Organisations',
    licenses: 'Licences',
    audit: 'Audit log',
    admin: 'Admin',
    users: 'Users',
    setup: 'Setup',
    'change-password': 'Change password',
  };
  const parent = labels[first] ?? first;
  if (segments.length === 1) return [{ label: parent }];
  return [
    { label: parent, href: `#/${first}` },
    { label: segments.slice(1).join(' / ') },
  ];
});

const userName = computed(() => auth.claims?.name || auth.claims?.sub || '');
const userRole = computed(() => 'Platform admin');

const loginError = ref<string>('');
const loginBusy = ref<boolean>(false);

async function onLogin(creds: { email: string; password: string }) {
  loginError.value = '';
  loginBusy.value = true;
  try {
    const resp = await api.get().login(creds);
    auth.setToken(resp.token);
    auth.setMustChange(resp.mustChangePassword);
    if (resp.mustChangePassword) {
      await router.replace('/change-password');
    }
  } catch (err) {
    loginError.value = err instanceof Error ? err.message : 'Sign-in failed';
  } finally {
    loginBusy.value = false;
  }
}

async function signOut() {
  try { await api.get().logout(); } catch { /* best-effort */ }
  auth.clear();
  toast.info({ title: 'Signed out' });
  await router.replace('/');
}
</script>

<template>
  <TAuthGate
    type="jwt"
    title="Triton License Server"
    subtitle="Sign in to continue."
    :error="loginError"
    :busy="loginBusy"
    @login="onLogin"
  >
    <TAppShell :portal-accent="PORTAL_ACCENT">
      <template #sidebar>
        <TSidebar
          :nav="nav"
          portal-title="Triton"
          portal-subtitle="Licence"
          :current-href="currentHref"
        />
      </template>
      <template #topbar>
        <TCrumbBar :crumbs="crumbs" />
        <div class="top-right">
          <TAppSwitcher :apps="apps" current-id="license" />
          <TThemeToggle />
          <TUserMenu
            :name="userName"
            :role="userRole"
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
.top-right {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: var(--space-2);
}
</style>
