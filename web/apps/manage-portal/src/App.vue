<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  TAppShell,
  TSidebar,
  TThemeToggle,
  TAppSwitcher,
  TCrumbBar,
  TUserMenu,
  TToastHost,
  TButton,
  useTheme,
  useToast,
  type Crumb,
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

// Human-readable crumb labels for each path segment. Detail routes
// (e.g. /operations/scan-jobs/:id) fall through to the raw segment if
// missing — good enough for phase 1; per-view overrides can land later.
const labels: Record<string, string> = {
  dashboard: 'Dashboard',
  inventory: 'Inventory',
  operations: 'Operations',
  admin: 'Admin',
  zones: 'Zones',
  hosts: 'Hosts',
  agents: 'Agents',
  'scan-jobs': 'Scan Jobs',
  'push-status': 'Push Status',
  users: 'Users',
  licence: 'Licence',
  settings: 'Settings',
  setup: 'Setup',
};

const crumbs = computed<Crumb[]>(() => {
  const segments = route.path.split('/').filter(Boolean);
  if (segments.length === 0) return [{ label: 'Dashboard' }];
  return segments.map((s, i) => {
    const label = labels[s] ?? s;
    if (i === segments.length - 1) return { label };
    return { label, href: `#/${segments.slice(0, i + 1).join('/')}` };
  });
});

// Derived user display — Pinia setup stores auto-unwrap refs, so
// auth.claims is the JwtClaims | null directly, not a computed.
const userName = computed(() => auth.claims?.name || auth.claims?.sub || '');
const userRole = computed(() => (auth.claims?.role === 'admin' ? 'Admin' : 'Engineer'));

const loginError = ref<string>('');
const loginBusy = ref<boolean>(false);

async function onLogin(creds: { email: string; password: string }) {
  loginError.value = '';
  loginBusy.value = true;
  try {
    const resp = await api.get().login(creds.email, creds.password);
    auth.setToken(resp.token);
    // Future phase: resp.must_change_password → push to change-password
    // view. Phase 1 has no such view; admins reset via the API directly.
  } catch (err) {
    loginError.value = err instanceof Error ? err.message : 'Sign-in failed';
  } finally {
    loginBusy.value = false;
  }
}

async function signOut() {
  try {
    await api.get().logout();
  } catch {
    // Best-effort: clear local state even if server-side delete fails.
  }
  auth.clear();
  toast.info({ title: 'Signed out', description: 'Session ended.' });
  router.replace('/dashboard');
}
</script>

<template>
  <!-- Setup routes render BELOW the auth gate — they don't need a JWT -->
  <!-- to reach. TAuthGate only activates when the user navigates to a -->
  <!-- non-setup route. The change-password view also renders standalone -->
  <!-- so forced-change users (JWT has mcp=true) aren't blocked by the -->
  <!-- AppShell chrome before they can comply. -->
  <template v-if="route.path.startsWith('/setup/') || route.path === '/auth/change-password'">
    <router-view />
  </template>
  <template v-else>
    <TAuthGate
      type="jwt"
      title="Triton Manage Server"
      subtitle="Sign in to manage your scanning fleet."
      :error="loginError"
      :busy="loginBusy"
      @login="onLogin"
    >
      <TAppShell :portal-accent="PORTAL_ACCENT">
        <template #sidebar>
          <TSidebar
            :nav="nav"
            portal-title="Triton"
            portal-subtitle="Manage"
            :current-href="currentHref"
          >
            <template #footer>
              <div
                v-if="userName"
                class="foot"
              >
                <strong>{{ userName }}</strong>
              </div>
            </template>
          </TSidebar>
        </template>

        <template #topbar>
          <TCrumbBar :crumbs="crumbs" />
          <div class="top-right">
            <TAppSwitcher
              :apps="apps"
              current-id="manage"
            />
            <TThemeToggle />
            <TButton
              variant="ghost"
              size="sm"
              @click="router.push('/auth/change-password')"
            >
              Change password
            </TButton>
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
  </template>
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
