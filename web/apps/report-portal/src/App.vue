<script setup lang="ts">
import { computed, ref, onMounted, watch } from 'vue';
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

// Human-readable crumb labels for each first-segment. When a detail
// route is added in phase 2 (e.g. /scans/:id) the existing entry maps
// to the list view and the detail segment lands as a leaf.
const labels: Record<string, string> = {
  machines: 'Machines',
  scans: 'Scans',
  nacsa: 'NACSA Arahan 9',
  priority: 'Priority',
  inventory: 'Inventory',
  certificates: 'Certificates',
  trend: 'Migration trend',
  diff: 'Scan diff',
  admin: 'Admin',
};

const crumbs = computed<Crumb[]>(() => {
  const segments = route.path.split('/').filter(Boolean);
  if (segments.length === 0) return [{ label: 'Overview' }];
  const first = segments[0]!;
  const parent = labels[first] ?? first;
  if (segments.length === 1) return [{ label: parent }];
  return [
    { label: parent, href: `#/${first}` },
    { label: segments.slice(1).join(' / ') },
  ];
});

// Derived user display — Pinia setup stores auto-unwrap refs, so
// auth.claims is the JwtClaims | null directly, not a computed.
const userName = computed(() => auth.claims?.name || auth.claims?.sub || '');
const userRole = computed(() => {
  const role = auth.claims?.role ?? '';
  if (role === 'super_admin') return 'Super admin';
  if (role === 'org_admin') return 'Admin';
  if (role === 'viewer') return 'Viewer';
  return role;
});
const orgName = computed(() => auth.claims?.orgName ?? '');

const loginError = ref<string>('');
const loginBusy = ref<boolean>(false);

async function onLogin(creds: { email: string; password: string }) {
  loginError.value = '';
  loginBusy.value = true;
  try {
    const resp = await api.get().login(creds);
    auth.setToken(resp.token);
    // Future phase: if resp.mustChangePassword, push to a change-password
    // view. Phase 1 has no such view; admins reset via the API directly.
  } catch (err) {
    loginError.value = err instanceof Error ? err.message : 'Sign-in failed';
  } finally {
    loginBusy.value = false;
  }
}

// First-run setup guard: if the server hasn't been set up yet, redirect to
// the Setup view. Silently ignored if the API is unreachable.
onMounted(async () => {
  try {
    const status = await api.get().setupStatus();
    if (status.needsSetup && router.currentRoute.value.name !== 'setup') {
      await router.replace({ name: 'setup' });
    }
  } catch {
    // API unreachable — proceed normally
  }
});

// Force password-change redirect whenever the JWT claim flips on.
watch(
  () => auth.claims?.mustChangePassword,
  (mcp) => {
    if (mcp && router.currentRoute.value.name !== 'change-password') {
      void router.push({ name: 'change-password' });
    }
  },
  { immediate: true },
);

async function signOut() {
  try {
    await api.get().logout();
  } catch {
    // Best-effort: clear local state even if server-side delete fails.
  }
  auth.clear();
  toast.info({ title: 'Signed out', description: 'Session ended.' });
  router.replace('/');
}
</script>

<template>
  <template v-if="route.meta?.public">
    <router-view />
  </template>
  <TAuthGate
    v-else
    type="jwt"
    title="Triton Report Server"
    subtitle="Sign in to review cryptographic compliance."
    :error="loginError"
    :busy="loginBusy"
    @login="onLogin"
  >
    <TAppShell :portal-accent="PORTAL_ACCENT">
      <template #sidebar>
        <TSidebar
          :nav="nav"
          portal-title="Triton"
          portal-subtitle="Report"
          :current-href="currentHref"
        >
          <template #footer>
            <div
              v-if="userName"
              class="foot"
            >
              <strong>{{ userName }}</strong>
              <span v-if="orgName">{{ orgName }}</span>
            </div>
          </template>
        </TSidebar>
      </template>

      <template #topbar>
        <TCrumbBar :crumbs="crumbs" />
        <div class="top-right">
          <TAppSwitcher
            :apps="apps"
            current-id="report"
          />
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
