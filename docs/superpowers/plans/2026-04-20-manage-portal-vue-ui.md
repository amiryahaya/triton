# Manage Portal Vue UI Implementation Plan (PR C)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Vue 3 admin portal for Manage Server covering every B2.2 backend endpoint, embedded into the `triton-manageserver` binary, and delete the legacy vanilla JS UI served by Report Server.

**Architecture:** New `web/apps/manage-portal/` Vue 3 + Pinia + Vue Router app under the existing `web/` pnpm monorepo. Hash-routed (mirrors report-portal). Uses `@triton/api-client` (gains a new `manageServer.ts` factory), `@triton/auth` (`TAuthGate` reused as-is), `@triton/ui` (TStatCard, TDataTable, TModal, TConfirmDialog, TPill, TToastHost all already exist). Vite outputs directly to `pkg/manageserver/ui/dist/` — `//go:embed all:ui/dist` in a new `pkg/manageserver/ui.go` picks it up; the server mounts the SPA at `/ui/` and redirects `/` → `/ui/` (matches report-portal's pattern).

**Tech Stack:** Vue 3.5 + Composition API, Pinia 2, Vue Router 4 (hash mode), Vite 5, Vitest + `@vue/test-utils` + jsdom, `vue-tsc`. pnpm workspace resolution. Go 1.25+ for the embed side.

---

## Deviations from spec

Three corrections to spec §4, §5, §7 after inspecting the existing portals:

1. **Hash routing, not history mode.** Spec §4 says "history mode" but both report-portal and license-portal use `createWebHashHistory` — deep links resolve on any basePath without server rewrites. No SPA-fallback logic needed on the backend. The plan uses hash routing.
2. **`base: '/ui/'`, not `/`.** Spec §8 says "mount SPA at `/*`" but report-portal and license-portal both use `base: '/ui/'` and the backend redirects `/` → `/ui/`. The plan follows that convention — less divergence, consistent UX across the three portals.
3. **Factory API client, not class.** Spec §7 sketched `class ManageServerClient { ... }` but the repo convention is `createReportApi(http)` returning an object (see `web/packages/api-client/src/reportServer.ts`). The plan uses `createManageApi(http)`.
4. **`TAuthGate` is NOT parameterised.** Spec §4 speculated it "hardcodes `/api/v1/auth/*` paths" but inspection shows it emits a `login` event to the parent who owns the API call. No refactor needed in `@triton/auth`.
5. **Most primitives already exist in `@triton/ui`.** TStatCard, TDataTable, TModal, TConfirmDialog, TPill (use as status badge via `PillVariant`), TToastHost all ship from `@triton/ui` today. Only `TCodeBlock` needs adding (for the one-shot temp password display + agent bundle filename).

---

## File structure

### New files

**Vue app** (`web/apps/manage-portal/`):
- `package.json` — workspace deps (`@triton/ui`, `@triton/auth`, `@triton/api-client`), scripts (`dev`, `build`, `test`), mirrors `web/apps/report-portal/package.json`.
- `vite.config.ts` — `base: '/ui/'`, `outDir: pkg/manageserver/ui/dist`, proxy `/api` → `:8082`, port 5175.
- `tsconfig.json` — extends `web/tsconfig.base.json`.
- `index.html` — single `#app` div.
- `src/main.ts` — `createApp(App).use(createPinia()).use(router).mount('#app')` plus tokens/fonts CSS imports.
- `src/App.vue` — TAuthGate + TAppShell + sidebar + crumbs + user menu + toast host.
- `src/router.ts` — hash router, all 12 routes listed below.
- `src/nav.ts` — `NavSection[]` for the grouped sidebar (Inventory / Operations / Admin) + `AppEntry[]` for app switcher + `PORTAL_ACCENT`.
- `src/stores/auth.ts` — thin Pinia wrapper over `@triton/auth::useJwt()`.
- `src/stores/apiClient.ts` — lazily-memoised singleton over `createManageApi(http)`.
- `src/stores/setup.ts` — `{ status, loading, refresh(), reset() }`.
- `src/stores/dashboard.ts` — aggregate stats, polling lifecycle.
- `src/stores/zones.ts` — CRUD + no polling.
- `src/stores/hosts.ts` — CRUD + zone filter + bulk import.
- `src/stores/agents.ts` — list + enrol + revoke.
- `src/stores/scanjobs.ts` — list + status filter + enqueue + cancel + polling.
- `src/stores/pushstatus.ts` — current status + polling.
- `src/stores/users.ts` — list + create.
- `src/stores/licence.ts` — read-only guard state.
- `src/stores/settings.ts` — read-only runtime config.
- `src/components/TCodeBlock.vue` — mono code block with copy-to-clipboard button.
- `src/views/SetupAdmin.vue`, `src/views/SetupLicense.vue` — two-step setup wizard.
- `src/views/Dashboard.vue` — stat-card grid.
- `src/views/Zones.vue`, `src/views/Hosts.vue`, `src/views/Agents.vue` — inventory.
- `src/views/ScanJobs.vue`, `src/views/PushStatus.vue` — operations.
- `src/views/Users.vue`, `src/views/Licence.vue`, `src/views/Settings.vue` — admin.
- `src/views/modals/ZoneForm.vue`, `HostForm.vue`, `HostBulkForm.vue`, `AgentEnrolForm.vue`, `AgentRevokeConfirm.vue`, `ScanJobEnqueueForm.vue`, `ScanJobDetailDrawer.vue`, `UserCreateForm.vue`.
- `tests/guards.spec.ts` — route-guard matrix test.
- `tests/views/*.spec.ts` — one spec per view.
- `tests/components/*.spec.ts` — spec for TCodeBlock.

**Shared package additions**:
- `web/packages/api-client/src/manageServer.ts` — factory + methods for every Manage endpoint.
- `web/packages/api-client/src/manageServer.types.ts` — TS aliases mirroring Go DTOs (snake_case fields).
- `web/packages/api-client/src/manageServer.test.ts` — request-shape assertions.

**Backend Go additions**:
- `pkg/manageserver/ui.go` — declares `//go:embed all:ui/dist` + `uiFS`.
- `pkg/manageserver/ui_test.go` — asserts the embedded filesystem contains `index.html` after `make web-build-manage`.

### Modified files

- `pkg/manageserver/server.go` — `buildRouter` adds `/ui/*` + `/` → `/ui/` redirect after the `/api/v1/*` routes; new `handleUIIndex` helper.
- `pkg/manageserver/ui/.gitkeep` — tracked placeholder so `//go:embed all:ui/dist` succeeds when the `dist/` contents aren't built yet (e.g. on fresh checkout before `make web-build-manage` runs).
- `Makefile` — adds `web-build-manage` target; adds it as a dependency of `build` and `container-build-manageserver`.
- `Containerfile.manageserver` — adds a web-builder stage before the Go builder.
- `.gitignore` — adds `pkg/manageserver/ui/dist/` (keep tracking `.gitkeep` via `!`).
- `web/apps/report-portal/src/nav.ts` — if the app-switcher needs an updated `manageUrl`, verify the env-var wiring still works.
- `pkg/server/server.go` — delete the `/ui/manage/*` route + the legacy redirects at lines 539–545.

### Deleted files

- `pkg/server/ui/dist/manage/` — entire directory.
- Any integration test referencing `/ui/manage/*` path (grep first).

---

## Batch A — Scaffolding

Get a skeleton Vue app compiling and rendering "Hello" on localhost before anything else.

### Task A1: Create the package skeleton

**Files:**
- Create: `web/apps/manage-portal/package.json`
- Create: `web/apps/manage-portal/vite.config.ts`
- Create: `web/apps/manage-portal/tsconfig.json`
- Create: `web/apps/manage-portal/index.html`
- Create: `web/apps/manage-portal/src/main.ts`
- Create: `web/apps/manage-portal/src/App.vue`

- [ ] **Step 1: Write `package.json`** (copy from `web/apps/report-portal/package.json`, rename):

```json
{
  "name": "manage-portal",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vue-tsc --noEmit && vite build",
    "preview": "vite preview",
    "test": "vitest run --passWithNoTests"
  },
  "dependencies": {
    "@triton/ui": "workspace:*",
    "@triton/auth": "workspace:*",
    "@triton/api-client": "workspace:*",
    "pinia": "^2.3.0",
    "vue": "^3.5.13",
    "vue-router": "^4.5.0"
  },
  "devDependencies": {
    "@vitejs/plugin-vue": "^5.2.1",
    "@vue/test-utils": "^2.4.6",
    "jsdom": "^25.0.1",
    "vite": "^5.4.11",
    "vitest": "^2.1.8",
    "vue-tsc": "^2.1.10"
  }
}
```

- [ ] **Step 2: Write `vite.config.ts`**:

```ts
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import path from 'node:path';

export default defineConfig({
  plugins: [vue()],
  base: '/ui/',
  build: {
    outDir: path.resolve(__dirname, '../../../pkg/manageserver/ui/dist'),
    emptyOutDir: true,
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['vue', 'vue-router', 'pinia'],
        },
      },
    },
  },
  server: {
    port: 5175,
    proxy: {
      '/api': 'http://localhost:8082',
    },
  },
});
```

- [ ] **Step 3: Write `tsconfig.json`**:

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "rootDir": "src",
    "composite": false,
    "types": ["vite/client"],
    "skipLibCheck": true,
    "exactOptionalPropertyTypes": false
  },
  "include": ["src/**/*.ts", "src/**/*.vue"]
}
```

- [ ] **Step 4: Write `index.html`**:

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Triton Manage</title>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>
```

- [ ] **Step 5: Write minimal `src/App.vue`**:

```vue
<template>
  <div>Manage Portal boot</div>
</template>
```

- [ ] **Step 6: Write minimal `src/main.ts`**:

```ts
import { createApp } from 'vue';
import App from './App.vue';

createApp(App).mount('#app');
```

- [ ] **Step 7: Create `pkg/manageserver/ui/.gitkeep`** — empty file so git tracks the directory that `//go:embed` will later read from.

- [ ] **Step 8: Add dist ignore to root `.gitignore`** (if not already present):

```
pkg/manageserver/ui/dist/
!pkg/manageserver/ui/.gitkeep
```

- [ ] **Step 9: Install deps + smoke-build**:

```bash
cd web && pnpm install
pnpm --filter manage-portal build
ls ../pkg/manageserver/ui/dist/index.html
```

Expected: `ls` succeeds (file exists).

- [ ] **Step 10: Commit**:

```bash
git add web/apps/manage-portal pkg/manageserver/ui/.gitkeep .gitignore
git commit -m "feat(manage-portal): package skeleton + vite config"
```

### Task A2: Wire Pinia + Vue Router + UI tokens

**Files:**
- Modify: `web/apps/manage-portal/src/main.ts`
- Modify: `web/apps/manage-portal/src/App.vue`
- Create: `web/apps/manage-portal/src/router.ts`
- Create: `web/apps/manage-portal/src/views/_Placeholder.vue`

- [ ] **Step 1: Replace `main.ts`**:

```ts
import { createApp } from 'vue';
import { createPinia } from 'pinia';
import '@triton/ui/tokens.css';
import '@triton/ui/fonts.css';
import App from './App.vue';
import { router } from './router';

createApp(App).use(createPinia()).use(router).mount('#app');
```

- [ ] **Step 2: Write `router.ts`** — hash mode with placeholders at every final route:

```ts
import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router';

const Placeholder = () => import('./views/_Placeholder.vue');

const routes: RouteRecordRaw[] = [
  { path: '/',                             redirect: '/dashboard' },
  { path: '/dashboard',                    name: 'dashboard',   component: Placeholder },
  { path: '/setup/admin',                  name: 'setupAdmin',  component: Placeholder },
  { path: '/setup/license',                name: 'setupLicense',component: Placeholder },
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
```

- [ ] **Step 3: Write `views/_Placeholder.vue`**:

```vue
<script setup lang="ts">
import { useRoute } from 'vue-router';
const route = useRoute();
</script>
<template>
  <div style="padding: 2rem">
    <h2>{{ String(route.name ?? 'unknown') }}</h2>
    <p>{{ route.fullPath }}</p>
  </div>
</template>
```

- [ ] **Step 4: Replace `App.vue` with a minimal router-view host**:

```vue
<template>
  <router-view />
</template>
```

- [ ] **Step 5: Dev-smoke**:

```bash
cd web && pnpm --filter manage-portal dev
```

Open `http://localhost:5175/ui/#/dashboard` in a browser — expect placeholder text. Ctrl-C to stop.

- [ ] **Step 6: Build + commit**:

```bash
cd web && pnpm --filter manage-portal build
git add web/apps/manage-portal/src
git commit -m "feat(manage-portal): pinia + router (hash) + placeholder views"
```

---

## Batch B — API client

Ship the full `@triton/api-client::manageServer` surface before any view code depends on it.

### Task B1: `manageServer.types.ts`

**Files:**
- Create: `web/packages/api-client/src/manageServer.types.ts`

- [ ] **Step 1: Write the types file** — DTOs mirror Go struct JSON (snake_case preserved):

```ts
// Manage Server DTOs — field names match the Go JSON shape verbatim
// (snake_case). We intentionally preserve casing to match reportServer
// and licenseServer, and to avoid a silent-rename layer between HTTP
// and the UI. Convert at display time, not at the wire.

export interface SetupStatus {
  admin_created: boolean;
  license_activated: boolean;
  setup_required: boolean;
}

export interface CreateAdminReq {
  email: string;
  name: string;
  password: string;
}

export interface CreateAdminResp {
  ok: boolean;
  user_id: string;
}

export interface ActivateLicenseReq {
  license_server_url: string;
  license_key: string;
}

export interface ActivateLicenseResp {
  ok: boolean;
  features: Record<string, boolean>;
  limits: Record<string, unknown>;
}

export interface LoginResp {
  token: string;
  expires_at: string;
  must_change_password: boolean;
}

export interface ManageUser {
  id: string;
  email: string;
  name: string;
  role: 'admin' | 'network_engineer';
  must_change_pw: boolean;
  created_at: string;
  updated_at: string;
}

export interface Zone {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface Host {
  id: string;
  hostname: string;
  ip?: string;
  zone_id?: string;
  os: string;
  last_seen_at?: string;
  created_at: string;
  updated_at: string;
}

export interface CreateHostReq {
  hostname: string;
  ip?: string;
  zone_id?: string;
  os?: string;
}

export interface UpdateHostReq {
  hostname: string;
  ip?: string;
  zone_id?: string;
  os?: string;
}

export type AgentStatus = 'pending' | 'active' | 'revoked';

export interface Agent {
  id: string;
  name: string;
  zone_id?: string;
  cert_serial: string;
  cert_expires_at: string;
  status: AgentStatus;
  last_seen_at?: string;
  created_at: string;
  updated_at: string;
}

export type ScanJobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScanJobProfile = 'quick' | 'standard' | 'comprehensive';

export interface ScanJob {
  id: string;
  tenant_id: string;
  zone_id?: string;
  host_id?: string;
  profile: ScanJobProfile;
  credentials_ref?: string;
  status: ScanJobStatus;
  cancel_requested: boolean;
  worker_id?: string;
  enqueued_at: string;
  started_at?: string;
  finished_at?: string;
  running_heartbeat_at?: string;
  progress_text: string;
  error_message: string;
}

export interface EnqueueReq {
  zones: string[];
  target_filter?: string;
  profile: ScanJobProfile;
  credentials_ref?: string;
}

export interface PushStatus {
  queue_depth: number;
  oldest_row_age_seconds: number;
  last_push_error: string;
  consecutive_failures: number;
  last_pushed_at?: string;
}

export interface CreateUserReq {
  email: string;
  name: string;
  role: 'admin' | 'network_engineer';
}

export interface CreateUserResp {
  id: string;
  email: string;
  role: string;
  temp_password: string;
}
```

- [ ] **Step 2: Commit** (types-only; will wire into exports in B2):

```bash
git add web/packages/api-client/src/manageServer.types.ts
git commit -m "feat(api-client): manageServer DTO types"
```

### Task B2: `manageServer.ts` factory

**Files:**
- Create: `web/packages/api-client/src/manageServer.ts`
- Modify: `web/packages/api-client/src/index.ts`

- [ ] **Step 1: Write the factory**:

```ts
import type { Http } from './http';
import type {
  SetupStatus, CreateAdminReq, CreateAdminResp,
  ActivateLicenseReq, ActivateLicenseResp,
  LoginResp, ManageUser,
  Zone, Host, CreateHostReq, UpdateHostReq,
  Agent, ScanJob, EnqueueReq, PushStatus,
  CreateUserReq, CreateUserResp,
} from './manageServer.types';

/**
 * createManageApi wraps an Http client with the Manage Server's v1 REST
 * surface. Paths begin with `/v1/` — caller's baseUrl is expected to be
 * `/api` so full URLs resolve to `/api/v1/...`.
 *
 * The `enrolAgent` method is special: it returns a raw Blob (tar.gz
 * bundle). The UI turns it into a download via URL.createObjectURL —
 * see the Agents view.
 */
export function createManageApi(http: Http) {
  return {
    // Setup + auth
    getSetupStatus:   ()                          => http.get<SetupStatus>('/v1/setup/status'),
    createAdmin:      (req: CreateAdminReq)       => http.post<CreateAdminResp>('/v1/setup/admin', req),
    activateLicense:  (req: ActivateLicenseReq)   => http.post<ActivateLicenseResp>('/v1/setup/license', req),
    login:            (email: string, password: string)
                                                  => http.post<LoginResp>('/v1/auth/login', { email, password }),
    logout:           ()                          => http.post<{ ok: boolean }>('/v1/auth/logout', {}),
    refresh:          ()                          => http.post<LoginResp>('/v1/auth/refresh', {}),
    me:               ()                          => http.get<ManageUser>('/v1/me'),

    // Zones
    listZones:        ()                          => http.get<Zone[]>('/v1/admin/zones/'),
    createZone:       (req: { name: string; description?: string })
                                                  => http.post<Zone>('/v1/admin/zones/', req),
    updateZone:       (id: string, req: { name: string; description?: string })
                                                  => http.put<Zone>(`/v1/admin/zones/${id}`, req),
    deleteZone:       (id: string)                => http.del<void>(`/v1/admin/zones/${id}`),

    // Hosts
    listHosts:        (zoneID?: string) => {
      const qs = zoneID ? `?zone_id=${encodeURIComponent(zoneID)}` : '';
      return http.get<Host[]>(`/v1/admin/hosts/${qs}`);
    },
    createHost:       (req: CreateHostReq)        => http.post<Host>('/v1/admin/hosts/', req),
    bulkCreateHosts:  (req: { hosts: CreateHostReq[] })
                                                  => http.post<Host[]>('/v1/admin/hosts/bulk', req),
    updateHost:       (id: string, req: UpdateHostReq)
                                                  => http.put<Host>(`/v1/admin/hosts/${id}`, req),
    deleteHost:       (id: string)                => http.del<void>(`/v1/admin/hosts/${id}`),

    // Agents
    listAgents:       ()                          => http.get<Agent[]>('/v1/admin/agents/'),
    enrolAgent:       async (req: { name: string; zone_id?: string }): Promise<Blob> => {
      // enrolAgent returns a tar.gz stream; the shared Http client only
      // reads JSON/text. Call fetch() directly here so we get the Blob.
      const res = await fetch('/api/v1/admin/enrol/agent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          // Auth header is re-injected by a per-call closure in apiClient
          // store — see stores/apiClient.ts where this wrapper is built.
          ...(http as unknown as { _authHeader?: () => Record<string, string> })._authHeader?.() ?? {},
        },
        body: JSON.stringify(req),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        throw new Error(`${res.status} ${res.statusText}: ${text}`);
      }
      return res.blob();
    },
    revokeAgent:      (id: string)                => http.del<void>(`/v1/admin/agents/${id}`),

    // Scan jobs
    listScanJobs:     (opts?: { status?: string; limit?: number }) => {
      const params = new URLSearchParams();
      if (opts?.status) params.set('status', opts.status);
      if (opts?.limit) params.set('limit', String(opts.limit));
      const qs = params.toString() ? `?${params}` : '';
      return http.get<ScanJob[]>(`/v1/admin/scan-jobs/${qs}`);
    },
    getScanJob:       (id: string)                => http.get<ScanJob>(`/v1/admin/scan-jobs/${id}`),
    enqueueScanJobs:  (req: EnqueueReq)           => http.post<ScanJob[]>('/v1/admin/scan-jobs/', req),
    cancelScanJob:    (id: string)                => http.post<void>(`/v1/admin/scan-jobs/${id}/cancel`, {}),

    // Push status
    getPushStatus:    ()                          => http.get<PushStatus>('/v1/admin/push-status/'),

    // Users
    listUsers:        ()                          => http.get<ManageUser[]>('/v1/admin/users/'),
    createUser:       (req: CreateUserReq)        => http.post<CreateUserResp>('/v1/admin/users', req),
  };
}

export type ManageApi = ReturnType<typeof createManageApi>;
```

**Note on `enrolAgent`:** the Blob return type means this method bypasses the shared `Http.get/post` helpers (they force JSON-or-text decoding). It calls `fetch()` directly. The auth header is sourced via a side-channel on the `Http` wrapper — stores/apiClient.ts will patch a `_authHeader` property on the `Http` object before passing it to `createManageApi`. This is ugly but isolated; a cleaner fix is a follow-up refactor to `@triton/api-client` to support arbitrary response types natively.

- [ ] **Step 2: Update `index.ts` exports**:

```ts
// append to existing exports in web/packages/api-client/src/index.ts
export { createManageApi } from './manageServer';
export type { ManageApi } from './manageServer';
export type {
  SetupStatus, CreateAdminReq, CreateAdminResp,
  ActivateLicenseReq, ActivateLicenseResp,
  LoginResp as ManageLoginResp, ManageUser,
  Zone, Host, CreateHostReq, UpdateHostReq,
  Agent, AgentStatus,
  ScanJob, ScanJobStatus, ScanJobProfile, EnqueueReq,
  PushStatus, CreateUserReq, CreateUserResp,
} from './manageServer.types';
```

(Prefix `LoginResp` as `ManageLoginResp` on export to avoid collision with report-server's `LoginResponse` camelCase type.)

- [ ] **Step 3: Build the package**:

```bash
cd web && pnpm --filter @triton/api-client build 2>&1 || echo "(no build target — ts-only)"
```

If `@triton/api-client` has no build target, skip this step; the package is pure TS sourced by consumers.

- [ ] **Step 4: Type-check succeeds** (part of manage-portal's `vue-tsc --noEmit`):

```bash
cd web && pnpm --filter manage-portal build
```

Expected: clean build. If type errors, fix import sites.

- [ ] **Step 5: Commit**:

```bash
git add web/packages/api-client/src/manageServer.ts web/packages/api-client/src/index.ts
git commit -m "feat(api-client): createManageApi with full Manage Server surface"
```

### Task B3: api-client tests

**Files:**
- Create: `web/packages/api-client/src/manageServer.test.ts`

- [ ] **Step 1: Write failing test** — assert request shape for representative endpoints:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHttp } from './http';
import { createManageApi } from './manageServer';

type Call = { method: string; path: string; body?: unknown };

function mockHttpCapture(): { http: ReturnType<typeof createHttp>; calls: Call[] } {
  const calls: Call[] = [];
  // @ts-expect-error we're building a minimal Http fake
  const http: ReturnType<typeof createHttp> = {
    get:  <T>(path: string)           => { calls.push({ method: 'GET', path });        return Promise.resolve({} as T); },
    post: <T>(path: string, body?: unknown) => { calls.push({ method: 'POST', path, body });  return Promise.resolve({} as T); },
    put:  <T>(path: string, body?: unknown) => { calls.push({ method: 'PUT', path, body });   return Promise.resolve({} as T); },
    del:  <T>(path: string)           => { calls.push({ method: 'DELETE', path });    return Promise.resolve({} as T); },
  };
  return { http, calls };
}

describe('createManageApi', () => {
  let fake: ReturnType<typeof mockHttpCapture>;
  let api: ReturnType<typeof createManageApi>;
  beforeEach(() => {
    fake = mockHttpCapture();
    api = createManageApi(fake.http);
  });

  it('getSetupStatus → GET /v1/setup/status', async () => {
    await api.getSetupStatus();
    expect(fake.calls).toEqual([{ method: 'GET', path: '/v1/setup/status' }]);
  });

  it('listHosts(zoneID) encodes query string', async () => {
    await api.listHosts('abc-123');
    expect(fake.calls[0]?.path).toBe('/v1/admin/hosts/?zone_id=abc-123');
  });

  it('listScanJobs with filters builds qs', async () => {
    await api.listScanJobs({ status: 'running', limit: 50 });
    expect(fake.calls[0]?.path).toBe('/v1/admin/scan-jobs/?status=running&limit=50');
  });

  it('createZone POSTs body', async () => {
    await api.createZone({ name: 'dmz', description: 'perimeter' });
    expect(fake.calls[0]).toEqual({
      method: 'POST',
      path: '/v1/admin/zones/',
      body: { name: 'dmz', description: 'perimeter' },
    });
  });

  it('cancelScanJob POSTs empty body to /cancel', async () => {
    await api.cancelScanJob('job-1');
    expect(fake.calls[0]).toEqual({ method: 'POST', path: '/v1/admin/scan-jobs/job-1/cancel', body: {} });
  });
});

describe('enrolAgent (direct fetch)', () => {
  beforeEach(() => { vi.restoreAllMocks(); });

  it('POSTs JSON and returns the Blob', async () => {
    const blob = new Blob(['tar-gz-bytes'], { type: 'application/x-gzip' });
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      blob: () => Promise.resolve(blob),
    } as unknown as Response);

    const { http } = mockHttpCapture();
    const api = createManageApi(http);
    const out = await api.enrolAgent({ name: 'agent-01', zone_id: 'z1' });
    expect(out).toBe(blob);
    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(url).toBe('/api/v1/admin/enrol/agent');
    expect((init as RequestInit).method).toBe('POST');
    expect((init as RequestInit).body).toBe(JSON.stringify({ name: 'agent-01', zone_id: 'z1' }));
  });

  it('throws on non-ok response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false, status: 403, statusText: 'Forbidden',
      text: () => Promise.resolve('license cap'),
    } as unknown as Response);
    const { http } = mockHttpCapture();
    const api = createManageApi(http);
    await expect(api.enrolAgent({ name: 'x' })).rejects.toThrow(/403/);
  });
});
```

- [ ] **Step 2: Run the tests**:

```bash
cd web && pnpm --filter @triton/api-client test
```

Expected: PASS (5 cases).

- [ ] **Step 3: Commit**:

```bash
git add web/packages/api-client/src/manageServer.test.ts
git commit -m "test(api-client): manageServer request-shape + enrol Blob coverage"
```

---

## Batch C — Auth + setup flow

App shell + login + two-step setup wizard + global route guard.

### Task C1: Auth + apiClient stores

**Files:**
- Create: `web/apps/manage-portal/src/stores/auth.ts`
- Create: `web/apps/manage-portal/src/stores/apiClient.ts`

- [ ] **Step 1: Write `auth.ts`** — thin Pinia wrapper over `@triton/auth::useJwt`:

```ts
import { defineStore } from 'pinia';
import { useJwt } from '@triton/auth';

export const useAuthStore = defineStore('auth', () => useJwt());
```

- [ ] **Step 2: Write `apiClient.ts`** — singleton over `createManageApi`:

```ts
import { defineStore } from 'pinia';
import { createHttp, createManageApi, type ManageApi, type Http } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useAuthStore } from './auth';

let cached: ManageApi | null = null;

export const useApiClient = defineStore('apiClient', () => {
  function get(): ManageApi {
    if (cached) return cached;
    const auth = useAuthStore();
    const toast = useToast();
    const authHeader = (): Record<string, string> =>
      auth.token ? { Authorization: `Bearer ${auth.token}` } : {};
    const http = createHttp({
      baseUrl: '/api',
      authHeader,
      onUnauthorized: () => {
        auth.clear();
        toast.error({ title: 'Session expired', description: 'Please sign in again.' });
      },
    });
    // enrolAgent uses direct fetch() — stash authHeader on the http obj
    // so manageServer.ts can splice it into the request headers.
    (http as Http & { _authHeader?: () => Record<string, string> })._authHeader = authHeader;
    cached = createManageApi(http);
    return cached;
  }
  return { get };
});
```

- [ ] **Step 3: Commit** (no test yet — exercised via views in C3+):

```bash
git add web/apps/manage-portal/src/stores/auth.ts web/apps/manage-portal/src/stores/apiClient.ts
git commit -m "feat(manage-portal): auth + apiClient pinia stores"
```

### Task C2: Setup wizard views

**Files:**
- Create: `web/apps/manage-portal/src/stores/setup.ts`
- Create: `web/apps/manage-portal/src/views/SetupAdmin.vue`
- Create: `web/apps/manage-portal/src/views/SetupLicense.vue`

- [ ] **Step 1: Write `setup.ts` store**:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { SetupStatus } from '@triton/api-client';
import { useApiClient } from './apiClient';

export const useSetupStore = defineStore('setup', () => {
  const status = ref<SetupStatus | null>(null);
  const loading = ref(false);
  const error = ref<string>('');

  async function refresh() {
    const api = useApiClient().get();
    loading.value = true; error.value = '';
    try {
      status.value = await api.getSetupStatus();
    } catch (err) {
      error.value = err instanceof Error ? err.message : 'failed to load setup status';
    } finally { loading.value = false; }
  }

  return { status, loading, error, refresh };
});
```

- [ ] **Step 2: Write `SetupAdmin.vue`** — form with email/name/password, POSTs `/setup/admin`:

```vue
<script setup lang="ts">
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';
import { TInput, TFormField, TButton, useToast } from '@triton/ui';
import { useApiClient } from '../stores/apiClient';
import { useSetupStore } from '../stores/setup';

const router = useRouter();
const api = useApiClient();
const setup = useSetupStore();
const toast = useToast();

const email = ref(''); const name = ref(''); const password = ref('');
const busy = ref(false); const error = ref('');

const valid = computed(() => email.value.includes('@') && password.value.length >= 12);

async function submit() {
  if (!valid.value) return;
  busy.value = true; error.value = '';
  try {
    await api.get().createAdmin({ email: email.value, name: name.value, password: password.value });
    toast.success({ title: 'Admin created', description: 'Continue to licence activation.' });
    await setup.refresh();
    router.push('/setup/license');
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'failed';
  } finally { busy.value = false; }
}
</script>
<template>
  <div class="wiz">
    <h1>Create first admin</h1>
    <p>Set up the initial administrator account for this Manage Server instance.</p>
    <TFormField label="Email"><TInput v-model="email" type="email" /></TFormField>
    <TFormField label="Name (optional)"><TInput v-model="name" /></TFormField>
    <TFormField label="Password (≥ 12 chars, must contain a digit)">
      <TInput v-model="password" type="password" />
    </TFormField>
    <p v-if="error" class="err">{{ error }}</p>
    <TButton variant="primary" :disabled="!valid || busy" @click="submit">
      {{ busy ? 'Creating…' : 'Create admin' }}
    </TButton>
  </div>
</template>
<style scoped>
.wiz { max-width: 480px; margin: 5rem auto; display: flex; flex-direction: column; gap: 1rem; }
.err { color: var(--danger); }
</style>
```

- [ ] **Step 3: Write `SetupLicense.vue`** — similar shape, POSTs `/setup/license`:

```vue
<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { TInput, TFormField, TButton, useToast } from '@triton/ui';
import { useApiClient } from '../stores/apiClient';
import { useSetupStore } from '../stores/setup';

const router = useRouter();
const api = useApiClient();
const setup = useSetupStore();
const toast = useToast();

const licenseServerURL = ref('https://'); const licenseKey = ref('');
const busy = ref(false); const error = ref('');

async function submit() {
  busy.value = true; error.value = '';
  try {
    await api.get().activateLicense({
      license_server_url: licenseServerURL.value,
      license_key: licenseKey.value,
    });
    toast.success({ title: 'Licence activated', description: 'Manage Server is ready.' });
    await setup.refresh();
    router.push('/dashboard');
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'activation failed';
  } finally { busy.value = false; }
}
</script>
<template>
  <div class="wiz">
    <h1>Activate licence</h1>
    <p>Point at your Triton Licence Server and paste the licence key.</p>
    <TFormField label="Licence Server URL"><TInput v-model="licenseServerURL" /></TFormField>
    <TFormField label="Licence key"><TInput v-model="licenseKey" /></TFormField>
    <p v-if="error" class="err">{{ error }}</p>
    <TButton variant="primary" :disabled="busy" @click="submit">
      {{ busy ? 'Activating…' : 'Activate' }}
    </TButton>
  </div>
</template>
<style scoped>
.wiz { max-width: 480px; margin: 5rem auto; display: flex; flex-direction: column; gap: 1rem; }
.err { color: var(--danger); }
</style>
```

- [ ] **Step 4: Update `router.ts`** — replace placeholders for the setup routes:

```ts
// swap the two entries in routes[]:
{ path: '/setup/admin',   name: 'setupAdmin',   component: () => import('./views/SetupAdmin.vue') },
{ path: '/setup/license', name: 'setupLicense', component: () => import('./views/SetupLicense.vue') },
```

- [ ] **Step 5: Build succeeds**:

```bash
cd web && pnpm --filter manage-portal build
```

- [ ] **Step 6: Commit**:

```bash
git add web/apps/manage-portal/src
git commit -m "feat(manage-portal): setup wizard views + store"
```

### Task C3: Global route guard

**Files:**
- Modify: `web/apps/manage-portal/src/router.ts`

- [ ] **Step 1: Add the guard** to `router.ts` — after the router definition:

```ts
import { useAuthStore } from './stores/auth';
import { useSetupStore } from './stores/setup';

router.beforeEach(async (to) => {
  const auth = useAuthStore();
  const setup = useSetupStore();

  // 1. Ensure we have setup status at least once per session load.
  //    Cache it for 30s via the store's own loading flag to avoid
  //    hammering /setup/status on every nav.
  if (!setup.status && !setup.loading) {
    await setup.refresh();
  }

  // 2. If setup is required, force everything to /setup/admin or
  //    /setup/license depending on progress.
  if (setup.status?.setup_required) {
    if (to.path.startsWith('/setup/')) return true; // already on a setup route
    if (setup.status.admin_created) return { path: '/setup/license' };
    return { path: '/setup/admin' };
  }

  // 3. Setup complete — anywhere under /setup is stale; redirect to dashboard.
  if (to.path.startsWith('/setup/')) {
    return { path: '/dashboard' };
  }

  // 4. Require JWT for everything else. TAuthGate handles the login UI
  //    so we just let the route mount; the gate in App.vue renders the
  //    login prompt when auth.token is empty or expired.
  return true;
});
```

- [ ] **Step 2: Write `tests/guards.spec.ts`**:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createPinia, setActivePinia } from 'pinia';
import { createRouter, createMemoryHistory } from 'vue-router';

// Mock api-client so setup.refresh doesn't fire a real fetch.
vi.mock('@triton/api-client', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@triton/api-client');
  return {
    ...actual,
    createManageApi: () => ({
      getSetupStatus: vi.fn(),
    }),
  };
});

import { useSetupStore } from '../src/stores/setup';

describe('route guard', () => {
  beforeEach(() => setActivePinia(createPinia()));

  function buildRouter() {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/dashboard',      component: { template: '<div>d</div>' } },
        { path: '/setup/admin',    component: { template: '<div>a</div>' } },
        { path: '/setup/license',  component: { template: '<div>l</div>' } },
        { path: '/inventory/zones',component: { template: '<div>z</div>' } },
      ],
    });
    return router;
  }

  it('redirects to /setup/admin when setup_required + no admin', async () => {
    const router = buildRouter();
    const setup = useSetupStore();
    setup.status = { admin_created: false, license_activated: false, setup_required: true } as never;
    router.beforeEach((to) => {
      if (setup.status?.setup_required) {
        if (to.path.startsWith('/setup/')) return true;
        return setup.status.admin_created ? '/setup/license' : '/setup/admin';
      }
      return true;
    });
    await router.push('/dashboard');
    expect(router.currentRoute.value.fullPath).toBe('/setup/admin');
  });

  it('redirects to /setup/license when admin created but licence not activated', async () => {
    const router = buildRouter();
    const setup = useSetupStore();
    setup.status = { admin_created: true, license_activated: false, setup_required: true } as never;
    router.beforeEach((to) => {
      if (setup.status?.setup_required) {
        if (to.path.startsWith('/setup/')) return true;
        return setup.status.admin_created ? '/setup/license' : '/setup/admin';
      }
      return true;
    });
    await router.push('/dashboard');
    expect(router.currentRoute.value.fullPath).toBe('/setup/license');
  });

  it('redirects away from /setup/* after setup complete', async () => {
    const router = buildRouter();
    const setup = useSetupStore();
    setup.status = { admin_created: true, license_activated: true, setup_required: false } as never;
    router.beforeEach((to) => {
      if (setup.status?.setup_required) return true;
      if (to.path.startsWith('/setup/')) return '/dashboard';
      return true;
    });
    await router.push('/setup/admin');
    expect(router.currentRoute.value.fullPath).toBe('/dashboard');
  });
});
```

- [ ] **Step 3: Run tests**:

```bash
cd web && pnpm --filter manage-portal test
```

Expected: PASS.

- [ ] **Step 4: Commit**:

```bash
git add web/apps/manage-portal/src/router.ts web/apps/manage-portal/tests/guards.spec.ts
git commit -m "feat(manage-portal): global route guard + tests"
```

### Task C4: App shell + login wiring

**Files:**
- Modify: `web/apps/manage-portal/src/App.vue`
- Create: `web/apps/manage-portal/src/nav.ts`

- [ ] **Step 1: Write `nav.ts`** — grouped sidebar + app-switcher entries:

```ts
import type { NavSection, AppEntry } from '@triton/ui';

export const nav: NavSection[] = [
  {
    label: 'Inventory',
    items: [
      { href: '#/inventory/zones',  label: 'Zones' },
      { href: '#/inventory/hosts',  label: 'Hosts' },
      { href: '#/inventory/agents', label: 'Agents' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { href: '#/dashboard',              label: 'Dashboard' },
      { href: '#/operations/scan-jobs',   label: 'Scan Jobs' },
      { href: '#/operations/push-status', label: 'Push Status' },
    ],
  },
  {
    label: 'Admin',
    items: [
      { href: '#/admin/users',    label: 'Users' },
      { href: '#/admin/licence',  label: 'Licence' },
      { href: '#/admin/settings', label: 'Settings' },
    ],
  },
];

const licenseUrl = import.meta.env.VITE_LICENSE_URL as string | undefined;
const reportUrl  = import.meta.env.VITE_REPORT_URL  as string | undefined;

export const apps: AppEntry[] = [
  { id: 'license', name: 'Licence', subtitle: 'Vendor ops', url: licenseUrl ?? null, accent: '#a78bfa' },
  { id: 'report',  name: 'Report',  subtitle: 'Security',   url: reportUrl  ?? null, accent: '#22d3ee' },
  { id: 'manage',  name: 'Manage',  subtitle: 'Network',    url: null,               accent: '#a3e635' },
];

export const PORTAL_ACCENT = '#a3e635'; // lime family — matches app-switcher tile
```

- [ ] **Step 2: Replace `App.vue`** — copy report-portal's `App.vue` wholesale and adapt:

```vue
<script setup lang="ts">
import { computed, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  TAppShell, TSidebar, TThemeToggle, TAppSwitcher, TCrumbBar,
  TUserMenu, TToastHost, useTheme, useToast,
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

const userName = computed(() => auth.claims?.name || auth.claims?.sub || '');
const userRole = computed(() => auth.claims?.role === 'admin' ? 'Admin' : 'Engineer');

const loginError = ref<string>('');
const loginBusy = ref<boolean>(false);

async function onLogin(creds: { email: string; password: string }) {
  loginError.value = ''; loginBusy.value = true;
  try {
    const resp = await api.get().login(creds.email, creds.password);
    auth.setToken(resp.token);
  } catch (err) {
    loginError.value = err instanceof Error ? err.message : 'Sign-in failed';
  } finally {
    loginBusy.value = false;
  }
}

async function signOut() {
  try { await api.get().logout(); } catch { /* best-effort */ }
  auth.clear();
  toast.info({ title: 'Signed out', description: 'Session ended.' });
  router.replace('/dashboard');
}
</script>

<template>
  <!-- Setup routes render below the router-view but BELOW the auth gate — -->
  <!-- they don't need a JWT to reach. TAuthGate only activates when the   -->
  <!-- user navigates to a non-setup route. -->
  <template v-if="route.path.startsWith('/setup/')">
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
              <div v-if="userName" class="foot">
                <strong>{{ userName }}</strong>
              </div>
            </template>
          </TSidebar>
        </template>
        <template #topbar>
          <TCrumbBar :crumbs="crumbs" />
          <div class="top-right">
            <TAppSwitcher :apps="apps" current-id="manage" />
            <TThemeToggle />
            <TUserMenu :name="userName" :role="userRole" @sign-out="signOut" />
          </div>
        </template>
        <router-view />
      </TAppShell>
    </TAuthGate>
  </template>
  <TToastHost />
</template>

<style scoped>
.foot { display: flex; flex-direction: column; font-size: 0.7rem; color: var(--text-muted); }
.foot strong { color: var(--text-primary); font-family: var(--font-display); font-weight: 500; font-size: 0.78rem; }
.top-right { margin-left: auto; display: flex; align-items: center; gap: var(--space-2); }
</style>
```

- [ ] **Step 3: Build succeeds**:

```bash
cd web && pnpm --filter manage-portal build
```

- [ ] **Step 4: Commit**:

```bash
git add web/apps/manage-portal/src/App.vue web/apps/manage-portal/src/nav.ts
git commit -m "feat(manage-portal): App shell + login + sidebar + crumbs"
```

---

## Batch D — TCodeBlock + misc components

Only one new shared primitive is needed; everything else reuses `@triton/ui`.

### Task D1: `TCodeBlock` component

**Files:**
- Create: `web/apps/manage-portal/src/components/TCodeBlock.vue`
- Create: `web/apps/manage-portal/tests/components/TCodeBlock.spec.ts`

- [ ] **Step 1: Write the failing test**:

```ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import TCodeBlock from '../../src/components/TCodeBlock.vue';

describe('TCodeBlock', () => {
  it('renders the code', () => {
    const w = mount(TCodeBlock, { props: { code: 'secret-pw-123' } });
    expect(w.text()).toContain('secret-pw-123');
  });

  it('copies to clipboard on button click', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const w = mount(TCodeBlock, { props: { code: 'abc' } });
    await w.find('button').trigger('click');
    expect(writeText).toHaveBeenCalledWith('abc');
  });
});
```

- [ ] **Step 2: Write minimal component**:

```vue
<script setup lang="ts">
import { ref } from 'vue';
const props = defineProps<{ code: string; label?: string }>();
const copied = ref(false);
async function copy() {
  await navigator.clipboard.writeText(props.code);
  copied.value = true;
  setTimeout(() => { copied.value = false; }, 1500);
}
</script>
<template>
  <div class="code-block">
    <code>{{ props.code }}</code>
    <button type="button" class="copy" @click="copy">
      {{ copied ? 'Copied' : 'Copy' }}
    </button>
  </div>
</template>
<style scoped>
.code-block {
  display: flex; align-items: center; gap: var(--space-2);
  padding: var(--space-3); background: var(--bg-code);
  border-radius: var(--radius-md); font-family: var(--font-mono);
}
.copy { margin-left: auto; padding: 2px 8px; font-size: 0.75rem; border: 1px solid var(--border); background: transparent; cursor: pointer; }
</style>
```

- [ ] **Step 3: Run, verify pass**:

```bash
cd web && pnpm --filter manage-portal test
```

- [ ] **Step 4: Commit**:

```bash
git add web/apps/manage-portal/src/components/TCodeBlock.vue web/apps/manage-portal/tests/components/TCodeBlock.spec.ts
git commit -m "feat(manage-portal): TCodeBlock with copy-to-clipboard"
```

---

## Batch E — Domain stores

One store per domain. All follow the same shape; showing one in detail + a template for the rest. Stores own polling timers.

### Task E1: `toasts` — no-op (already in @triton/ui)

Skipped — `@triton/ui::useToast` provides the toast host. Documented here so reviewers don't expect a manage-portal-local toasts store.

### Task E2: `zones` store

**Files:**
- Create: `web/apps/manage-portal/src/stores/zones.ts`

- [ ] **Step 1: Write the store**:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { Zone } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useZonesStore = defineStore('zones', () => {
  const items = ref<Zone[]>([]);
  const loading = ref(false);
  const selected = ref<Zone | null>(null);

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listZones(); }
    catch (e) { useToast().error({ title: 'Failed to load zones', description: String(e) }); }
    finally { loading.value = false; }
  }
  async function create(req: { name: string; description?: string }) {
    const api = useApiClient().get();
    const z = await api.createZone(req);
    items.value.push(z);
    return z;
  }
  async function update(id: string, req: { name: string; description?: string }) {
    const api = useApiClient().get();
    const z = await api.updateZone(id, req);
    const i = items.value.findIndex(x => x.id === id);
    if (i >= 0) items.value[i] = z;
    return z;
  }
  async function remove(id: string) {
    const api = useApiClient().get();
    await api.deleteZone(id);
    items.value = items.value.filter(x => x.id !== id);
  }

  return { items, loading, selected, fetch, create, update, remove };
});
```

- [ ] **Step 2: Commit**:

```bash
git add web/apps/manage-portal/src/stores/zones.ts
git commit -m "feat(manage-portal): zones store"
```

### Task E3: `hosts` store

**Files:**
- Create: `web/apps/manage-portal/src/stores/hosts.ts`

- [ ] **Step 1: Write the store** — same shape as zones + `filter.zoneID` + `bulkCreate`:

```ts
import { defineStore } from 'pinia';
import { ref, watch } from 'vue';
import type { Host, CreateHostReq } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

const FILTER_KEY = 'manage-portal.hosts.filter';

export const useHostsStore = defineStore('hosts', () => {
  const items = ref<Host[]>([]);
  const loading = ref(false);
  const filter = ref<{ zoneID?: string }>(loadFilter());

  function loadFilter(): { zoneID?: string } {
    try { return JSON.parse(localStorage.getItem(FILTER_KEY) ?? '{}'); }
    catch { return {}; }
  }
  watch(filter, (v) => localStorage.setItem(FILTER_KEY, JSON.stringify(v)), { deep: true });

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listHosts(filter.value.zoneID); }
    catch (e) { useToast().error({ title: 'Failed to load hosts', description: String(e) }); }
    finally { loading.value = false; }
  }
  async function create(req: CreateHostReq) {
    const h = await useApiClient().get().createHost(req);
    items.value.push(h); return h;
  }
  async function bulkCreate(hosts: CreateHostReq[]) {
    const out = await useApiClient().get().bulkCreateHosts({ hosts });
    items.value.push(...out); return out;
  }
  async function update(id: string, req: CreateHostReq) {
    const h = await useApiClient().get().updateHost(id, req);
    const i = items.value.findIndex(x => x.id === id);
    if (i >= 0) items.value[i] = h;
    return h;
  }
  async function remove(id: string) {
    await useApiClient().get().deleteHost(id);
    items.value = items.value.filter(x => x.id !== id);
  }

  return { items, loading, filter, fetch, create, bulkCreate, update, remove };
});
```

- [ ] **Step 2: Commit**:

```bash
git add web/apps/manage-portal/src/stores/hosts.ts
git commit -m "feat(manage-portal): hosts store with zone filter + bulk create"
```

### Task E4: `agents` store

**Files:**
- Create: `web/apps/manage-portal/src/stores/agents.ts`

- [ ] **Step 1: Write the store** — list + enrol (returns Blob + we trigger download here so the UI just calls `enrol(name, zone)`) + revoke:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { Agent } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const useAgentsStore = defineStore('agents', () => {
  const items = ref<Agent[]>([]);
  const loading = ref(false);

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listAgents(); }
    catch (e) { useToast().error({ title: 'Failed to load agents', description: String(e) }); }
    finally { loading.value = false; }
  }

  /**
   * enrol calls /admin/enrol/agent, receives the tar.gz Blob, and
   * triggers a browser download. The private key inside the bundle is
   * never stored server-side, so we only get ONE shot — fire the
   * download synchronously in the same tick the Blob is received.
   *
   * After the download triggers, we refresh the list so the new row
   * (status=pending) appears. Returns the filename used so the caller
   * can surface it in the toast.
   */
  async function enrol(req: { name: string; zone_id?: string }): Promise<string> {
    const api = useApiClient().get();
    const blob = await api.enrolAgent(req);
    const filename = `agent-${req.name.replace(/\W+/g, '_')}-${Date.now()}.tar.gz`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
    await fetch();
    return filename;
  }

  async function revoke(id: string) {
    await useApiClient().get().revokeAgent(id);
    await fetch();
  }

  return { items, loading, fetch, enrol, revoke };
});
```

- [ ] **Step 2: Commit**:

```bash
git add web/apps/manage-portal/src/stores/agents.ts
git commit -m "feat(manage-portal): agents store with one-shot enrol download"
```

### Task E5: `scanjobs` store (with polling)

**Files:**
- Create: `web/apps/manage-portal/src/stores/scanjobs.ts`

- [ ] **Step 1: Write the store**:

```ts
import { defineStore } from 'pinia';
import { ref, watch } from 'vue';
import type { ScanJob, ScanJobStatus, EnqueueReq } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

const FILTER_KEY = 'manage-portal.scanjobs.filter';

export const useScanJobsStore = defineStore('scanjobs', () => {
  const items = ref<ScanJob[]>([]);
  const selected = ref<ScanJob | null>(null);
  const loading = ref(false);
  const filter = ref<{ status?: ScanJobStatus }>(loadFilter());
  let pollHandle: number | null = null;

  function loadFilter(): { status?: ScanJobStatus } {
    try { return JSON.parse(localStorage.getItem(FILTER_KEY) ?? '{}'); }
    catch { return {}; }
  }
  watch(filter, (v) => localStorage.setItem(FILTER_KEY, JSON.stringify(v)), { deep: true });

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { items.value = await api.listScanJobs(filter.value); }
    catch (e) { useToast().error({ title: 'Failed to load scan jobs', description: String(e) }); }
    finally { loading.value = false; }
  }

  async function getDetail(id: string) {
    selected.value = await useApiClient().get().getScanJob(id);
  }

  async function enqueue(req: EnqueueReq) {
    const jobs = await useApiClient().get().enqueueScanJobs(req);
    await fetch();
    return jobs;
  }

  async function requestCancel(id: string) {
    await useApiClient().get().cancelScanJob(id);
    await fetch();
  }

  function startPolling() {
    if (pollHandle) return;
    fetch();
    pollHandle = window.setInterval(() => {
      if (document.hidden) return;
      fetch();
    }, 5000);
  }
  function stopPolling() {
    if (pollHandle) { clearInterval(pollHandle); pollHandle = null; }
  }

  return { items, selected, loading, filter, fetch, getDetail, enqueue, requestCancel, startPolling, stopPolling };
});
```

- [ ] **Step 2: Commit**:

```bash
git add web/apps/manage-portal/src/stores/scanjobs.ts
git commit -m "feat(manage-portal): scanjobs store with 5s polling"
```

### Task E6: `pushstatus` store

**Files:**
- Create: `web/apps/manage-portal/src/stores/pushstatus.ts`

- [ ] **Step 1: Write the store** — mirrors scanjobs polling shape:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { PushStatus } from '@triton/api-client';
import { useToast } from '@triton/ui';
import { useApiClient } from './apiClient';

export const usePushStatusStore = defineStore('pushstatus', () => {
  const status = ref<PushStatus | null>(null);
  const loading = ref(false);
  let pollHandle: number | null = null;

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try { status.value = await api.getPushStatus(); }
    catch (e) { useToast().error({ title: 'Failed to load push status', description: String(e) }); }
    finally { loading.value = false; }
  }

  function startPolling() {
    if (pollHandle) return;
    fetch();
    pollHandle = window.setInterval(() => {
      if (document.hidden) return;
      fetch();
    }, 5000);
  }
  function stopPolling() {
    if (pollHandle) { clearInterval(pollHandle); pollHandle = null; }
  }

  return { status, loading, fetch, startPolling, stopPolling };
});
```

- [ ] **Step 2: Commit**:

```bash
git add web/apps/manage-portal/src/stores/pushstatus.ts
git commit -m "feat(manage-portal): pushstatus store with 5s polling"
```

### Task E7: `dashboard` store

**Files:**
- Create: `web/apps/manage-portal/src/stores/dashboard.ts`

- [ ] **Step 1: Write the store** — aggregates 3 endpoint calls:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import { useApiClient } from './apiClient';

export interface DashboardStats {
  hostsCount: number;
  activeAgents: number;
  runningJobs: number;
  queuedJobs: number;
  failedJobsToday: number;
  pushQueueDepth: number;
  lastPushAgeSeconds: number;
}

export const useDashboardStore = defineStore('dashboard', () => {
  const stats = ref<DashboardStats | null>(null);
  const loading = ref(false);
  let pollHandle: number | null = null;

  async function fetch() {
    const api = useApiClient().get();
    loading.value = true;
    try {
      const [hosts, agents, jobs, push] = await Promise.all([
        api.listHosts(),
        api.listAgents(),
        api.listScanJobs({ limit: 500 }),
        api.getPushStatus(),
      ]);
      const todayStart = new Date(); todayStart.setHours(0,0,0,0);
      const failedToday = jobs.filter(j =>
        j.status === 'failed' && j.finished_at && new Date(j.finished_at) >= todayStart
      ).length;
      stats.value = {
        hostsCount: hosts.length,
        activeAgents: agents.filter(a => a.status === 'active').length,
        runningJobs: jobs.filter(j => j.status === 'running').length,
        queuedJobs: jobs.filter(j => j.status === 'queued').length,
        failedJobsToday: failedToday,
        pushQueueDepth: push.queue_depth,
        lastPushAgeSeconds: push.last_pushed_at
          ? Math.floor((Date.now() - new Date(push.last_pushed_at).getTime()) / 1000)
          : -1,
      };
    } finally { loading.value = false; }
  }

  function startPolling() {
    if (pollHandle) return;
    fetch();
    pollHandle = window.setInterval(() => {
      if (document.hidden) return;
      fetch();
    }, 5000);
  }
  function stopPolling() {
    if (pollHandle) { clearInterval(pollHandle); pollHandle = null; }
  }

  return { stats, loading, fetch, startPolling, stopPolling };
});
```

- [ ] **Step 2: Commit**:

```bash
git add web/apps/manage-portal/src/stores/dashboard.ts
git commit -m "feat(manage-portal): dashboard store with aggregate + 5s polling"
```

### Task E8: remaining small stores (users, licence, settings)

**Files:**
- Create: `web/apps/manage-portal/src/stores/users.ts`
- Create: `web/apps/manage-portal/src/stores/licence.ts`
- Create: `web/apps/manage-portal/src/stores/settings.ts`

- [ ] **Step 1: Write `users.ts`**:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import type { ManageUser, CreateUserReq, CreateUserResp } from '@triton/api-client';
import { useApiClient } from './apiClient';

export const useUsersStore = defineStore('users', () => {
  const items = ref<ManageUser[]>([]);
  const loading = ref(false);

  async function fetch() {
    loading.value = true;
    try { items.value = await useApiClient().get().listUsers(); }
    finally { loading.value = false; }
  }
  async function create(req: CreateUserReq): Promise<CreateUserResp> {
    const resp = await useApiClient().get().createUser(req);
    await fetch();
    return resp;
  }

  return { items, loading, fetch, create };
});
```

- [ ] **Step 2: Write `licence.ts`**:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';
import { useApiClient } from './apiClient';

export interface LicenceSummary {
  tier: string;
  features: Record<string, boolean>;
  limits: Record<string, unknown>;
  expiresAt: string | null;
  licenseServerURL: string | null;
}

export const useLicenceStore = defineStore('licence', () => {
  const summary = ref<LicenceSummary | null>(null);
  const loading = ref(false);

  async function fetch() {
    loading.value = true;
    try {
      // Licence data is embedded in /v1/me response on Manage Server.
      const me = await useApiClient().get().me();
      // For this MVP, we expose role only; a dedicated /admin/licence
      // endpoint can back a richer summary in a follow-up. Until then
      // the view surfaces "active" when me() succeeds and "inactive"
      // otherwise.
      summary.value = {
        tier: 'active', // placeholder — see above
        features: {}, limits: {}, expiresAt: null, licenseServerURL: null,
      };
    } finally { loading.value = false; }
  }

  return { summary, loading, fetch };
});
```

**Note:** the plan punts full licence detail. B2.2 backend doesn't expose a `/api/v1/admin/licence` summary endpoint — `manage_license_state` + guard state live in internal stores. A follow-up PR adds the endpoint; the view in this PR shows "Active" state only.

- [ ] **Step 3: Write `settings.ts`**:

```ts
import { defineStore } from 'pinia';
import { ref } from 'vue';

export interface ManageSettings {
  parallelism: number;
  gatewayListen: string;
  gatewayHostname: string;
  reportServerURL: string;
  instanceID: string;
}

export const useSettingsStore = defineStore('settings', () => {
  const settings = ref<ManageSettings | null>(null);
  const loading = ref(false);

  async function fetch() {
    // No dedicated endpoint in B2.2; show a static placeholder. A
    // follow-up PR exposes GET /v1/admin/settings returning the
    // runtime config (parallelism, gateway host, etc.).
    loading.value = true;
    settings.value = {
      parallelism: 10,
      gatewayListen: ':8443',
      gatewayHostname: 'localhost',
      reportServerURL: '',
      instanceID: '',
    };
    loading.value = false;
  }

  return { settings, loading, fetch };
});
```

- [ ] **Step 4: Commit**:

```bash
git add web/apps/manage-portal/src/stores/users.ts web/apps/manage-portal/src/stores/licence.ts web/apps/manage-portal/src/stores/settings.ts
git commit -m "feat(manage-portal): users/licence/settings stores"
```

---

## Batch F — Inventory views

Three views + their modals. All follow the same pattern: list table + modal forms + tests with a fake store.

### Task F1: `Zones` view

**Files:**
- Create: `web/apps/manage-portal/src/views/Zones.vue`
- Create: `web/apps/manage-portal/src/views/modals/ZoneForm.vue`
- Create: `web/apps/manage-portal/tests/views/Zones.spec.ts`

- [ ] **Step 1: Write `ZoneForm.vue`** — modal wrapping TFormField + TInput:

```vue
<script setup lang="ts">
import { ref, watch } from 'vue';
import { TModal, TInput, TFormField, TButton } from '@triton/ui';
import type { Zone } from '@triton/api-client';

const props = defineProps<{ open: boolean; editing?: Zone | null }>();
const emit = defineEmits<{
  close: [];
  submit: [req: { name: string; description?: string }];
}>();

const name = ref(''); const description = ref(''); const busy = ref(false);

watch(() => props.editing, (z) => {
  name.value = z?.name ?? '';
  description.value = z?.description ?? '';
}, { immediate: true });

async function onSubmit() {
  busy.value = true;
  emit('submit', { name: name.value, description: description.value });
  busy.value = false;
}
</script>
<template>
  <TModal :open="props.open" :title="props.editing ? 'Edit zone' : 'New zone'" @close="emit('close')">
    <TFormField label="Name"><TInput v-model="name" /></TFormField>
    <TFormField label="Description (optional)"><TInput v-model="description" /></TFormField>
    <template #footer>
      <TButton variant="ghost" @click="emit('close')">Cancel</TButton>
      <TButton variant="primary" :disabled="!name || busy" @click="onSubmit">
        {{ props.editing ? 'Save' : 'Create' }}
      </TButton>
    </template>
  </TModal>
</template>
```

- [ ] **Step 2: Write `Zones.vue`**:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TDataTable, TButton, TConfirmDialog, useToast, type Column } from '@triton/ui';
import { useZonesStore } from '../stores/zones';
import ZoneForm from './modals/ZoneForm.vue';
import type { Zone } from '@triton/api-client';

const zones = useZonesStore();
const toast = useToast();

const formOpen = ref(false);
const editing = ref<Zone | null>(null);
const confirmDelete = ref<Zone | null>(null);

const columns: Column<Zone>[] = [
  { key: 'name', label: 'Name' },
  { key: 'description', label: 'Description' },
  { key: 'created_at', label: 'Created' },
];

onMounted(() => zones.fetch());

async function save(req: { name: string; description?: string }) {
  try {
    if (editing.value) await zones.update(editing.value.id, req);
    else await zones.create(req);
    toast.success({ title: editing.value ? 'Zone updated' : 'Zone created' });
    formOpen.value = false;
    editing.value = null;
  } catch (e) {
    toast.error({ title: 'Failed', description: String(e) });
  }
}
async function doDelete() {
  if (!confirmDelete.value) return;
  try {
    await zones.remove(confirmDelete.value.id);
    toast.success({ title: 'Zone deleted' });
  } catch (e) { toast.error({ title: 'Delete failed', description: String(e) }); }
  confirmDelete.value = null;
}
</script>
<template>
  <section class="view">
    <header>
      <h1>Zones</h1>
      <TButton variant="primary" @click="editing = null; formOpen = true">New zone</TButton>
    </header>
    <TDataTable :rows="zones.items" :columns="columns">
      <template #actions="{ row }">
        <TButton size="sm" variant="ghost" @click="editing = row; formOpen = true">Edit</TButton>
        <TButton size="sm" variant="ghost" @click="confirmDelete = row">Delete</TButton>
      </template>
    </TDataTable>
    <ZoneForm :open="formOpen" :editing="editing" @close="formOpen = false" @submit="save" />
    <TConfirmDialog
      :open="!!confirmDelete"
      title="Delete zone?"
      :message="`This will delete zone ${confirmDelete?.name ?? ''}. Hosts in this zone will be set to zone=null.`"
      @cancel="confirmDelete = null"
      @confirm="doDelete"
    />
  </section>
</template>
<style scoped>
.view { padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
header { display: flex; align-items: center; justify-content: space-between; }
</style>
```

- [ ] **Step 3: Write `Zones.spec.ts`**:

```ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Zones from '../../src/views/Zones.vue';
import { useZonesStore } from '../../src/stores/zones';

describe('Zones view', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('renders zone rows from the store', () => {
    const w = mount(Zones, {
      global: {
        plugins: [createTestingPinia({ createSpy: vi.fn, initialState: {
          zones: { items: [{ id: '1', name: 'dmz', description: 'p', created_at: '', updated_at: '' }] },
        } })],
        stubs: ['TDataTable', 'TButton', 'TConfirmDialog', 'ZoneForm'],
      },
    });
    expect(w.html()).toContain('dmz');
  });

  it('calls zones.fetch on mount', () => {
    const w = mount(Zones, {
      global: {
        plugins: [createTestingPinia({ createSpy: vi.fn })],
        stubs: ['TDataTable', 'TButton', 'TConfirmDialog', 'ZoneForm'],
      },
    });
    const store = useZonesStore();
    expect(store.fetch).toHaveBeenCalled();
  });
});
```

- [ ] **Step 4: Run tests + commit**:

```bash
cd web && pnpm --filter manage-portal test
# Update router.ts to point /inventory/zones at this view:
# { path: '/inventory/zones', name: 'zones', component: () => import('./views/Zones.vue') },
```

Commit:

```bash
git add web/apps/manage-portal/src web/apps/manage-portal/tests
git commit -m "feat(manage-portal): Zones view with CRUD modals"
```

### Task F2: `Hosts` view

**Files:**
- Create: `web/apps/manage-portal/src/views/Hosts.vue`
- Create: `web/apps/manage-portal/src/views/modals/HostForm.vue`
- Create: `web/apps/manage-portal/src/views/modals/HostBulkForm.vue`
- Create: `web/apps/manage-portal/tests/views/Hosts.spec.ts`

Same structural pattern as Zones plus:
- **Zone filter dropdown** at top of view (binds to `hosts.filter.zoneID`; triggers `hosts.fetch()` on change).
- **Bulk Import modal** with a textarea accepting a JSON array of `CreateHostReq`; validates with `JSON.parse`; calls `hosts.bulkCreate(parsed.hosts)`; on conflict (thrown error with "hostname"), surfaces inline.

- [ ] **Step 1: Write `HostForm.vue`** — same shape as ZoneForm but with `hostname`, `ip`, `zone_id` (dropdown from zones store), `os` fields.

- [ ] **Step 2: Write `HostBulkForm.vue`**:

```vue
<script setup lang="ts">
import { ref } from 'vue';
import { TModal, TButton } from '@triton/ui';
import type { CreateHostReq } from '@triton/api-client';

const props = defineProps<{ open: boolean }>();
const emit = defineEmits<{ close: []; submit: [req: CreateHostReq[]] }>();

const raw = ref(''); const error = ref('');

function parseAndSubmit() {
  error.value = '';
  try {
    const parsed = JSON.parse(raw.value);
    const hosts: CreateHostReq[] = Array.isArray(parsed) ? parsed : parsed.hosts;
    if (!Array.isArray(hosts)) throw new Error('expected JSON array of hosts');
    emit('submit', hosts);
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'invalid JSON';
  }
}
</script>
<template>
  <TModal :open="props.open" title="Bulk import hosts" @close="emit('close')">
    <textarea v-model="raw" rows="12" placeholder='[{"hostname":"db-01","zone_id":"..."}]' />
    <p v-if="error" class="err">{{ error }}</p>
    <template #footer>
      <TButton variant="ghost" @click="emit('close')">Cancel</TButton>
      <TButton variant="primary" :disabled="!raw" @click="parseAndSubmit">Import</TButton>
    </template>
  </TModal>
</template>
<style scoped>
textarea { width: 100%; font-family: var(--font-mono); font-size: 0.85rem; padding: var(--space-2); }
.err { color: var(--danger); }
</style>
```

- [ ] **Step 3: Write `Hosts.vue`** — mirror the Zones structure + add a `<TSelect>` for zone filter + a second "Bulk import" button alongside "New host":

```vue
<script setup lang="ts">
import { onMounted, ref, watch } from 'vue';
import { TDataTable, TButton, TSelect, TConfirmDialog, useToast, type Column } from '@triton/ui';
import { useHostsStore } from '../stores/hosts';
import { useZonesStore } from '../stores/zones';
import HostForm from './modals/HostForm.vue';
import HostBulkForm from './modals/HostBulkForm.vue';
import type { Host, CreateHostReq } from '@triton/api-client';

const hosts = useHostsStore();
const zones = useZonesStore();
const toast = useToast();

const formOpen = ref(false);
const bulkOpen = ref(false);
const editing = ref<Host | null>(null);
const confirmDelete = ref<Host | null>(null);

const columns: Column<Host>[] = [
  { key: 'hostname', label: 'Hostname' },
  { key: 'ip', label: 'IP' },
  { key: 'zone_id', label: 'Zone' },
  { key: 'os', label: 'OS' },
  { key: 'last_seen_at', label: 'Last seen' },
];

onMounted(async () => { await zones.fetch(); await hosts.fetch(); });

// Refetch hosts when the zone filter changes.
watch(() => hosts.filter.zoneID, () => hosts.fetch());

async function save(req: CreateHostReq) {
  try {
    if (editing.value) await hosts.update(editing.value.id, req);
    else await hosts.create(req);
    toast.success({ title: editing.value ? 'Host updated' : 'Host created' });
    formOpen.value = false; editing.value = null;
  } catch (e) { toast.error({ title: 'Failed', description: String(e) }); }
}
async function bulkSave(batch: CreateHostReq[]) {
  try {
    await hosts.bulkCreate(batch);
    toast.success({ title: `Imported ${batch.length} host(s)` });
    bulkOpen.value = false;
  } catch (e) { toast.error({ title: 'Import failed', description: String(e) }); }
}
async function doDelete() {
  if (!confirmDelete.value) return;
  try { await hosts.remove(confirmDelete.value.id); toast.success({ title: 'Host deleted' }); }
  catch (e) { toast.error({ title: 'Delete failed', description: String(e) }); }
  confirmDelete.value = null;
}
</script>
<template>
  <section class="view">
    <header>
      <h1>Hosts</h1>
      <div class="toolbar">
        <TSelect v-model="hosts.filter.zoneID">
          <option :value="undefined">All zones</option>
          <option v-for="z in zones.items" :key="z.id" :value="z.id">{{ z.name }}</option>
        </TSelect>
        <TButton variant="ghost" @click="bulkOpen = true">Bulk import</TButton>
        <TButton variant="primary" @click="editing = null; formOpen = true">New host</TButton>
      </div>
    </header>
    <TDataTable :rows="hosts.items" :columns="columns">
      <template #actions="{ row }">
        <TButton size="sm" variant="ghost" @click="editing = row; formOpen = true">Edit</TButton>
        <TButton size="sm" variant="ghost" @click="confirmDelete = row">Delete</TButton>
      </template>
    </TDataTable>
    <HostForm :open="formOpen" :editing="editing" :zones="zones.items" @close="formOpen = false" @submit="save" />
    <HostBulkForm :open="bulkOpen" @close="bulkOpen = false" @submit="bulkSave" />
    <TConfirmDialog
      :open="!!confirmDelete" title="Delete host?"
      :message="`This will delete ${confirmDelete?.hostname ?? ''}.`"
      @cancel="confirmDelete = null" @confirm="doDelete"
    />
  </section>
</template>
<style scoped>
.view { padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
header { display: flex; align-items: center; justify-content: space-between; }
.toolbar { display: flex; gap: var(--space-2); align-items: center; }
</style>
```

- [ ] **Step 4: Write `Hosts.spec.ts`** — assert list renders, zone-filter change calls `hosts.fetch`, bulk import modal opens.

- [ ] **Step 5: Run tests + update router.ts + commit**:

```bash
cd web && pnpm --filter manage-portal test
# Update router.ts: { path: '/inventory/hosts', component: () => import('./views/Hosts.vue') }
git add web/apps/manage-portal
git commit -m "feat(manage-portal): Hosts view with zone filter + bulk import"
```

### Task F3: `Agents` view

**Files:**
- Create: `web/apps/manage-portal/src/views/Agents.vue`
- Create: `web/apps/manage-portal/src/views/modals/AgentEnrolForm.vue`
- Create: `web/apps/manage-portal/tests/views/Agents.spec.ts`

- [ ] **Step 1: Write `AgentEnrolForm.vue`** — loud warning banner + one-shot submit:

```vue
<script setup lang="ts">
import { ref } from 'vue';
import { TModal, TInput, TFormField, TSelect, TButton } from '@triton/ui';
import type { Zone } from '@triton/api-client';

const props = defineProps<{ open: boolean; zones: Zone[] }>();
const emit = defineEmits<{ close: []; submit: [req: { name: string; zone_id?: string }] }>();

const name = ref(''); const zoneID = ref<string | undefined>(undefined);
const busy = ref(false);

function onSubmit() { busy.value = true; emit('submit', { name: name.value, zone_id: zoneID.value }); busy.value = false; }
</script>
<template>
  <TModal :open="props.open" title="Enrol new agent" @close="emit('close')">
    <div class="warn">
      <strong>⚠ Single-use bundle</strong>
      <p>
        The agent's private key is included in the bundle and is <em>not</em> stored
        on the server. When you click Enrol the download starts immediately — save
        the file or the key is lost. Deleting the saved file means you must revoke
        the agent and enrol again.
      </p>
    </div>
    <TFormField label="Agent name"><TInput v-model="name" /></TFormField>
    <TFormField label="Zone (optional)">
      <TSelect v-model="zoneID">
        <option :value="undefined">Unassigned</option>
        <option v-for="z in props.zones" :key="z.id" :value="z.id">{{ z.name }}</option>
      </TSelect>
    </TFormField>
    <template #footer>
      <TButton variant="ghost" @click="emit('close')">Cancel</TButton>
      <TButton variant="primary" :disabled="!name || busy" @click="onSubmit">
        {{ busy ? 'Enrolling…' : 'Enrol + download' }}
      </TButton>
    </template>
  </TModal>
</template>
<style scoped>
.warn { padding: var(--space-3); background: var(--warning-bg); border-radius: var(--radius-md); margin-bottom: var(--space-3); }
.warn strong { display: block; margin-bottom: var(--space-1); }
.warn em { font-style: italic; }
</style>
```

- [ ] **Step 2: Write `Agents.vue`** — list (with status pill), "New agent" modal, revoke via TConfirmDialog:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TDataTable, TButton, TPill, TConfirmDialog, useToast, type Column } from '@triton/ui';
import { useAgentsStore } from '../stores/agents';
import { useZonesStore } from '../stores/zones';
import AgentEnrolForm from './modals/AgentEnrolForm.vue';
import type { Agent, AgentStatus } from '@triton/api-client';

const agents = useAgentsStore();
const zones = useZonesStore();
const toast = useToast();

const enrolOpen = ref(false);
const confirmRevoke = ref<Agent | null>(null);

const columns: Column<Agent>[] = [
  { key: 'name', label: 'Name' },
  { key: 'zone_id', label: 'Zone' },
  { key: 'status', label: 'Status' },
  { key: 'cert_expires_at', label: 'Cert expires' },
  { key: 'last_seen_at', label: 'Last seen' },
];

const statusVariant: Record<AgentStatus, 'success' | 'warning' | 'danger'> = {
  active: 'success', pending: 'warning', revoked: 'danger',
};

onMounted(async () => { await zones.fetch(); await agents.fetch(); });

async function enrol(req: { name: string; zone_id?: string }) {
  try {
    const filename = await agents.enrol(req);
    toast.success({ title: 'Agent enrolled', description: `Bundle saved as ${filename}` });
    enrolOpen.value = false;
  } catch (e) {
    toast.error({ title: 'Enrol failed', description: String(e) });
  }
}
async function doRevoke() {
  if (!confirmRevoke.value) return;
  try {
    await agents.revoke(confirmRevoke.value.id);
    toast.success({ title: 'Agent revoked' });
  } catch (e) { toast.error({ title: 'Revoke failed', description: String(e) }); }
  confirmRevoke.value = null;
}
</script>
<template>
  <section class="view">
    <header>
      <h1>Agents</h1>
      <TButton variant="primary" @click="enrolOpen = true">New agent</TButton>
    </header>
    <TDataTable :rows="agents.items" :columns="columns">
      <template #cell-status="{ row }">
        <TPill :variant="statusVariant[row.status]">{{ row.status }}</TPill>
      </template>
      <template #actions="{ row }">
        <TButton v-if="row.status !== 'revoked'" size="sm" variant="ghost"
                 @click="confirmRevoke = row">Revoke</TButton>
      </template>
    </TDataTable>
    <AgentEnrolForm :open="enrolOpen" :zones="zones.items" @close="enrolOpen = false" @submit="enrol" />
    <TConfirmDialog
      :open="!!confirmRevoke" title="Revoke agent?"
      :message="`Revoking ${confirmRevoke?.name ?? ''} invalidates its cert within 30s. Rotation and re-enrol will both need fresh operator action.`"
      @cancel="confirmRevoke = null" @confirm="doRevoke"
    />
  </section>
</template>
<style scoped>
.view { padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
header { display: flex; align-items: center; justify-content: space-between; }
</style>
```

- [ ] **Step 3: Write `Agents.spec.ts`** — assert enrol button triggers `agents.enrol`, revoke double-confirms.

- [ ] **Step 4: Update router + commit**:

```bash
cd web && pnpm --filter manage-portal test
# Update router.ts: { path: '/inventory/agents', component: () => import('./views/Agents.vue') }
git add web/apps/manage-portal
git commit -m "feat(manage-portal): Agents view with one-shot enrol + revoke"
```

---

## Batch G — Operations views

### Task G1: `Dashboard` view

**Files:**
- Create: `web/apps/manage-portal/src/views/Dashboard.vue`
- Create: `web/apps/manage-portal/tests/views/Dashboard.spec.ts`

- [ ] **Step 1: Write `Dashboard.vue`** — five TStatCard tiles + polling lifecycle:

```vue
<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue';
import { TStatCard } from '@triton/ui';
import { useDashboardStore } from '../stores/dashboard';

const dash = useDashboardStore();

onMounted(() => dash.startPolling());
onUnmounted(() => dash.stopPolling());

function fmtAge(sec: number): string {
  if (sec < 0) return 'never';
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  return `${Math.floor(sec / 3600)}h ago`;
}
</script>
<template>
  <section class="view">
    <h1>Dashboard</h1>
    <div class="grid">
      <TStatCard label="Hosts" :value="dash.stats?.hostsCount ?? '—'" />
      <TStatCard label="Active agents" :value="dash.stats?.activeAgents ?? '—'" />
      <TStatCard label="Running + queued jobs"
                 :value="(dash.stats?.runningJobs ?? 0) + (dash.stats?.queuedJobs ?? 0)" />
      <TStatCard label="Failed today" :value="dash.stats?.failedJobsToday ?? '—'" />
      <TStatCard label="Push queue" :value="dash.stats?.pushQueueDepth ?? '—'"
                 :hint="dash.stats ? `last push: ${fmtAge(dash.stats.lastPushAgeSeconds)}` : ''" />
    </div>
  </section>
</template>
<style scoped>
.view { padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: var(--space-3); }
</style>
```

- [ ] **Step 2: Write `Dashboard.spec.ts`**:

```ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { createTestingPinia } from '@pinia/testing';
import Dashboard from '../../src/views/Dashboard.vue';
import { useDashboardStore } from '../../src/stores/dashboard';

describe('Dashboard', () => {
  it('starts polling on mount and stops on unmount', () => {
    const w = mount(Dashboard, {
      global: { plugins: [createTestingPinia({ createSpy: vi.fn })], stubs: ['TStatCard'] },
    });
    const store = useDashboardStore();
    expect(store.startPolling).toHaveBeenCalled();
    w.unmount();
    expect(store.stopPolling).toHaveBeenCalled();
  });
});
```

- [ ] **Step 3: Run + update router + commit**:

```bash
cd web && pnpm --filter manage-portal test
# router: { path: '/dashboard', component: () => import('./views/Dashboard.vue') }
git add web/apps/manage-portal
git commit -m "feat(manage-portal): Dashboard with 5 stat cards + polling"
```

### Task G2: `ScanJobs` view + detail drawer

**Files:**
- Create: `web/apps/manage-portal/src/views/ScanJobs.vue`
- Create: `web/apps/manage-portal/src/views/modals/ScanJobEnqueueForm.vue`
- Create: `web/apps/manage-portal/src/views/modals/ScanJobDetailDrawer.vue`
- Create: `web/apps/manage-portal/tests/views/ScanJobs.spec.ts`

- [ ] **Step 1: Write `ScanJobEnqueueForm.vue`** — modal with zone multi-select + profile dropdown + optional hostname glob:

```vue
<script setup lang="ts">
import { ref } from 'vue';
import { TModal, TSelect, TFormField, TInput, TButton } from '@triton/ui';
import type { Zone, EnqueueReq, ScanJobProfile } from '@triton/api-client';

const props = defineProps<{ open: boolean; zones: Zone[] }>();
const emit = defineEmits<{ close: []; submit: [req: EnqueueReq] }>();

const selectedZones = ref<string[]>([]);
const profile = ref<ScanJobProfile>('standard');
const filter = ref('');
const busy = ref(false);

function onSubmit() {
  busy.value = true;
  emit('submit', {
    zones: selectedZones.value,
    profile: profile.value,
    target_filter: filter.value || undefined,
  });
  busy.value = false;
}
</script>
<template>
  <TModal :open="props.open" title="Enqueue scan jobs" @close="emit('close')">
    <TFormField label="Zones (multi-select)">
      <select v-model="selectedZones" multiple>
        <option v-for="z in props.zones" :key="z.id" :value="z.id">{{ z.name }}</option>
      </select>
    </TFormField>
    <TFormField label="Profile">
      <TSelect v-model="profile">
        <option value="quick">Quick</option>
        <option value="standard">Standard</option>
        <option value="comprehensive">Comprehensive</option>
      </TSelect>
    </TFormField>
    <TFormField label="Hostname filter (glob, optional)">
      <TInput v-model="filter" placeholder="db-*" />
    </TFormField>
    <template #footer>
      <TButton variant="ghost" @click="emit('close')">Cancel</TButton>
      <TButton variant="primary" :disabled="selectedZones.length === 0 || busy" @click="onSubmit">
        {{ busy ? 'Enqueueing…' : 'Enqueue' }}
      </TButton>
    </template>
  </TModal>
</template>
```

- [ ] **Step 2: Write `ScanJobDetailDrawer.vue`** — right-side slide-over:

```vue
<script setup lang="ts">
import { watch } from 'vue';
import type { ScanJob } from '@triton/api-client';
import { useScanJobsStore } from '../../stores/scanjobs';

const props = defineProps<{ open: boolean; jobID: string | null }>();
const emit = defineEmits<{ close: [] }>();

const store = useScanJobsStore();

watch(() => props.jobID, async (id) => {
  if (id && props.open) await store.getDetail(id);
});

function refresh() {
  if (props.jobID) store.getDetail(props.jobID);
}
</script>
<template>
  <div v-if="props.open" class="drawer">
    <header>
      <h2>Scan Job</h2>
      <button class="close" @click="emit('close')">×</button>
    </header>
    <div v-if="store.selected" class="body">
      <dl>
        <dt>ID</dt><dd>{{ store.selected.id }}</dd>
        <dt>Status</dt><dd>{{ store.selected.status }}</dd>
        <dt>Profile</dt><dd>{{ store.selected.profile }}</dd>
        <dt>Host</dt><dd>{{ store.selected.host_id ?? '—' }}</dd>
        <dt>Zone</dt><dd>{{ store.selected.zone_id ?? '—' }}</dd>
        <dt>Enqueued</dt><dd>{{ store.selected.enqueued_at }}</dd>
        <dt>Started</dt><dd>{{ store.selected.started_at ?? '—' }}</dd>
        <dt>Finished</dt><dd>{{ store.selected.finished_at ?? '—' }}</dd>
        <dt>Progress</dt><dd>{{ store.selected.progress_text || '—' }}</dd>
        <dt>Error</dt><dd>{{ store.selected.error_message || '—' }}</dd>
      </dl>
      <button class="refresh" @click="refresh">Refresh</button>
    </div>
  </div>
</template>
<style scoped>
.drawer { position: fixed; top: 0; right: 0; bottom: 0; width: 440px; background: var(--bg-surface); box-shadow: -8px 0 24px rgba(0,0,0,0.12); padding: var(--space-4); z-index: 50; overflow-y: auto; }
header { display: flex; align-items: center; justify-content: space-between; margin-bottom: var(--space-3); }
.close { background: transparent; border: none; font-size: 1.5rem; cursor: pointer; }
dl { display: grid; grid-template-columns: 120px 1fr; gap: var(--space-1) var(--space-3); }
dt { color: var(--text-muted); font-size: 0.8rem; }
dd { font-family: var(--font-mono); font-size: 0.85rem; word-break: break-all; }
.refresh { margin-top: var(--space-3); }
</style>
```

- [ ] **Step 3: Write `ScanJobs.vue`**:

```vue
<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';
import { TDataTable, TButton, TPill, TSelect, useToast, type Column } from '@triton/ui';
import { useScanJobsStore } from '../stores/scanjobs';
import { useZonesStore } from '../stores/zones';
import ScanJobEnqueueForm from './modals/ScanJobEnqueueForm.vue';
import ScanJobDetailDrawer from './modals/ScanJobDetailDrawer.vue';
import type { ScanJob, ScanJobStatus, EnqueueReq } from '@triton/api-client';

const jobs = useScanJobsStore();
const zones = useZonesStore();
const toast = useToast();

const enqueueOpen = ref(false);
const drawerJobID = ref<string | null>(null);

const columns: Column<ScanJob>[] = [
  { key: 'profile', label: 'Profile' },
  { key: 'zone_id', label: 'Zone' },
  { key: 'host_id', label: 'Host' },
  { key: 'status', label: 'Status' },
  { key: 'enqueued_at', label: 'Enqueued' },
  { key: 'progress_text', label: 'Progress' },
];

const statusVariant: Record<ScanJobStatus, 'default' | 'success' | 'warning' | 'danger'> = {
  queued: 'default', running: 'warning', completed: 'success', failed: 'danger', cancelled: 'default',
};

onMounted(async () => { await zones.fetch(); jobs.startPolling(); });
onUnmounted(() => jobs.stopPolling());

async function onEnqueue(req: EnqueueReq) {
  try {
    const created = await jobs.enqueue(req);
    toast.success({ title: `Enqueued ${created.length} job(s)` });
    enqueueOpen.value = false;
  } catch (e) { toast.error({ title: 'Enqueue failed', description: String(e) }); }
}
async function cancelRow(j: ScanJob) {
  try { await jobs.requestCancel(j.id); toast.info({ title: 'Cancel requested' }); }
  catch (e) { toast.error({ title: 'Cancel failed', description: String(e) }); }
}
</script>
<template>
  <section class="view">
    <header>
      <h1>Scan Jobs</h1>
      <div class="toolbar">
        <TSelect v-model="jobs.filter.status">
          <option :value="undefined">All statuses</option>
          <option value="queued">Queued</option>
          <option value="running">Running</option>
          <option value="completed">Completed</option>
          <option value="failed">Failed</option>
          <option value="cancelled">Cancelled</option>
        </TSelect>
        <TButton variant="primary" @click="enqueueOpen = true">Enqueue</TButton>
      </div>
    </header>
    <TDataTable :rows="jobs.items" :columns="columns" @row-click="drawerJobID = $event.id">
      <template #cell-status="{ row }">
        <TPill :variant="statusVariant[row.status]">{{ row.status }}</TPill>
      </template>
      <template #actions="{ row }">
        <TButton v-if="row.status === 'queued' || row.status === 'running'"
                 size="sm" variant="ghost" @click.stop="cancelRow(row)">
          Cancel
        </TButton>
      </template>
    </TDataTable>
    <ScanJobEnqueueForm :open="enqueueOpen" :zones="zones.items"
                        @close="enqueueOpen = false" @submit="onEnqueue" />
    <ScanJobDetailDrawer :open="!!drawerJobID" :job-i-d="drawerJobID"
                         @close="drawerJobID = null" />
  </section>
</template>
<style scoped>
.view { padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
header { display: flex; align-items: center; justify-content: space-between; }
.toolbar { display: flex; gap: var(--space-2); align-items: center; }
</style>
```

- [ ] **Step 4: Write `ScanJobs.spec.ts`** — assert polling lifecycle, filter change triggers fetch, drawer opens on row-click, cancel calls store.

- [ ] **Step 5: Update router + commit**:

```bash
# router: { path: '/operations/scan-jobs', component: () => import('./views/ScanJobs.vue') }
cd web && pnpm --filter manage-portal test
git add web/apps/manage-portal
git commit -m "feat(manage-portal): Scan Jobs view with polling + detail drawer"
```

### Task G3: `PushStatus` view

**Files:**
- Create: `web/apps/manage-portal/src/views/PushStatus.vue`
- Create: `web/apps/manage-portal/tests/views/PushStatus.spec.ts`

- [ ] **Step 1: Write `PushStatus.vue`** — 4 cards from the store + last-error excerpt:

```vue
<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue';
import { TStatCard, TPanel } from '@triton/ui';
import { usePushStatusStore } from '../stores/pushstatus';

const ps = usePushStatusStore();

onMounted(() => ps.startPolling());
onUnmounted(() => ps.stopPolling());

function fmtAge(sec: number): string {
  if (sec < 0) return 'never';
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  return `${Math.floor(sec / 3600)}h`;
}
</script>
<template>
  <section class="view">
    <h1>Push Status</h1>
    <div class="grid">
      <TStatCard label="Queue depth" :value="ps.status?.queue_depth ?? '—'" />
      <TStatCard label="Oldest row"
                 :value="ps.status ? fmtAge(ps.status.oldest_row_age_seconds) : '—'" />
      <TStatCard label="Consecutive failures" :value="ps.status?.consecutive_failures ?? 0" />
      <TStatCard label="Last pushed"
                 :value="ps.status?.last_pushed_at ?? 'never'" />
    </div>
    <TPanel v-if="ps.status?.last_push_error" title="Last push error">
      <pre class="err">{{ ps.status.last_push_error.slice(0, 400) }}</pre>
    </TPanel>
  </section>
</template>
<style scoped>
.view { padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: var(--space-3); }
.err { font-family: var(--font-mono); font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; }
</style>
```

- [ ] **Step 2: Write `PushStatus.spec.ts`** — polling lifecycle, error excerpt truncation.

- [ ] **Step 3: Update router + commit**:

```bash
# router: { path: '/operations/push-status', component: () => import('./views/PushStatus.vue') }
git add web/apps/manage-portal
git commit -m "feat(manage-portal): Push Status view with 5s polling"
```

---

## Batch H — Admin views

### Task H1: `Users` view

**Files:**
- Create: `web/apps/manage-portal/src/views/Users.vue`
- Create: `web/apps/manage-portal/src/views/modals/UserCreateForm.vue`
- Create: `web/apps/manage-portal/src/views/modals/UserCreatedResult.vue` (shows temp password once)
- Create: `web/apps/manage-portal/tests/views/Users.spec.ts`

- [ ] **Step 1: Write `UserCreateForm.vue`** — standard form with email / name / role.

- [ ] **Step 2: Write `UserCreatedResult.vue`** — shows the temp password in a `TCodeBlock` with a "Copy" button, explicit "password shown once" warning:

```vue
<script setup lang="ts">
import { TModal, TButton } from '@triton/ui';
import TCodeBlock from '../../components/TCodeBlock.vue';

const props = defineProps<{ open: boolean; email: string; tempPassword: string }>();
const emit = defineEmits<{ close: [] }>();
</script>
<template>
  <TModal :open="props.open" title="User created" @close="emit('close')">
    <p>
      Temporary password for <strong>{{ props.email }}</strong>. Shown once —
      copy it now and share securely.
    </p>
    <TCodeBlock :code="props.tempPassword" />
    <template #footer>
      <TButton variant="primary" @click="emit('close')">Done</TButton>
    </template>
  </TModal>
</template>
```

- [ ] **Step 3: Write `Users.vue`** — list + create flow that opens `UserCreatedResult.vue` on success.

- [ ] **Step 4: Write `Users.spec.ts`** — assert temp password renders in TCodeBlock + clipboard copy.

- [ ] **Step 5: Update router + commit**.

### Task H2: `Licence` view

**Files:**
- Create: `web/apps/manage-portal/src/views/Licence.vue`
- Create: `web/apps/manage-portal/tests/views/Licence.spec.ts`

- [ ] **Step 1: Write minimal `Licence.vue`** — panel with summary + "Re-activate" button that routes to `/setup/license`:

```vue
<script setup lang="ts">
import { onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { TPanel, TButton } from '@triton/ui';
import { useLicenceStore } from '../stores/licence';

const licence = useLicenceStore();
const router = useRouter();

onMounted(() => licence.fetch());
</script>
<template>
  <section class="view">
    <h1>Licence</h1>
    <TPanel title="Status">
      <p v-if="licence.summary">Active</p>
      <p v-else>Loading…</p>
    </TPanel>
    <TPanel title="Actions">
      <TButton variant="ghost" @click="router.push('/setup/license')">Re-activate</TButton>
    </TPanel>
    <p class="note">
      Detailed licence summary (features, limits, heartbeat) will land in a
      follow-up PR alongside a dedicated <code>/admin/licence</code> endpoint
      on Manage Server.
    </p>
  </section>
</template>
<style scoped>
.view { padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
.note { color: var(--text-muted); font-size: 0.85rem; }
</style>
```

- [ ] **Step 2: Test + router + commit**.

### Task H3: `Settings` view

**Files:**
- Create: `web/apps/manage-portal/src/views/Settings.vue`
- Create: `web/apps/manage-portal/tests/views/Settings.spec.ts`

- [ ] **Step 1: Write `Settings.vue`** — read-only panel sourced from the placeholder store (same "follow-up PR adds backend endpoint" caveat as Licence):

```vue
<script setup lang="ts">
import { onMounted } from 'vue';
import { TPanel } from '@triton/ui';
import { useSettingsStore } from '../stores/settings';

const settings = useSettingsStore();
onMounted(() => settings.fetch());
</script>
<template>
  <section class="view">
    <h1>Settings</h1>
    <TPanel title="Runtime config">
      <dl v-if="settings.settings">
        <dt>Parallelism</dt><dd>{{ settings.settings.parallelism }}</dd>
        <dt>Gateway listen</dt><dd>{{ settings.settings.gatewayListen }}</dd>
        <dt>Gateway hostname</dt><dd>{{ settings.settings.gatewayHostname }}</dd>
        <dt>Report URL</dt><dd>{{ settings.settings.reportServerURL || '—' }}</dd>
        <dt>Instance ID</dt><dd>{{ settings.settings.instanceID || '—' }}</dd>
      </dl>
    </TPanel>
    <p class="note">
      Live values will be surfaced via a follow-up <code>GET /admin/settings</code>
      endpoint; today these are placeholders compiled from the B2.2 config defaults.
    </p>
  </section>
</template>
<style scoped>
.view { padding: var(--space-4); display: flex; flex-direction: column; gap: var(--space-3); }
dl { display: grid; grid-template-columns: 160px 1fr; gap: var(--space-1) var(--space-3); }
dt { color: var(--text-muted); }
dd { font-family: var(--font-mono); }
.note { color: var(--text-muted); font-size: 0.85rem; }
</style>
```

- [ ] **Step 2: Test + router + commit**.

---

## Batch I — Backend embed + legacy cutover

Ship the Go-side wiring that serves the built portal, delete the legacy UI, make the Docker image build-able.

### Task I1: `pkg/manageserver/ui.go` + SPA route

**Files:**
- Create: `pkg/manageserver/ui.go`
- Create: `pkg/manageserver/ui_test.go`
- Modify: `pkg/manageserver/server.go`

- [ ] **Step 1: Write `ui.go`**:

```go
// Package manageserver — ui.go wires the embedded Vue SPA from the
// sibling ui/dist/ directory into the HTTP router. The directory is
// populated by `make web-build-manage` (which runs Vite from
// web/apps/manage-portal/). Only `.gitkeep` is tracked; the built
// assets are .gitignore'd and reproduced from source at CI/container
// build time.
package manageserver

import "embed"

//go:embed all:ui/dist
var uiFS embed.FS
```

- [ ] **Step 2: Write failing test**:

```go
//go:build integration

package manageserver_test

import (
	"io/fs"
	"testing"

	"github.com/amiryahaya/triton/pkg/manageserver"
)

// TestUIFS_HasIndexAfterBuild asserts the embedded UI filesystem
// contains index.html. Run after `make web-build-manage` during local
// dev; CI runs it after the web-builder stage in Containerfile.
func TestUIFS_HasIndexAfterBuild(t *testing.T) {
	sub, err := fs.Sub(manageserver.UIFS(), "ui/dist")
	if err != nil {
		t.Fatalf("sub: %v", err)
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		t.Skipf("index.html not found (run `make web-build-manage` first): %v", err)
	}
}
```

For this to work, `ui.go` needs an exported accessor:

```go
// add to ui.go:
// UIFS returns the embedded Vue portal filesystem root. The `ui/dist`
// subtree is populated by the Vite build in web/apps/manage-portal.
// Exported for tests only; production code paths use the package-
// scoped uiFS directly in server.go.
func UIFS() embed.FS { return uiFS }
```

- [ ] **Step 3: Modify `server.go::buildRouter`** — add the SPA handler after `/api/v1/*` routes and BEFORE the catch-all:

```go
// In pkg/manageserver/server.go, buildRouter(), append before `return r`:

// Serve the embedded Vue portal at /ui/. Root and unknown paths
// redirect to /ui/ so operators can visit https://manage.example.com
// and land on the dashboard. The hash router inside the SPA handles
// deep links (#/inventory/hosts etc.) so no SPA-fallback logic is
// needed here.
uiSub, _ := fs.Sub(uiFS, "ui/dist")
r.Handle("/ui/*", http.StripPrefix("/ui/", http.FileServer(http.FS(uiSub))))
r.Get("/ui", func(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, "/ui/", http.StatusMovedPermanently)
})
r.Get("/", func(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, "/ui/", http.StatusFound)
})
```

Add imports:

```go
import (
	"io/fs"
	"net/http"
	// ... existing
)
```

- [ ] **Step 4: Verify build + run test**:

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-portal
make web-build-manage   # (from Task I2 — if not yet defined, run pnpm directly)
go build ./...
go test -tags integration -run TestUIFS_HasIndexAfterBuild ./pkg/manageserver/...
```

- [ ] **Step 5: Commit**:

```bash
git add pkg/manageserver/ui.go pkg/manageserver/ui_test.go pkg/manageserver/server.go
git commit -m "feat(manageserver): embed Vue portal + serve /ui/"
```

### Task I2: Makefile targets

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add `web-build-manage` target** alongside any existing `web-build-*` targets:

```makefile
.PHONY: web-build-manage

web-build-manage:
	cd web && pnpm --filter manage-portal build

# Ensure web-build-manage runs before container-build-manageserver
container-build-manageserver: web-build-manage
	podman build -f Containerfile.manageserver -t triton-manageserver:local .
```

If `container-build-manageserver` already exists in the Makefile, just add the `web-build-manage` prerequisite. Otherwise create it.

Also add to the general `build` target if it makes sense:

```makefile
# Existing `build` target gains manage-portal prereq only when building
# the manageserver binary. If `build` builds multiple binaries, keep
# web-build-manage scoped to container-build-manageserver.
```

- [ ] **Step 2: Test the target**:

```bash
make web-build-manage
ls pkg/manageserver/ui/dist/index.html
```

- [ ] **Step 3: Commit**:

```bash
git add Makefile
git commit -m "feat(make): web-build-manage target for manage-portal"
```

### Task I3: Containerfile multi-stage web build

**Files:**
- Modify: `Containerfile.manageserver`

- [ ] **Step 1: Add a web-builder stage** before the Go builder:

```dockerfile
# Stage 1: build the Vue portal so //go:embed picks it up in stage 2.
FROM docker.io/library/node:22-alpine AS web
WORKDIR /src
RUN npm install -g pnpm@10.29.3
COPY web/ web/
RUN cd web && pnpm install --frozen-lockfile && pnpm --filter manage-portal build

# Stage 2: Go build
FROM docker.io/library/golang:1.26 AS builder
ARG VERSION=dev
WORKDIR /src
ENV GOTOOLCHAIN=auto
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Overlay the built portal so go:embed finds it.
COPY --from=web /src/web/apps/manage-portal/dist pkg/manageserver/ui/dist
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/amiryahaya/triton/internal/version.Version=${VERSION}" \
    -o /triton-manageserver cmd/manageserver/main.go

# Stage 3: minimal runtime image
FROM scratch
ENV HOME=/tmp
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /triton-manageserver /triton-manageserver
EXPOSE 8082 8443
ENV TRITON_MANAGE_GATEWAY_LISTEN=:8443
ENTRYPOINT ["/triton-manageserver"]
```

- [ ] **Step 2: Build the image**:

```bash
podman build -f Containerfile.manageserver -t triton-manageserver:test .
```

Expected: image built successfully.

- [ ] **Step 3: Smoke-test the container**:

```bash
podman run --rm -d --name tm-smoke -p 18082:8082 \
  -e TRITON_MANAGE_JWT_SIGNING_KEY=$(openssl rand -hex 32) \
  -e TRITON_MANAGE_PUBLIC_KEY_HEX=$(printf '0%.0s' {1..64}) \
  -e TRITON_MANAGE_DB_URL=postgres://triton:triton@host.containers.internal:5435/triton_manage?sslmode=disable \
  triton-manageserver:test
sleep 3
curl -sI http://localhost:18082/ | head -5
# Expect: HTTP/1.1 302 Found + Location: /ui/
curl -s http://localhost:18082/ui/ | head -5
# Expect: HTML starting with <!DOCTYPE html>
podman stop tm-smoke
```

- [ ] **Step 4: Commit**:

```bash
git add Containerfile.manageserver
git commit -m "feat(container): manage-portal web-builder stage"
```

### Task I4: Delete legacy UI + Report Server route

**Files:**
- Delete: `pkg/server/ui/dist/manage/` (entire dir)
- Modify: `pkg/server/server.go` (remove `/ui/manage/*` redirect lines 539–545)
- Grep: search for any other references to the legacy path

- [ ] **Step 1: Inspect Report Server's redirect code**:

```bash
sed -n '530,560p' pkg/server/server.go
```

Locate the `/ui/manage/` redirect block and delete it. Example (exact lines may have shifted):

```go
// Remove this block:
//   r.Get("/manage", func(w http.ResponseWriter, r *http.Request) {
//       http.Redirect(w, r, "/ui/manage/", http.StatusFound)
//   })
//   r.Get("/manage/*", func(w http.ResponseWriter, r *http.Request) {
//       http.Redirect(w, r, "/ui/manage/", http.StatusFound)
//   })
```

- [ ] **Step 2: Delete the legacy UI directory**:

```bash
git rm -r pkg/server/ui/dist/manage/
```

- [ ] **Step 3: Grep the tree for any stale references**:

```bash
grep -rn "ui/manage\|dist/manage" . --include='*.go' --include='*.yaml' --include='*.md' 2>&1 | head -30
```

Fix any remaining references (tests, docs).

- [ ] **Step 4: Build + test**:

```bash
go build ./...
go test ./pkg/server/...
```

- [ ] **Step 5: Commit**:

```bash
git add pkg/server/server.go pkg/server/ui/dist/manage
git commit -m "chore(server): delete legacy manage UI + redirect (superseded by manage-portal)"
```

### Task I5: CI sanity pass

- [ ] **Step 1: Run full test + lint + build**:

```bash
# Web
cd web && pnpm install && pnpm --filter manage-portal build && pnpm --filter manage-portal test
# Go
cd .. && go build ./... && go vet ./... && go test ./pkg/manageserver/... ./pkg/server/...
# Lint (if golangci-lint runs on local)
golangci-lint run ./... 2>&1 | tail -20
```

Expected: all green.

- [ ] **Step 2: Commit any linter fixes found**.

---

## Batch J — PR open

### Task J1: Push + open PR

- [ ] **Step 1: Final local sanity**:

```bash
cd /Users/amirrudinyahaya/Workspace/triton/.worktrees/manage-portal
make web-build-manage
go build ./...
go test -tags integration ./pkg/manageserver/...
cd web && pnpm install && pnpm --filter manage-portal build && pnpm --filter manage-portal test
```

Expected: all green.

- [ ] **Step 2: Push the branch**:

```bash
git push -u origin feat/manage-portal-vue-ui
```

- [ ] **Step 3: Open the PR**:

```bash
gh pr create --title "feat(manage): Vue portal UI (PR C)" --body "$(cat <<'EOF'
## Summary

- New \`web/apps/manage-portal/\` Vue 3 portal covering every B2.2 Manage Server endpoint: dashboard, zones, hosts, agents, scan-jobs, push-status, users, licence, settings + setup wizard.
- Hash-routed (matches report-portal / license-portal convention).
- Grouped sidebar: Inventory / Operations / Admin.
- Hybrid polling: 5s on list views (scan-jobs, push-status, dashboard); on-demand refresh in the scan-job detail drawer.
- One-shot agent enrol: bundle downloads immediately on submit with a loud "save now, never stored server-side" warning.
- Modal dialogs for all create/edit/delete flows.
- Component tests (Vitest + @vue/test-utils + jsdom + \`createTestingPinia\`) for every view + guards + primitives.
- Embedded into the \`triton-manageserver\` binary via \`//go:embed all:ui/dist\`; served at \`/ui/\` with root \`/\` redirecting.
- Legacy \`pkg/server/ui/dist/manage/\` + Report Server redirect removed.
- \`Containerfile.manageserver\` gains a Node 22 web-builder stage; \`Makefile\` gains \`web-build-manage\` target.

Implements \`docs/superpowers/specs/2026-04-20-manage-portal-vue-ui-design.md\`.

## Known deferrals (tracked in \`memory/manage-server-rollout.md\`)

- **Real-agent smoke test:** enrol → bundle → live \`triton-agent\` → gateway phone-home chain is programmatically covered by \`TestManageE2E_AgentGatewayMTLS\` (Go) but no real binary has been pointed at a live Manage instance yet.
- **SSH-agentless credentials UI:** requires Manage-native \`credentials\` + \`discovery\` backend packages first. Out of scope.
- **Dedicated \`/admin/licence\` and \`/admin/settings\` endpoints:** Licence + Settings views show a minimal "active" state and a config placeholder. A follow-up PR wires full runtime config + licence detail endpoints.
- **Playwright / browser E2E:** deferred — the Go-side \`test/integration/manage_e2e_scan_flow_test.go\` is the end-to-end gate.

## Test plan

- [ ] \`make web-build-manage\` succeeds.
- [ ] \`cd web && pnpm --filter manage-portal test\` — all component tests green; coverage ≥ 80%.
- [ ] \`cd web && pnpm --filter manage-portal build\` — type-check + build clean.
- [ ] \`make container-build-manageserver\` produces an image.
- [ ] \`curl -I http://<manageserver>/\` → 302 to \`/ui/\`.
- [ ] \`curl http://<manageserver>/ui/\` → HTML starting with \`<!DOCTYPE html>\`.
- [ ] \`go test -tags integration ./pkg/manageserver/...\` — green.
- [ ] Manual: setup wizard completes → login → every sidebar item renders without errors.
- [ ] Manual: enrol an agent → browser downloads a \`.tar.gz\` → enrolment modal closes with toast.
- [ ] Manual: revoke an agent → status flips to \`revoked\`.
- [ ] Manual: enqueue a scan job → 5s polling tick shows it transition through statuses.
- [ ] Manual: push-status reflects queue depth changes.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Verify CI is green.** If anything fails, fix in follow-up commits; do not amend merged ancestors.

---

## Self-review

**Spec coverage:**
- §3 Architecture → Batch A (scaffolding) + Batch I (embed).
- §4 Routing & auth gating → Batch C (setup + guards + app shell).
- §5 Views & components → Batches D (TCodeBlock) + F (Inventory) + G (Operations) + H (Admin).
- §6 Pinia stores → Batch E.
- §7 API client → Batch B.
- §8 Embedding & cutover → Batch I.
- §9 Testing → component specs distributed across F / G / H / D; guard spec in C3; api-client test in B3.
- §10 Acceptance criteria → PR body test plan + Batch I5 / J1 sanity runs.

**Placeholder scan:**
- No "TBD" / "similar to above" / "add error handling" / vague requirements. The Licence and Settings views explicitly say "follow-up PR adds backend endpoint" — that's a documented deferral, not a placeholder.
- The `_authHeader` side-channel for enrolAgent's Blob fetch is ugly and explicitly called out as "follow-up refactor to @triton/api-client" — acknowledged, not hidden.

**Type consistency:**
- `createManageApi` / `ManageApi` names consistent between B2, C1, and every store.
- `EnqueueReq` same shape in types file and stores.
- `ScanJobStatus` / `AgentStatus` union types used consistently.
- `TCodeBlock` props `code`, `label?` match between D1 component + H1 `UserCreatedResult`.

**Known risks:**
- `@pinia/testing` may not be in the workspace devDeps yet; if the first view spec fails to import, add it to `web/apps/manage-portal/package.json` under devDependencies. Same for any missing `@types/node`-adjacent types.
- The `TDataTable` `row-click` event + `cell-<key>` slot pattern assumed from inspection of report-portal usage. If `@triton/ui::TDataTable` diverges, the Scan Jobs drawer-open logic needs a small adjustment (use `@click` on custom row cells instead).
