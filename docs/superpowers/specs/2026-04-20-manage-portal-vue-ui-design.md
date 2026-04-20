# Manage Portal — Vue UI Design (PR C)

> **Status:** Approved 2026-04-20 (brainstorm transcript). Parent spec: [`2026-04-19-license-v2-and-manage-portal-design.md`](./2026-04-19-license-v2-and-manage-portal-design.md) §5. Portal unification foundation: [`2026-04-18-portal-unification-design.md`](./2026-04-18-portal-unification-design.md).
>
> **Preceding work (merged):**
> - PR #81 (B1 backend shell): auth, setup, licence
> - PR #83 (B2.1 pool-injection refactor)
> - PR #85 (B2.2 scanner orchestrator + mTLS push)
> - PR #84 (report-portal Vue scaffold + JWT auth gate) — defines the baseline portal pattern this PR mirrors.

## 1. Problem

B2.2 shipped the backend surface for Manage Server: zones, hosts, scan-jobs, agents, push-status, users, licence, setup. The only UI serving the Manage Server today is the legacy vanilla JS bundle at `pkg/server/ui/dist/manage/` — served *by the Report Server*, covering only the B1 surface (auth, setup, licence). It does not surface any of B2.2's endpoints, and it has no path to ever do so (it's vanilla JS with no build pipeline, no framework, no shared component library).

PR C ships a Vue 3 portal covering every endpoint the B2.2 backend exposes, embedded directly into the `triton-manageserver` binary, and deletes the legacy UI in the same commit range.

### Goals

- Ship `web/apps/manage-portal/` as a Vue 3 Vite app inside the existing `web/` pnpm monorepo, alongside `report-portal` + `license-portal`.
- Cover every B2.2 endpoint with a view: dashboard, zones, hosts, scan-jobs, agents, push-status, users, licence, settings. Plus the pre-existing auth + setup flows.
- Embed the built SPA into `pkg/manageserver/ui/dist/` via `//go:embed`; serve at `/` on the admin `:8082` listener with SPA-fallback routing.
- Delete `pkg/server/ui/dist/manage/` and the Report Server route that serves it.
- Component-test coverage ≥ 80% via Vitest + `@vue/test-utils`.

### Non-goals

- **Playwright / browser E2E tests.** Deferred; the Go-side E2E in `test/integration/manage_e2e_scan_flow_test.go` is the end-to-end gate for the integrated pipeline.
- **New backend endpoints.** PR C surfaces existing endpoints only. No new migrations, no new handlers, no schema changes.
- **Credentials / discovery management.** B2.2 did not ship Manage-native `credentials` or `discovery` packages. SSH-agentless scans of remote hosts remain non-functional; unblocking them is a separate backend PR.
- **Real-agent smoke test.** The agent enrolment path is programmatically covered by `TestManageE2E_AgentGatewayMTLS`, but this PR does not wire a real `triton-agent` binary smoke test. Tracked in `manage-server-rollout.md` as a manual QA item before GA.
- **i18n, theming, visual-regression tests.** Out of scope.

## 2. Decisions captured from brainstorm (2026-04-20)

| # | Decision | Choice |
|---|---|---|
| 1 | Scope of endpoints covered | (b) Full B2.2 surfacing — UI-only; no new backend surface |
| 2 | Navigation shape | (b) Grouped sidebar: Inventory / Operations / Admin |
| 3 | Live-update pattern on volatile views | (c) Hybrid — 5s polling on list views, on-demand refresh on detail views |
| 4 | Legacy UI handling | (a) Delete `pkg/server/ui/dist/manage/` in the same PR |
| 5 | Dashboard landing content | (a) Summary stat cards |
| 6 | Create/edit form shape | (b) Modal dialogs over list views |
| 7 | Agent enrol bundle download UX | (a) One-shot modal + download-immediately + loud warning banner; no server-side bundle storage |
| 8 | Testing strategy | (c) Component tests (Vitest + `@vue/test-utils` + mocked api-client); no Playwright |

## 3. Architecture

### Monorepo layout

```
web/
  apps/
    license-portal/       ← existing
    report-portal/        ← existing (PR #84)
    manage-portal/        ← NEW
      package.json
      vite.config.ts
      index.html
      src/
        main.ts
        App.vue
        router.ts
        nav.ts
        stores/           ← Pinia stores per domain
        views/            ← one Vue component per route
        components/       ← portal-specific primitives not worth sharing
        types/            ← TS aliases / re-exports
      tests/
        guards.spec.ts
        views/*.spec.ts
  packages/
    api-client/           ← gains manageServer.ts
    auth/                 ← may gain small parameterisation (endpoint paths)
    ui/                   ← unchanged unless TDataTable needs extraction
```

### Stack

- Vue 3.5 (Composition API, `<script setup>`).
- Pinia 2 for stores.
- Vue Router 4 for routing (history mode).
- Vite 5 for bundling.
- Vitest + `@vue/test-utils` + `jsdom` for testing.
- `vue-tsc` for type-check on build.
- Workspace deps: `@triton/ui`, `@triton/auth`, `@triton/api-client`.

### Dev server

Vite on `:5175`. Proxies `/api/v1/*` → `http://localhost:8082` (the Manage Server admin listener). Matches conventions: license-portal `:5174`, report-portal `:5173`.

### Production embed

`pkg/manageserver/ui/dist/` populated by `make web-build-manage` (which delegates to `pnpm --filter manage-portal build`). A new Go file `pkg/manageserver/ui.go` declares:

```go
package manageserver

import "embed"

//go:embed all:ui/dist
var uiFS embed.FS
```

`server.go::buildRouter` mounts an SPA handler after the `/api/v1/*` routes:

```go
uiSub, _ := fs.Sub(uiFS, "ui/dist")
r.Handle("/*", spaHandler(uiSub))
```

`spaHandler` tries `ServeFileFS(path)`, falls back to `index.html` on 404. Reuse the existing helper in `pkg/server/ui_fs.go` — factor into a shared `internal/webserve` package if the two implementations would diverge.

### Legacy cutover

Same PR:

1. `git rm -r pkg/server/ui/dist/manage/`
2. Remove the Report Server route that serves `/ui/manage/*` (locate via `grep "ui/manage" pkg/server/server.go`).
3. Delete / repoint any integration tests referencing the legacy manage path.
4. Update `docs/DEPLOYMENT_GUIDE.md` if the legacy UI is referenced.

## 4. Routing & auth gating

### Route tree

```
/login                          — TLoginPrompt (from @triton/auth)
/setup                          — AppShell-less setup wizard
  /setup/admin                  — step 1: create first admin
  /setup/license                — step 2: activate licence against LS
/                               — AppShell with grouped sidebar
  /dashboard                    — default landing
  /inventory/zones
  /inventory/hosts
  /inventory/agents
  /operations/scan-jobs         — list view with slide-over drawer for detail
  /operations/push-status
  /admin/users
  /admin/licence
  /admin/settings
```

Note: scan-job detail is a **slide-over drawer** inside the list view, not a separate route. This preserves the 5s list-polling cadence while drilling into a single row. Drawer close returns to exact scroll position.

### Gating order (global `router.beforeEach`)

1. `GET /api/v1/health` on first-load — if 503, show a maintenance page and retry.
2. `GET /api/v1/setup/status` (cached for 30s) — if `setup_required=true`, force redirect to `/setup` unless already under `/setup/*`.
3. If `!setup_required` and no JWT in `localStorage` → redirect to `/login`.
4. Any 401 from an authenticated request → clear JWT + redirect to `/login`.

### Auth gate component

Reuse `@triton/auth::TAuthGate` from report-portal. If `TAuthGate` currently hardcodes the `/api/v1/auth/*` paths for Report Server, parameterise them in this PR (small additive change — accept a config with `loginPath`, `refreshPath`, `logoutPath`). Report-portal gets the new signature wired with its existing paths; manage-portal wires the same paths (Manage Server uses identical `/api/v1/auth/*` shape).

## 5. Views & components

### Sidebar groups

| Group | Items |
|---|---|
| **Inventory** | Zones, Hosts, Agents |
| **Operations** | Dashboard, Scan Jobs, Push Status |
| **Admin** | Users, Licence, Settings |

### Per-view spec

| View | Content | Forms | Polling |
|---|---|---|---|
| **Dashboard** | 5 stat cards: hosts count, active-agents count, running+queued jobs, today's failed jobs, push queue depth + last push age | — | 5s on the whole card grid |
| **Zones** | Data table (name, description, host count, created_at) | Create/Edit modal (name + description) | — |
| **Hosts** | Data table (hostname, IP, zone, OS, last seen) + zone-filter dropdown | Create/Edit modal + Bulk Import modal (paste JSON/CSV of rows) | — |
| **Agents** | Data table (name, zone, status, cert expiry, last seen) | Enrol modal (name + zone dropdown → one-shot bundle download) + Revoke confirm | — |
| **Scan Jobs** | Data table (profile, zone, host, status, enqueued, duration, progress text) + status filter | Enqueue modal (zone multi-select + profile dropdown + optional hostname filter) + Cancel confirm + Drawer on row click | 5s on list; on-demand in drawer |
| **Push Status** | Cards: queue depth, oldest row age, consecutive failures, last push timestamp, last error excerpt | — | 5s |
| **Users** | Data table (email, name, role, created, must-change-pw flag) | Create modal (email + name + role → response shows temp password in code block, once) | — |
| **Licence** | Read-only panel: tier, features, limits, server URL, last heartbeat from `license_state` | "Re-activate" action → navigates to `/setup/license` | — |
| **Settings** | Read-only panel: parallelism, gateway listen, gateway hostname, report_url, instance_id | — | — |

### Shared primitives

From `@triton/ui` (existing or added this PR):

- `TDataTable` — paged list with optional filter/sort. If not already in `@triton/ui`, factor out now (two apps now exercise the pattern).
- `TModal` — modal dialog scaffold.
- `TStatCard` — dashboard stat tile.
- `TStatusBadge` — colour-coded pill for scan-job + agent status.
- `TCodeBlock` — for temp passwords, bundle filenames, error excerpts; with copy-to-clipboard.
- `TConfirmDelete` — destructive-action confirmation.

### Toast / error system

Inherit from `@triton/ui` if a toast store exists; else add a small `stores/toasts.ts` scoped to manage-portal.

## 6. State management (Pinia)

One store per domain. Setup-style with Composition API. Stores own polling timers; views call `startPolling()` in `onMounted` and `stopPolling()` in `onUnmounted`.

```
stores/
  auth.ts              — re-export / wire @triton/auth's store
  setup.ts             — setup_required flag + wizard step
  dashboard.ts         — aggregate stats (merges multiple endpoint responses)
  zones.ts             — list + selected + mutations
  hosts.ts             — list + zone filter + selected + mutations (incl. bulk import)
  agents.ts            — list + selected + enrol + revoke
  scanjobs.ts          — list + status filter + selected detail + enqueue/cancel + polling
  pushstatus.ts        — current Status + polling
  users.ts             — list + create
  licence.ts           — current guard + last heartbeat
  settings.ts          — read-only runtime config
  toasts.ts            — push(msg, kind), dismiss(id)
```

Polling tick includes a `document.hidden` check so background tabs don't burn requests. 401 on any fetch triggers `auth.logout()` + `router.push('/login')` via a global interceptor in `@triton/api-client`.

Filter state persists to `localStorage` via a `watch` hook on each store's `filter` ref. Nothing else persists (JWT handled by `@triton/auth`).

Example shape (`scanjobs.ts`):

```typescript
export const useScanJobsStore = defineStore('scanjobs', () => {
  const items = ref<ScanJob[]>([])
  const filter = ref<{ status?: ScanJobStatus }>({})
  const selected = ref<ScanJob | null>(null)
  let pollHandle: number | null = null

  async function fetch() {
    items.value = await api.manageServer.listScanJobs(filter.value)
  }
  async function enqueue(req: EnqueueReq) {
    const jobs = await api.manageServer.enqueueScanJobs(req)
    await fetch()
    return jobs
  }
  async function requestCancel(id: string) {
    await api.manageServer.cancelScanJob(id)
    await fetch()
  }

  function startPolling() {
    if (pollHandle) return
    fetch()
    pollHandle = window.setInterval(() => {
      if (document.hidden) return
      fetch()
    }, 5000)
  }
  function stopPolling() {
    if (pollHandle) { clearInterval(pollHandle); pollHandle = null }
  }

  return { items, filter, selected, fetch, enqueue, requestCancel, startPolling, stopPolling }
})
```

## 7. API client layer

Add `manageServer.ts` to `@triton/api-client/src/` alongside existing `reportServer.ts` + `licenseServer.ts`. Exports a `ManageServerClient` class with typed methods for every Manage endpoint.

### Surface

```typescript
export class ManageServerClient {
  constructor(private http: HttpClient) {}

  // Setup + auth
  getSetupStatus(): Promise<SetupStatus>
  createAdmin(req: CreateAdminReq): Promise<CreateAdminResp>
  activateLicense(req: ActivateLicenseReq): Promise<ActivateLicenseResp>
  login(email: string, password: string): Promise<LoginResp>
  logout(): Promise<void>
  refresh(): Promise<LoginResp>
  me(): Promise<ManageUser>

  // Zones
  listZones(): Promise<Zone[]>
  createZone(req: { name: string; description?: string }): Promise<Zone>
  updateZone(id: string, req: { name: string; description?: string }): Promise<Zone>
  deleteZone(id: string): Promise<void>

  // Hosts
  listHosts(opts?: { zoneID?: string }): Promise<Host[]>
  createHost(req: CreateHostReq): Promise<Host>
  bulkCreateHosts(req: { hosts: CreateHostReq[] }): Promise<Host[]>
  updateHost(id: string, req: UpdateHostReq): Promise<Host>
  deleteHost(id: string): Promise<void>

  // Agents
  listAgents(): Promise<Agent[]>
  enrolAgent(req: { name: string; zone_id?: string }): Promise<Blob>
  revokeAgent(id: string): Promise<void>

  // Scan jobs
  listScanJobs(opts?: { status?: ScanJobStatus; limit?: number }): Promise<ScanJob[]>
  getScanJob(id: string): Promise<ScanJob>
  enqueueScanJobs(req: EnqueueReq): Promise<ScanJob[]>
  cancelScanJob(id: string): Promise<void>

  // Push status
  getPushStatus(): Promise<PushStatus>

  // Users
  listUsers(): Promise<ManageUser[]>
  createUser(req: CreateUserReq): Promise<CreateUserResp>  // returns temp_password
}
```

### Types file

`manageServer.types.ts` — DTOs mirror Go struct JSON exactly (snake_case field names preserved — no JS-side transformer, and preserving snake_case matches both the other portal clients and avoids a silent-rename foot-gun). A single top-of-file comment documents the rationale.

### Authentication

The shared `HttpClient` from `@triton/api-client/src/http.ts` already handles Bearer token injection and 401 interceptor. No changes needed; manage-portal reuses the same hook as report-portal.

### Bundle download

`enrolAgent(req)` returns a `Blob` of content-type `application/x-gzip`. UI calling pattern:

```typescript
const blob = await api.manageServer.enrolAgent({ name, zone_id })
const agentID = /* parsed from response header or known from state */
const url = URL.createObjectURL(blob)
const a = document.createElement('a')
a.href = url
a.download = `agent-${agentID}.tar.gz`
a.click()
URL.revokeObjectURL(url)
```

The modal wraps this in a try/finally so the modal closes + toast fires regardless. The single-download UX (Q7-a) requires a "downloading — do not close this tab" banner that shows until the download triggers.

### Tests

`manageServer.test.ts` in the package — uses the same mocking pattern as `reportServer.test.ts`. Asserts request shape (method, path, headers, body) for each method.

## 8. Embedding & cutover

### Backend additions

File: `pkg/manageserver/ui.go` — declares `//go:embed all:ui/dist` + `uiFS`.

File: `pkg/manageserver/server.go::buildRouter` — mounts `r.Handle("/*", spaHandler(uiSub))` after the `/api/v1/*` routes.

File: `pkg/manageserver/spa.go` (or reused from `pkg/server/ui_fs.go`) — the `spaHandler` helper with index.html fallback.

### Build pipeline

`Makefile`:

```make
web-build-manage:
	cd web && pnpm --filter manage-portal build
	rm -rf pkg/manageserver/ui/dist
	mkdir -p pkg/manageserver/ui
	cp -r web/apps/manage-portal/dist pkg/manageserver/ui/dist

build: web-build-manage
	go build ...

container-build-manageserver: web-build-manage
	podman build -f Containerfile.manageserver ...
```

### .gitignore

```
pkg/manageserver/ui/dist/
```

### Containerfile.manageserver

Gains a web-builder stage:

```dockerfile
FROM docker.io/library/node:22-alpine AS web
WORKDIR /src
RUN npm install -g pnpm
COPY web/ web/
RUN cd web && pnpm install --frozen-lockfile && pnpm --filter manage-portal build

FROM docker.io/library/golang:1.26 AS builder
ARG VERSION=dev
WORKDIR /src
ENV GOTOOLCHAIN=auto
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/apps/manage-portal/dist pkg/manageserver/ui/dist
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/amiryahaya/triton/internal/version.Version=${VERSION}" \
    -o /triton-manageserver cmd/manageserver/main.go

FROM scratch
ENV HOME=/tmp
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /triton-manageserver /triton-manageserver
EXPOSE 8082 8443
ENV TRITON_MANAGE_GATEWAY_LISTEN=:8443
ENTRYPOINT ["/triton-manageserver"]
```

### CI

The `Web build + test` job already runs `pnpm install` + workspace-wide build/test for the monorepo. Adding manage-portal to `pnpm-workspace.yaml` means it's picked up automatically. Unit-test job runs `pnpm --filter manage-portal test`.

## 9. Testing

### Strategy

Component tests (Vitest + `@vue/test-utils` + `jsdom`) — one spec per view and per shared primitive. No Playwright / browser E2E. The existing Go-side `test/integration/manage_e2e_scan_flow_test.go` remains the end-to-end integration gate.

### Mocking

- `@triton/api-client` is mocked at the module level with `vi.mock('@triton/api-client')` so tests never touch the network.
- Pinia stores use `createTestingPinia({ createSpy: vi.fn })` — tests stub any action.
- Vue Router tests use `createMemoryHistory`.

### Per-view coverage matrix

| View | Assertions |
|---|---|
| **Dashboard** | renders 5 stat cards from store; `startPolling` fires on mount; `stopPolling` fires on unmount |
| **Zones** | list rows render; "New Zone" opens modal; submit calls `zones.create` + closes modal; 409 surfaces toast "name already exists" |
| **Hosts** | list filtering calls store with filter; bulk-import parses JSON and calls `bulkCreateHosts`; 400 on bad IP shows inline error per row |
| **Agents** | enrol submit triggers Blob download via spied `URL.createObjectURL`; one-shot warning banner present; revoke double-confirms before action |
| **Scan Jobs** | 5s interval calls `scanjobs.fetch`; drawer opens on row click and fetches detail; Cancel button on queued row fires `requestCancel` |
| **Push Status** | renders queue depth + oldest-age + consecutive-failures; last-error excerpt truncated to 200 chars |
| **Users** | create 201 → temp password shown in `TCodeBlock` with working clipboard copy; 403 seat cap surfaces toast "seat limit reached" |
| **Licence** | renders tier + limits + last heartbeat; "Re-activate" navigates to `/setup/license` |
| **Settings** | renders all read-only fields from store |

### Routing-guard tests

`tests/guards.spec.ts` covers the `beforeEach` matrix:
- no JWT → `/login`
- setup-required → `/setup`
- 401 on fetch → logout + `/login`
- authenticated + operational → passes through

### Primitives

`TStatCard`, `TStatusBadge`, `TConfirmDelete` tested in isolation. `TDataTable` tested with sample rows + sort + filter hooks.

### What's explicitly excluded

- Playwright / browser E2E.
- Visual regression tests.
- Snapshot tests (too brittle on UI iteration).
- Real-backend integration tests from UI side.

### Coverage target

80% line coverage on `web/apps/manage-portal/src/`. CI fails below. Matches report-portal's target.

## 10. Acceptance criteria

- [ ] `web/apps/manage-portal/` builds cleanly via `pnpm --filter manage-portal build`.
- [ ] `make container-build-manageserver` produces an image with the embedded Vue portal accessible at `http://localhost:8082/`.
- [ ] All 8 post-login views are reachable from the grouped sidebar (Inventory/Operations/Admin) and render data from a live Manage Server.
- [ ] Scan Jobs list polls every 5s; Push Status same; Dashboard same.
- [ ] Agent enrol modal downloads the bundle on submit; one-shot warning banner visible.
- [ ] Bulk host import accepts JSON array, rejects malformed rows at the handler boundary (400 surfaces).
- [ ] User create returns temp password in a `TCodeBlock` shown once.
- [ ] `pkg/server/ui/dist/manage/` is deleted; the Report Server route for `/ui/manage/*` is removed.
- [ ] Vitest + `vue-tsc` CI stages green; ≥80% line coverage on `web/apps/manage-portal/src/`.
- [ ] `go test ./pkg/manageserver/...` green after the embed wiring.

## 11. Known deferrals / follow-ups

These are explicitly **not** in PR C and are tracked in `memory/manage-server-rollout.md`:

- **Real-agent smoke test.** Point a real `triton-agent` binary at a live Manage `:8443`; verify phone-home, revocation propagation, cert rotation. Manual QA before GA.
- **SSH-agentless credentials UI.** Requires Manage-native `credentials` + `discovery` backend packages first (separate PR). Today the orchestrator only works for localhost-style scans.
- **Playwright E2E for the portal.** Deferred until the portal has stabilised.
- **90-day gateway server-leaf renewal telemetry** + HTTPS enforcement on `license_server_url` during setup. Backend follow-ups, not UI.

## 12. Risks / collision surface

- `TAuthGate` parameterisation (small additive change to `@triton/auth`) affects both report-portal and manage-portal. Changes are backward-compatible if existing usage stays as the default; test report-portal's wiring continues to pass post-PR.
- `TDataTable` extraction into `@triton/ui` (if we do it) changes the shared package — report-portal would need to migrate. Do it inline with this PR to avoid a temporary divergence.
- Deleting `pkg/server/ui/dist/manage/` orphans any unknown downstream integration that was pointing at that path. Grep the entire tree for references before merge.

## 13. Open questions (none blocking)

None from the brainstorm. All 8 decision points are locked. If anything comes up during implementation that requires a design-level change, pause and revise this doc rather than improvising.
