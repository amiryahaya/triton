# Portal Unification — Design Spec

- **Date:** 2026-04-18
- **Status:** Draft — awaiting user review
- **Scope:** Redesign the three Triton web portals to share a single design system, component library, and shell. Build in Vue 3.
- **Out of scope:** Backend APIs (Report, License, Manage) — this spec targets UI only. Changes to auth protocols (JWT, admin-key) are out of scope. NACSA/CBOM report content & schema.

---

## 1. Problem

Triton ships three web portals that have diverged visually and behaviourally:

- **License Server UI** (`pkg/licenseserver/ui/dist/`, served at `:8081`) — vanilla JS SPA, admin-key auth, 7 pages.
- **Report Server UI** (`pkg/server/ui/dist/`, served at `:8080`) — vanilla JS + Chart.js SPA, JWT auth, ~12 pages, 3 nav sections.
- **Manage Server UI** (currently nested at `pkg/server/ui/dist/manage/`) — separate SPA scaffold for host onboarding / scan orchestration, ~9 pages.

Each portal has been hand-built: different component vocabularies, different spacing, different empty/error/loading states, different tables, different forms. Users experience them as three unrelated tools even though they share fonts and a base navy palette.

**Goals** (what "seamless UX" means here):

1. One design system — two themes (slate dark default + light), one token set.
2. One component library, shared by all three portals.
3. One shell grammar — sidebar, topbar, context chip, ⌘K search, app-switcher, avatar — identical across portals.
4. Subtle per-portal differentiation via a single accent stripe + logo subtitle, not loud theming.
5. Modern Vue 3 stack, typed, with a single build pipeline each portal consumes.

**Non-goals:**

- Changing the backend APIs or auth models.
- Merging the portals into a single SPA. They stay three separate deployables.
- Rewriting content (NACSA Arahan 9 reports, CBOM fields, government formats).

---

## 2. Product architecture context

Established during brainstorming (memory: `triton-product-architecture.md`). The UX design rules follow from this:

| Component | Role | Who uses it | Hosting | Licensing |
|-----------|------|-------------|---------|-----------|
| **License Server** | Issues + revokes licences | Vendor staff (operator) | Vendor cloud | N/A |
| **Report Server** | Multi-tenant scan analytics, NACSA Arahan 9 | Security officer, analyst, tenant admin | Customer cloud or on-prem (Podman) | Tenant-count |
| **Manage Server** | Host onboarding, scan orchestration (optional) | Network engineer | Customer on-prem, single-tenant | None |
| **Agent** | Per-host scanner (no UI) | Runs headless | On every host | `agent.yaml` |

### Deployment rules that drive UX

1. **Manage Server is single-tenant, per-customer, on-prem.** UI has no tenant-switcher; it has **Zones** (Corp / DMZ / Prod / OT) as a first-class grouping.
2. **Report Server is multi-tenant.** UI has tenant scope context chip; super-admin view sees all tenants.
3. **License Server is vendor-only.** UI never shows customer scan data.
4. **Agents push results directly to Report Server** — Manage is a control plane, not a data plane.
5. **Air-gapped sites** get their own Manage Server instance and optionally their own Report Server.
6. **Three portals are separate deployables** on different hosts. "Seamless" = chrome + component consistency, not a single SPA.

---

## 3. UX principles

1. **One chrome, three apps.** Each portal stays a separate deployable; they share the shell, empty/loading/error patterns, and keyboard shortcuts.
2. **Muted portal colour-coding.** Single accent stripe per portal — purple = License, cyan = Report, lime = Manage — applied only to the logo rail and active-nav item. Navy/slate base stays identical.
3. **Role-appropriate density.** Operator (License) → audit-first density. Security officer (Report) → exec-summary density. Network engineer (Manage) → bulk-action density. Same components, different defaults.
4. **Cross-portal wayfinding.** Topbar app-switcher (3×3 waffle) shows the three portals; disabled/undeployed portals are visible but greyed. Logo links back to the current portal's home only — never cross-navigates.
5. **Shared Vue component library.** Ship `@triton/ui` as a private workspace package. Both dashboards and data-grids come from it.

---

## 4. Tech stack

- **Framework:** Vue 3.4+ with `<script setup>` and Composition API.
- **Build tool:** Vite 5 per portal app.
- **Language:** TypeScript. Strict mode. Shared types in `@triton/ui` and `@triton/api-client`.
- **Styling:** CSS custom properties for tokens; `html[data-theme="dark|light"]` switches. Component CSS scoped with Vue SFC `<style scoped>` or `<style module>`. No runtime CSS-in-JS.
- **State:** Pinia per app. Auth, context (tenant/zone), theme stored in their own stores.
- **Router:** Vue Router 4 with hash routing (to preserve behaviour behind `//go:embed` + same-origin fetch without needing server rewrites).
- **HTTP:** `ofetch` or native `fetch` wrapped in a tiny client; mandatory `Authorization` header injection, 401 → auth prompt, 5xx → toast.
- **Charts:** Keep Chart.js 4 (already bundled in Report Server). Wrapped as Vue components (`<StatLineChart>`, `<MigrationBarChart>`, `<ClassificationDonut>`).
- **Icons:** Self-hosted SVG sprite (`@triton/ui/icons`). No icon-font or runtime CDN.
- **Fonts:** Self-hosted `.woff2` — Inter (400/500/600/700) + Geist (500/600/700) + JetBrains Mono (400/500).
- **No external CDNs at runtime.** Fonts, icons, charts all bundled or embedded.

### Monorepo layout

```
web/
├─ apps/
│  ├─ report-portal/          # Vue app → built into pkg/server/ui/dist/
│  ├─ license-portal/         # Vue app → built into pkg/licenseserver/ui/dist/
│  └─ manage-portal/          # Vue app → built into its own embed target
├─ packages/
│  ├─ ui/                     # @triton/ui — components, tokens, icons, fonts, chart wrappers
│  ├─ api-client/             # @triton/api-client — typed fetch wrappers per server
│  └─ auth/                   # @triton/auth — JWT + admin-key + license-server-token adapters
├─ pnpm-workspace.yaml
└─ package.json
```

- **Package manager:** pnpm workspaces.
- **One Vue app per portal** (not a single multi-entry app) — lets each embed ship independently and avoids cross-portal auth leakage.
- **Shared `@triton/ui`** imported by all three apps.

### Build + embed pipeline

Each app has `vite.config.ts` with:

```ts
build: {
  outDir: '../../dist/<portal-name>',
  emptyOutDir: true,
  rollupOptions: { input: 'index.html' }
}
```

The Go build copies/symlinks into the existing `pkg/.../ui/dist/` paths, preserving `//go:embed`. Options:

- **Option A (chosen):** `web/` build emits to `pkg/<portal>/ui/dist/` directly; a Makefile target `make web` runs `pnpm -C web build`.
- Option B (rejected): committed pre-built assets. Bigger diffs, worse review.

The current vanilla-JS builds are deleted once Vue parity is achieved.

---

## 5. Design system

### 5.1 Typography

- **Body / UI:** Inter (400/500/600/700)
- **Display + numerals:** Geist (500/600/700), with `font-variant-numeric: tabular-nums` for all numeric columns and stat values.
- **Mono:** JetBrains Mono (400/500) — for licence keys, fingerprints, IPs, codes.
- **Scale** (rem-based, 16px root):
  - `display` 2.2rem / letter-spacing -0.03em (Geist 600)
  - `h1` 1.55rem / -0.03em (Geist 600)
  - `h2` 1.15rem / -0.02em (Geist 600)
  - `h3` 0.95rem / -0.01em (Geist 600)
  - `body` 0.88rem (Inter 400)
  - `small` 0.76rem (Inter 400)
  - `label` 0.6rem / 0.14em uppercase / 500 (Inter)
- **Cormorant Garamond is removed** from all portals.

### 5.2 Theme tokens

Two themes, one token set. Both defined in `@triton/ui/tokens.css`. Switch via `<html data-theme="dark|light">`.

Single-source tokens per role, e.g.:

```css
:root {
  --radius-sm: 5px;
  --radius:    8px;
  --radius-lg: 12px;
  --sidebar-w: 256px;
  --topbar-h:  44px;
  /* semantic colour tokens declared for both themes below */
}

html[data-theme="dark"] {
  --bg-base:     #0f172a;
  --bg-surface:  #1e293b;
  --bg-elevated: #334155;
  --bg-hover:    #475569;

  --text-primary:   #f1f5f9;
  --text-secondary: #cbd5e1;
  --text-muted:     #94a3b8;
  --text-subtle:    #64748b;

  --border:         #334155;
  --border-strong:  #475569;

  --accent:         #0891b2;
  --accent-strong:  #22d3ee;
  --accent-muted:   rgba(34,211,238,0.12);

  --safe:         #34d399;
  --warn:         #fbbf24;
  --deprecated:   #fb923c;
  --unsafe:       #f87171;
}

html[data-theme="light"] {
  --bg-base:     #f8fafc;
  --bg-surface:  #ffffff;
  --bg-elevated: #f1f5f9;
  --bg-hover:    #e2e8f0;

  --text-primary:   #0f172a;
  --text-secondary: #475569;
  --text-muted:     #64748b;
  --text-subtle:    #94a3b8;

  --border:         #e2e8f0;
  --border-strong:  #cbd5e1;

  --accent:         #0e7490;
  --accent-strong:  #0891b2;
  --accent-muted:   rgba(14,116,144,0.08);

  --safe:         #059669;
  --warn:         #d97706;
  --deprecated:   #ea580c;
  --unsafe:       #dc2626;
}
```

**Portal accents** — portal identity is constant, hex values adapt per theme so contrast stays WCAG-AA:

- License → violet family · `#a78bfa` dark · `#7c3aed` light
- Report → cyan family (shares `--accent-strong`) · `#22d3ee` dark · `#0891b2` light
- Manage → lime family · `#a3e635` dark · `#65a30d` light

Each portal defines its own `--portal-accent` token that resolves to the right hex per active theme. Applied to: logo rail stripe (3px), active nav border-left, logo gradient, `:focus-visible` outlines.

**Never** on primary buttons — every portal's primary button uses the shared semantic `--accent` (cyan family), so the call-to-action reads consistently across all three. Portal accents signal location, not action.

### 5.3 Theme selection

- Default = **dark** (slate).
- On first paint, read `localStorage.tritonTheme`; fall back to `matchMedia('(prefers-color-scheme: light)')`.
- User toggle lives in the topbar — three states: `light`, `dark`, `system`. Persist to `localStorage` and (if authenticated) sync to user profile via `PATCH /api/v1/me/preferences`.
- **Exported NACSA PDFs always render in light theme** regardless of user preference — handled server-side where the HTML template applies `data-theme="light"`.

### 5.4 Motion

- Standard easing `cubic-bezier(0.4, 0, 0.2, 1)`.
- Default durations: hover 150ms · enter 250ms · modal/drawer 300ms.
- Reduced-motion media query disables all non-essential transitions.

---

## 6. Shell

All three portals mount the `<AppShell>` component from `@triton/ui`. Structure:

```
<AppShell portal="report|license|manage">
  <template #sidebar>  <Sidebar :items="nav" />  </template>
  <template #context>  <ContextChip />           </template>
  <router-view />
</AppShell>
```

### 6.1 Sidebar

- 256px fixed.
- Logo rail with 3px portal-accent stripe + logo tile (`T` in Geist 700), title "Triton", subtitle = portal name in caps.
- Nav sections with `SectionLabel` small-caps headers.
- Nav item = icon + label; active state uses portal accent + muted accent background + left border.
- Footer: user identity (name · role) + org/tenant string.
- Auth screens (login, change-password, admin-key prompt) hide the sidebar.

### 6.2 Topbar

- 44px, sticky.
- **Breadcrumb** — current page path. Plain text; parents are links within-portal only.
- **Context chip** — tenant (Report) / zone (Manage) / empty (License). Clickable to open a switcher popover (tenants / zones). License never shows one.
- **Global search** (⌘K) — opens command palette scoped to portal. Common shortcut across all three.
- **App-switcher** — 3×3 waffle icon. Popover shows three tiles with portal accents; greyed out if the portal isn't deployed (health-check URL fails). Cross-portal URLs configured per deployment via build-time env.
- **Theme toggle** — sun/moon/auto tri-state.
- **Avatar** — user initial in a gradient disc. Popover for profile · preferences · sign out.

### 6.3 Page layout

- 20px padding.
- Page header: H1 + meta row (inline metrics) on the left, primary CTAs on the right.
- Max content width 1440px at high res; stretches to fill on smaller.

---

## 7. Component library (`@triton/ui`)

Target: all three portals use these. Custom work is allowed only where a component doesn't yet exist.

### 7.1 Atomic

| Component | Notes |
|-----------|-------|
| `Button` | variants `primary · secondary · ghost · danger`; sizes `sm · md · lg`; icon slot. |
| `Pill` | variants `safe · warn · deprecated · unsafe · info · neutral · enterprise`; optional leading dot. |
| `Tabs` | underline style with optional count badge. |
| `Segment` | inline segmented control. |
| `Avatar` | initial + gradient. |
| `Kbd` | keyboard key indicator. |
| `Dot` | status dot with theme tokens. |
| `Checkbox` / `Toggle` / `Radio` | |
| `Input` / `Select` / `Textarea` | error + hint states, `<FormField>` wrapper. |
| `SearchInput` | ⌘K-bound; emits query. |

### 7.2 Composite

| Component | Notes |
|-----------|-------|
| `StatCard` | label + big value + delta + sparkline. Slot for icon; `--stat-accent` CSS var for left border. |
| `DataTable` | column config, row selection, bulk-action toolbar, sort, filter segment, pagination footer. Virtualised for > 500 rows. |
| `Panel` | framed container with header slot (title / sub / action link) + body. |
| `EmptyState` | icon + title + description + CTA row. |
| `LoadingSkeleton` | shimmer, sizing via props. |
| `Toast` | variants `success · warn · error · info`; imperative `toast.success('…')`. |
| `Modal` | header + body + foot; destructive variant tints danger. |
| `Drawer` | right-anchored side-sheet (detail views), locked width 420px. |
| `ConfirmDialog` | wrapper over Modal for yes/no destructive. |
| `ContextChip` | tenant / zone switcher. |
| `AppSwitcher` | topbar waffle popover. |
| `ThemeToggle` | light / dark / auto. |
| `CrumbBar` | breadcrumbs. |
| `ZoneBadges` (Manage only, exposed for reuse) | multi-filter pill set with counts. |
| `FileDrop` | drag-drop + click-to-browse; emits `FileList`. |
| `VerdictBanner` | Report compliance verdict — pass/warn/fail with icon, text, CTA. |

### 7.3 Chart wrappers (Chart.js 4)

- `<LineChart>` — trend lines (migration trend).
- `<BarChart>` — counts over time (scans/day).
- `<DonutChart>` — classification breakdown.
- `<Sparkline>` — inline in StatCard.

Each accepts a typed `series` prop with theme-aware colour derivation from CSS custom properties.

---

## 8. Per-portal IA

### 8.1 Report Server (Report)

- Overview
- Machines
- Scans
- **Compliance** (section)
  - NACSA Arahan 9
  - Priority
  - Inventory
  - Certificates
- **Trend & diff** (section)
  - Migration trend
  - Scan diff
- **Admin** (section, role-gated)
  - Users
  - Tenants (super-admin only)
  - Audit log

Context chip: tenant/environment (ACME · Production).
Hero screen = Overview with VerdictBanner + 4 StatCards + Migration trend panel + Classification donut + Top migration priorities list.

### 8.2 License Server (Licence)

- Dashboard
- Organisations
- Licences
- Activations
- **Admin** (section)
  - Audit log
  - Binaries
  - Superadmins

No context chip (vendor-only, no multi-tenancy).
Hero screen = Licence detail: licence key card + seats/hosts/days/scans stats + seat-activations table + recent audit feed.

### 8.3 Manage Server (Manage)

- Dashboard
- Zones
- Hosts
- Discovery
- **Scanning** (section)
  - Profiles
  - SSH keys
  - Agents
- **Operations** (section)
  - Jobs
  - Bulk upload

Context chip: current zone (Zone: Prod · OT). Single-tenant — no tenant switcher.
Hero screen = Hosts list: ZoneBadges filter row + DataTable with bulk-action toolbar (Assign profile · Deploy agent · Run scan · Decommission) + FileDrop card for CSV upload.

---

## 9. Auth integration

UI unification must **not** change the auth protocols. What changes is the auth UX:

- Report — JWT login page (`email` + `password`); change-password flow; role claim for nav gating. Uses `localStorage.tritonJWT`.
- License — admin-key prompt (modal); `sessionStorage.triton_admin_key`; 30-min inactivity timeout.
- Manage — shares Report's JWT scheme (customer identity); roles: `network_engineer`, `admin`. Detail: Manage lives inside the customer trust boundary, so it can validate JWTs signed by the Report Server's key, **or** it uses its own local JWT — decision deferred to backend spec.

Both JWT and admin-key auth layer into the same `<AuthGate>` component in `@triton/auth`, which renders either a login form, a key prompt, or a password-change form depending on auth type configuration at app build time.

401 from any endpoint → `AuthGate` takes over the viewport; stored credentials cleared.

---

## 10. Compatibility & migration

### 10.1 URL / routing

- Keep hash routing (`#/path`) so deployed HTML behind `//go:embed` works with any `basePath` without server rewrites.
- All existing deep links (`#/scans/:id`, `#/licenses/:id`) are preserved.

### 10.2 Incremental rollout

Three portals migrate independently. Suggested order (lowest risk first):

1. **License Server UI** — smallest surface (~7 pages), operator audience, least external dependence. Prove the stack.
2. **Report Server UI** — larger (~14 pages with analytics), customer-facing. After tokens + components are proven.
3. **Manage Server UI** — currently scaffolded (vanilla JS) at `pkg/server/ui/dist/manage/`. Promote to its own Vue app and, if backend separation is ready, move its embed target to a new Manage Server binary.

Each portal migration is its own PR sequence per plan. Existing E2E Playwright tests (`test/e2e/`) are preserved and extended — the DOM structure changes, so selector updates are expected as part of each portal's cutover.

### 10.3 Chart.js & existing charts

Chart.js 4 stays. Wrappers preserve existing chart data shapes so API responses don't change.

### 10.4 Embedded assets

- Continue using `//go:embed all:ui/dist` (Report) and `//go:embed ui/dist` (License, Manage).
- Vite output directly into `pkg/<portal>/ui/dist/`. No committed `node_modules`, no lockfile diff required at Go-build time.
- Go build depends on a prior `make web` step in CI.

---

## 11. Testing

- **Unit (Vitest):** Every `@triton/ui` component has a render test + props test + accessibility role test.
- **Component interaction (Vitest + `@vue/test-utils`):** DataTable selection, Modal confirm, ThemeToggle, ContextChip switcher, AppSwitcher popover.
- **Visual regression (optional, defer):** Chromatic or Percy on the component catalogue.
- **E2E (Playwright, existing):** Extend to cover theme toggle, app-switcher presence, hero-screen contents. Update selectors per portal.
- **Accessibility:** axe-core run on every Playwright spec. WCAG AA target. Focus traps in Modal/Drawer. Esc closes popovers.

---

## 12. Open questions to resolve during implementation

1. **Manage Server binary separation** — currently its UI lives inside the Report Server's embed tree. Decide whether to promote Manage to its own `cmd/manageserver/main.go` or keep it co-located but shielded under `/manage` URL. Affects build pipeline but not UX.
2. **App-switcher cross-portal URLs** — how does each portal know the URLs of its siblings? Candidate: build-time env vars `TRITON_LICENSE_URL`, `TRITON_REPORT_URL`, `TRITON_MANAGE_URL` baked in at Vite build. User can override via config.
3. **Tenant switcher for super-admin in Report** — deferred to the existing multi-tenant work (memory: `feat/multi-tenant`).
4. **Zones data model** — Manage Server backend must expose `GET /api/v1/zones`, `POST /api/v1/zones`, `PATCH /api/v1/hosts/:id { zone_id }`. Scoped out of this spec but noted as a dependency.

---

## 13. Acceptance criteria

A reviewer should be able to check, for each of the three portals:

- [ ] Portal renders with slate-dark default theme; toggle to light theme works without page reload.
- [ ] `<AppShell>` is used — no per-portal hand-rolled sidebar/topbar.
- [ ] Portal accent stripe appears on logo rail and active nav; no other chrome differs.
- [ ] ⌘K opens search; app-switcher waffle lists three portals; theme toggle persists.
- [ ] All tables use `<DataTable>`; all stat cards use `<StatCard>`; all modals use `<Modal>` or `<ConfirmDialog>`.
- [ ] No Cormorant Garamond references remain; Inter + Geist are the only web-font requests.
- [ ] No external CDN requests at runtime (verified via DevTools network tab).
- [ ] All existing Playwright E2E specs pass with selector updates.
- [ ] Hero screens match the design mockups for each portal.
- [ ] Accessibility: axe-core reports zero critical issues per page.

---

## 14. Appendix — visual references

All design mockups generated during brainstorming are preserved in `.superpowers/brainstorm/7517-1776438674/content/`:

- `storyboard-architecture.html` — 4-component architecture + deployment scenarios + 5 UX principles
- `deployment-topologies.html` — where Manage lives, 4 topology cards, 6 deployment rules
- `unified-shell.html` — anatomy + three-up comparison
- `component-library.html` — full component catalogue
- `theme-options.html` — pitch-dark vs slate vs light tradeoffs
- `typography-options.html` — 4 type stacks compared
- `final-look-preview.html` — Inter/Geist in both themes
- `key-screens.html` — hero screen per portal

These should be copied into `docs/superpowers/specs/assets/2026-04-18-portal-unification/` before the spec is committed, so they survive the brainstorm-server cleanup.
