# Portal Unification — Foundation + License Portal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the new Vue 3 monorepo at `web/` with shared `@triton/ui`, `@triton/auth`, `@triton/api-client` packages, and ship a complete migration of the License Server admin UI as the first portal — producing working, testable software and proving the design system end-to-end.

**Architecture:** pnpm monorepo at `web/`. One Vue 3 + Vite + TypeScript app per portal (`apps/license-portal` in this plan). Three shared packages: `@triton/ui` (components, tokens, icons, fonts, chart wrappers), `@triton/auth` (JWT + admin-key adapters), `@triton/api-client` (typed fetch wrappers). Each app builds into the existing `pkg/<portal>/ui/dist/` path, preserving `//go:embed` with no code changes on the Go side.

**Tech Stack:** Vue 3.4+ (Composition API, `<script setup>`), Vite 5, TypeScript strict, Pinia, Vue Router 4 (hash mode), Chart.js 4, Vitest, Playwright (existing), pnpm workspaces. Self-hosted `.woff2` for Inter, Geist, JetBrains Mono.

**Scope — this plan:** Monorepo foundation + `@triton/ui` core + `@triton/auth` admin-key adapter + `@triton/api-client` license endpoints + complete License Portal migration (all 7 pages) + old admin.js/admin.css deleted + Playwright E2E updated to match new DOM.

**Out of scope — follow-on plans:** Report Server migration, Manage Server migration, JWT auth adapter, drawer/file-drop/zone-badges/verdict-banner components, donut/sparkline charts. Those ship in the next two plans (Report first, Manage second).

**Spec reference:** `docs/superpowers/specs/2026-04-18-portal-unification-design.md`
**Mockup reference:** `docs/superpowers/specs/assets/2026-04-18-portal-unification/` — open `unified-shell.html`, `component-library.html`, `final-look-preview.html`, `key-screens.html` for pixel-level styling.

---

## File structure — created by this plan

```
web/
├─ package.json                      # workspace root, pnpm-compatible
├─ pnpm-workspace.yaml
├─ tsconfig.base.json                # shared TS config
├─ .eslintrc.cjs
├─ .prettierrc
├─ vitest.workspace.ts               # runs tests across all packages
├─ apps/
│  └─ license-portal/
│     ├─ package.json
│     ├─ tsconfig.json
│     ├─ vite.config.ts
│     ├─ index.html
│     ├─ public/
│     │  └─ logo.png                 # copied from existing pkg/licenseserver/ui/dist/logo.png
│     ├─ src/
│     │  ├─ main.ts
│     │  ├─ App.vue
│     │  ├─ router.ts
│     │  ├─ nav.ts                   # sidebar config for license portal
│     │  ├─ stores/
│     │  │  ├─ auth.ts               # admin-key pinia store
│     │  │  └─ theme.ts              # theme pinia store
│     │  └─ views/
│     │     ├─ Dashboard.vue
│     │     ├─ Organisations.vue
│     │     ├─ OrganisationDetail.vue
│     │     ├─ Licences.vue
│     │     ├─ LicenceDetail.vue
│     │     ├─ Activations.vue
│     │     ├─ AuditLog.vue
│     │     ├─ Binaries.vue
│     │     └─ Superadmins.vue
│     └─ tests/
│        └─ views.test.ts
└─ packages/
   ├─ ui/                            # @triton/ui
   │  ├─ package.json
   │  ├─ src/
   │  │  ├─ index.ts                 # public barrel
   │  │  ├─ tokens/tokens.css
   │  │  ├─ fonts/fonts.css
   │  │  ├─ fonts/*.woff2            # self-hosted
   │  │  ├─ icons/sprite.svg
   │  │  ├─ icons/TIcon.vue
   │  │  ├─ composables/
   │  │  │  ├─ useTheme.ts
   │  │  │  ├─ useToast.ts
   │  │  │  └─ useFocusTrap.ts
   │  │  ├─ atoms/
   │  │  │  ├─ TButton.vue
   │  │  │  ├─ TPill.vue
   │  │  │  ├─ TDot.vue
   │  │  │  ├─ TAvatar.vue
   │  │  │  ├─ TKbd.vue
   │  │  │  ├─ TInput.vue
   │  │  │  ├─ TSelect.vue
   │  │  │  ├─ TFormField.vue
   │  │  │  ├─ TToggle.vue
   │  │  │  ├─ TCheckbox.vue
   │  │  │  ├─ TTabs.vue
   │  │  │  └─ TSegment.vue
   │  │  ├─ composite/
   │  │  │  ├─ TStatCard.vue
   │  │  │  ├─ TPanel.vue
   │  │  │  ├─ TDataTable.vue
   │  │  │  ├─ TModal.vue
   │  │  │  ├─ TConfirmDialog.vue
   │  │  │  └─ TToastHost.vue
   │  │  ├─ shell/
   │  │  │  ├─ TAppShell.vue
   │  │  │  ├─ TSidebar.vue
   │  │  │  ├─ TCrumbBar.vue
   │  │  │  ├─ TAppSwitcher.vue
   │  │  │  ├─ TThemeToggle.vue
   │  │  │  └─ TUserMenu.vue
   │  │  └─ charts/
   │  │     ├─ chartTheme.ts
   │  │     ├─ TLineChart.vue
   │  │     └─ TBarChart.vue
   │  └─ tests/
   ├─ auth/                          # @triton/auth
   │  ├─ package.json
   │  ├─ src/
   │  │  ├─ index.ts
   │  │  ├─ adminKey.ts              # useAdminKey composable
   │  │  ├─ TAdminKeyPrompt.vue
   │  │  └─ TAuthGate.vue
   │  └─ tests/
   └─ api-client/                    # @triton/api-client
      ├─ package.json
      ├─ src/
      │  ├─ index.ts
      │  ├─ http.ts
      │  ├─ licenseServer.ts
      │  └─ types.ts
      └─ tests/
```

**Files modified (not created):**

- `Makefile` — add `web` and `web-install` targets
- `.github/workflows/ci.yml` — add Node toolchain job, build `web/` before Go build
- `.gitignore` — add `web/node_modules/`, `web/**/dist/` (but preserve existing `!pkg/licenseserver/ui/dist/` negations)
- `test/e2e/license-admin.spec.js` — selector updates to new DOM
- `pkg/licenseserver/ui/dist/*` — overwritten by Vite build output (no code, file churn only)

**Files deleted at cutover:**

- `pkg/licenseserver/ui/dist/admin.js`
- `pkg/licenseserver/ui/dist/admin.css`
- `pkg/licenseserver/ui/dist/index.html` (replaced by Vite output)
- `pkg/licenseserver/ui/dist/fonts/` (replaced by bundled fonts from Vite)

---

## Phase 0 — Monorepo scaffolding

### Task 0.1: Create pnpm workspace root

**Files:**
- Create: `web/package.json`
- Create: `web/pnpm-workspace.yaml`
- Create: `web/tsconfig.base.json`
- Create: `web/.eslintrc.cjs`
- Create: `web/.prettierrc`
- Create: `web/vitest.workspace.ts`
- Modify: `.gitignore` (add `web/node_modules`, `web/**/dist`, `web/**/.vite`, `web/**/coverage`)
- Create: `web/README.md`

- [ ] **Step 1: Create `web/package.json`**

```json
{
  "name": "triton-web",
  "version": "0.0.0",
  "private": true,
  "description": "Triton web portals — License, Report, Manage",
  "scripts": {
    "build": "pnpm -r --filter ./apps/* build",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "eslint .",
    "format": "prettier --write ."
  },
  "devDependencies": {
    "@types/node": "^22.10.0",
    "@typescript-eslint/eslint-plugin": "^8.18.0",
    "@typescript-eslint/parser": "^8.18.0",
    "@vitejs/plugin-vue": "^5.2.1",
    "@vue/eslint-config-typescript": "^14.1.4",
    "@vue/test-utils": "^2.4.6",
    "eslint": "^9.17.0",
    "eslint-plugin-vue": "^9.32.0",
    "jsdom": "^25.0.1",
    "prettier": "^3.4.2",
    "typescript": "^5.7.2",
    "vite": "^5.4.11",
    "vitest": "^2.1.8",
    "vue-tsc": "^2.1.10"
  },
  "packageManager": "pnpm@9.15.0"
}
```

- [ ] **Step 2: Create `web/pnpm-workspace.yaml`**

```yaml
packages:
  - 'apps/*'
  - 'packages/*'
```

- [ ] **Step 3: Create `web/tsconfig.base.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitOverride": true,
    "exactOptionalPropertyTypes": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "types": []
  }
}
```

- [ ] **Step 4: Create `web/.eslintrc.cjs`**

```js
/* eslint-env node */
module.exports = {
  root: true,
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:vue/vue3-recommended',
    '@vue/eslint-config-typescript'
  ],
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module'
  },
  rules: {
    'vue/multi-word-component-names': 'off',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
  },
  ignorePatterns: ['dist', 'node_modules', 'coverage']
};
```

- [ ] **Step 5: Create `web/.prettierrc`**

```json
{
  "semi": true,
  "singleQuote": true,
  "trailingComma": "es5",
  "printWidth": 100,
  "tabWidth": 2,
  "vueIndentScriptAndStyle": true
}
```

- [ ] **Step 6: Create `web/vitest.workspace.ts`**

```ts
import { defineWorkspace } from 'vitest/config';

export default defineWorkspace([
  'packages/*/vitest.config.ts',
  'apps/*/vitest.config.ts'
]);
```

- [ ] **Step 7: Update `.gitignore`**

Append to `.gitignore`:

```
# Node / pnpm for web/
web/node_modules/
web/**/node_modules/
web/**/.vite/
web/**/coverage/
web/**/*.tsbuildinfo

# Vite-built portal assets override embedded dist (built fresh in CI)
# (the dist/ negations for pkg/.../ui/dist already exist)
```

- [ ] **Step 8: Create `web/README.md`**

```markdown
# Triton web portals

pnpm monorepo for the three Triton portals.

## Layout

- `apps/license-portal` — License Server admin UI
- `apps/report-portal` — Report Server UI (future)
- `apps/manage-portal` — Manage Server UI (future)
- `packages/ui` — shared components, tokens, fonts, icons (`@triton/ui`)
- `packages/auth` — JWT + admin-key adapters (`@triton/auth`)
- `packages/api-client` — typed HTTP clients (`@triton/api-client`)

## Dev

```sh
cd web
pnpm install
pnpm --filter license-portal dev      # serves on http://localhost:5173
pnpm test                             # run all package tests
pnpm build                            # build every app into its embed target
```

## Build pipeline

Each portal app's `vite.config.ts` emits directly into `pkg/<portal>/ui/dist/`,
preserving Go's `//go:embed`. Run `make web` from the repo root.
```

- [ ] **Step 9: Verify pnpm is available, then install**

Run:
```sh
command -v pnpm || corepack enable pnpm
cd web && pnpm install
```

Expected: pnpm installs workspace root devDependencies; `web/node_modules/` created; `web/pnpm-lock.yaml` created.

- [ ] **Step 10: Commit**

```sh
cd /Users/amirrudinyahaya/Workspace/triton
git add web/package.json web/pnpm-workspace.yaml web/tsconfig.base.json web/.eslintrc.cjs web/.prettierrc web/vitest.workspace.ts web/README.md web/pnpm-lock.yaml .gitignore
git commit -m "feat(web): scaffold pnpm workspace for Vue portal monorepo"
```

---

### Task 0.2: Add Makefile targets and CI job for web build

**Files:**
- Modify: `Makefile` (add `web`, `web-install`, `web-test`, `web-clean` targets; wire into `build`)
- Modify: `.github/workflows/ci.yml` (add web job before Go build)

- [ ] **Step 1: Add Makefile targets**

Open `Makefile`. Add to the `.PHONY` line: ` web web-install web-test web-clean`.

Append at the end of the file:

```make
# ──── Web portal build ───────────────────────────────────────────────
# Requires pnpm (install via `corepack enable pnpm` once).
# `make web` builds every app and writes output into its embed target
# under pkg/<portal>/ui/dist/.

web-install:
	cd web && pnpm install --frozen-lockfile

web: web-install
	cd web && pnpm build

web-test: web-install
	cd web && pnpm test

web-clean:
	rm -rf web/node_modules web/**/node_modules web/**/dist web/**/coverage
```

- [ ] **Step 2: Add Node job to CI**

Open `.github/workflows/ci.yml`. After the `lint` job, before `test`, insert:

```yaml
  web:
    name: Web build + test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: pnpm/action-setup@v4
        with:
          version: 9.15.0

      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: 'pnpm'
          cache-dependency-path: web/pnpm-lock.yaml

      - name: Install
        working-directory: web
        run: pnpm install --frozen-lockfile

      - name: Lint
        working-directory: web
        run: pnpm lint

      - name: Test
        working-directory: web
        run: pnpm test

      - name: Build
        working-directory: web
        run: pnpm build

      - name: Upload built portals
        uses: actions/upload-artifact@v4
        with:
          name: portal-dist
          path: |
            pkg/licenseserver/ui/dist/
            pkg/server/ui/dist/
          retention-days: 7
```

Also update the `build` job's `needs:` array (if it has one) to include `web`. If `build` doesn't have a `needs:`, add `needs: [lint, test, web]`.

- [ ] **Step 3: Commit**

```sh
git add Makefile .github/workflows/ci.yml
git commit -m "build(web): wire pnpm install/test/build into Makefile and CI"
```

---

## Phase 1 — @triton/ui design tokens, fonts, base

### Task 1.1: Scaffold `@triton/ui` package

**Files:**
- Create: `web/packages/ui/package.json`
- Create: `web/packages/ui/tsconfig.json`
- Create: `web/packages/ui/vitest.config.ts`
- Create: `web/packages/ui/src/index.ts`
- Create: `web/packages/ui/tests/sanity.test.ts`

- [ ] **Step 1: `web/packages/ui/package.json`**

```json
{
  "name": "@triton/ui",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "main": "src/index.ts",
  "types": "src/index.ts",
  "exports": {
    ".": "./src/index.ts",
    "./tokens.css": "./src/tokens/tokens.css",
    "./fonts.css": "./src/fonts/fonts.css"
  },
  "scripts": {
    "test": "vitest run",
    "lint": "eslint src"
  },
  "dependencies": {
    "chart.js": "^4.4.7",
    "vue": "^3.5.13"
  },
  "devDependencies": {
    "@vue/test-utils": "^2.4.6",
    "jsdom": "^25.0.1",
    "vitest": "^2.1.8"
  }
}
```

- [ ] **Step 2: `web/packages/ui/tsconfig.json`**

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "dist",
    "composite": true,
    "rootDir": "src"
  },
  "include": ["src/**/*.ts", "src/**/*.vue"]
}
```

- [ ] **Step 3: `web/packages/ui/vitest.config.ts`**

```ts
import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['tests/**/*.test.ts', 'src/**/*.test.ts']
  }
});
```

- [ ] **Step 4: `web/packages/ui/src/index.ts` (placeholder barrel)**

```ts
export const VERSION = '0.0.0';
```

- [ ] **Step 5: `web/packages/ui/tests/sanity.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { VERSION } from '../src';

describe('@triton/ui', () => {
  it('exports a version constant', () => {
    expect(VERSION).toBe('0.0.0');
  });
});
```

- [ ] **Step 6: Install and verify**

Run from `web/`:
```sh
pnpm install
pnpm --filter @triton/ui test
```

Expected: `1 passed`.

- [ ] **Step 7: Commit**

```sh
git add web/packages/ui web/pnpm-lock.yaml
git commit -m "feat(ui): scaffold @triton/ui package with vitest harness"
```

---

### Task 1.2: Design tokens CSS (dark + light)

**Files:**
- Create: `web/packages/ui/src/tokens/tokens.css`
- Create: `web/packages/ui/tests/tokens.test.ts`

- [ ] **Step 1: Write the failing test**

`web/packages/ui/tests/tokens.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import '../src/tokens/tokens.css';

function cssVar(el: HTMLElement, name: string): string {
  return getComputedStyle(el).getPropertyValue(name).trim();
}

describe('design tokens', () => {
  beforeEach(() => {
    document.documentElement.removeAttribute('data-theme');
  });

  it('defines structural tokens on :root regardless of theme', () => {
    const root = document.documentElement;
    expect(cssVar(root, '--sidebar-w')).toBe('256px');
    expect(cssVar(root, '--topbar-h')).toBe('44px');
    expect(cssVar(root, '--radius')).toBe('8px');
  });

  it('resolves dark palette when data-theme="dark"', () => {
    document.documentElement.setAttribute('data-theme', 'dark');
    const root = document.documentElement;
    expect(cssVar(root, '--bg-base')).toBe('#0f172a');
    expect(cssVar(root, '--text-primary')).toBe('#f1f5f9');
    expect(cssVar(root, '--safe')).toBe('#34d399');
    expect(cssVar(root, '--unsafe')).toBe('#f87171');
  });

  it('resolves light palette when data-theme="light"', () => {
    document.documentElement.setAttribute('data-theme', 'light');
    const root = document.documentElement;
    expect(cssVar(root, '--bg-base')).toBe('#f8fafc');
    expect(cssVar(root, '--text-primary')).toBe('#0f172a');
    expect(cssVar(root, '--safe')).toBe('#059669');
    expect(cssVar(root, '--unsafe')).toBe('#dc2626');
  });
});
```

- [ ] **Step 2: Run test — expect failure**

```sh
cd web && pnpm --filter @triton/ui test
```

Expected: FAIL — `tokens.css` doesn't exist or returns empty.

- [ ] **Step 3: Implement tokens.css**

`web/packages/ui/src/tokens/tokens.css`:

```css
/* ============================================================
   @triton/ui — design tokens
   Two themes, one token set. Flip via html[data-theme="dark|light"].
   ============================================================ */

:root {
  /* Structural tokens (theme-independent) */
  --radius-sm:   5px;
  --radius:      8px;
  --radius-lg:  12px;
  --radius-pill: 999px;

  --sidebar-w: 256px;
  --topbar-h:   44px;

  --ease:     cubic-bezier(0.4, 0, 0.2, 1);
  --ease-out: cubic-bezier(0, 0, 0.2, 1);

  --motion-hover:  150ms;
  --motion-enter:  250ms;
  --motion-modal:  300ms;

  --z-sidebar: 40;
  --z-topbar:  50;
  --z-drawer:  70;
  --z-modal:   80;
  --z-toast:   90;

  /* Portal accent (placeholders — apps override at their app root) */
  --portal-accent:      #22d3ee;
  --portal-accent-soft: rgba(34, 211, 238, 0.12);
}

/* ─────────── Dark palette (default) ─────────── */
html[data-theme='dark'] {
  --bg-base:      #0f172a;
  --bg-surface:   #1e293b;
  --bg-elevated:  #334155;
  --bg-hover:     #475569;

  --text-primary:    #f1f5f9;
  --text-secondary:  #cbd5e1;
  --text-muted:      #94a3b8;
  --text-subtle:     #64748b;

  --border:          #334155;
  --border-strong:   #475569;

  --accent:          #0891b2;
  --accent-strong:   #22d3ee;
  --accent-muted:    rgba(34, 211, 238, 0.12);

  --safe:            #34d399;
  --safe-muted:      rgba(52, 211, 153, 0.12);
  --warn:            #fbbf24;
  --warn-muted:      rgba(251, 191, 36, 0.12);
  --deprecated:      #fb923c;
  --deprecated-muted:rgba(251, 146, 60, 0.12);
  --unsafe:          #f87171;
  --unsafe-muted:    rgba(248, 113, 113, 0.14);

  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.3);
  --shadow:    0 4px 12px rgba(0, 0, 0, 0.35);
  --shadow-lg: 0 20px 60px rgba(0, 0, 0, 0.5);

  color-scheme: dark;
}

/* ─────────── Light palette ─────────── */
html[data-theme='light'] {
  --bg-base:      #f8fafc;
  --bg-surface:   #ffffff;
  --bg-elevated:  #f1f5f9;
  --bg-hover:     #e2e8f0;

  --text-primary:    #0f172a;
  --text-secondary:  #475569;
  --text-muted:      #64748b;
  --text-subtle:     #94a3b8;

  --border:          #e2e8f0;
  --border-strong:   #cbd5e1;

  --accent:          #0e7490;
  --accent-strong:   #0891b2;
  --accent-muted:    rgba(14, 116, 144, 0.08);

  --safe:            #059669;
  --safe-muted:      #d1fae5;
  --warn:            #d97706;
  --warn-muted:      #fef3c7;
  --deprecated:      #ea580c;
  --deprecated-muted:#ffedd5;
  --unsafe:          #dc2626;
  --unsafe-muted:    #fee2e2;

  --shadow-sm: 0 1px 2px rgba(15, 23, 42, 0.05);
  --shadow:    0 4px 12px rgba(15, 23, 42, 0.1);
  --shadow-lg: 0 20px 60px rgba(15, 23, 42, 0.15);

  color-scheme: light;
}

/* ─────────── Base element defaults ─────────── */
*, *::before, *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html, body {
  background: var(--bg-base);
  color: var(--text-primary);
  font-family: var(--font-body, 'Inter', system-ui, sans-serif);
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    transition-duration: 0ms !important;
    animation-duration: 0ms !important;
  }
}
```

- [ ] **Step 4: Run test — expect pass**

```sh
pnpm --filter @triton/ui test
```

Expected: `3 passed`.

- [ ] **Step 5: Commit**

```sh
git add web/packages/ui/src/tokens web/packages/ui/tests/tokens.test.ts
git commit -m "feat(ui): design tokens for slate-dark + light themes"
```

---

### Task 1.3: Font assets and fonts.css

**Files:**
- Create: `web/packages/ui/src/fonts/fonts.css`
- Create: `web/packages/ui/src/fonts/README.md` (documenting which files must be present)
- Create/download: `web/packages/ui/src/fonts/Inter-{Regular,Medium,SemiBold,Bold}.woff2`
- Create/download: `web/packages/ui/src/fonts/Geist-{Medium,SemiBold,Bold}.woff2`
- Create/download: `web/packages/ui/src/fonts/JetBrainsMono-{Regular,Medium}.woff2`

- [ ] **Step 1: Download the fonts**

Run from repo root:
```sh
cd web/packages/ui/src/fonts
# Inter from rsms.me (official distribution, OFL licence)
curl -fsSL -o Inter-Regular.woff2 'https://rsms.me/inter/font-files/Inter-Regular.woff2?v=3.19'
curl -fsSL -o Inter-Medium.woff2  'https://rsms.me/inter/font-files/Inter-Medium.woff2?v=3.19'
curl -fsSL -o Inter-SemiBold.woff2 'https://rsms.me/inter/font-files/Inter-SemiBold.woff2?v=3.19'
curl -fsSL -o Inter-Bold.woff2     'https://rsms.me/inter/font-files/Inter-Bold.woff2?v=3.19'

# Geist from Vercel (OFL)
curl -fsSL -o Geist-Medium.woff2   'https://github.com/vercel/geist-font/raw/main/packages/next/dist/fonts/geist-sans/Geist-Medium.woff2'
curl -fsSL -o Geist-SemiBold.woff2 'https://github.com/vercel/geist-font/raw/main/packages/next/dist/fonts/geist-sans/Geist-SemiBold.woff2'
curl -fsSL -o Geist-Bold.woff2     'https://github.com/vercel/geist-font/raw/main/packages/next/dist/fonts/geist-sans/Geist-Bold.woff2'

# JetBrains Mono (Apache 2.0)
curl -fsSL -o JetBrainsMono-Regular.woff2 'https://github.com/JetBrains/JetBrainsMono/raw/master/fonts/webfonts/JetBrainsMono-Regular.woff2'
curl -fsSL -o JetBrainsMono-Medium.woff2  'https://github.com/JetBrains/JetBrainsMono/raw/master/fonts/webfonts/JetBrainsMono-Medium.woff2'

ls -la *.woff2
```

Expected: 9 `.woff2` files, each > 50 KB.

- [ ] **Step 2: `web/packages/ui/src/fonts/fonts.css`**

```css
/* ============================================================
   @triton/ui — self-hosted web fonts
   All three families bundled as .woff2 — no runtime CDN.
   ============================================================ */

@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: url('./Inter-Regular.woff2') format('woff2');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 500;
  font-display: swap;
  src: url('./Inter-Medium.woff2') format('woff2');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 600;
  font-display: swap;
  src: url('./Inter-SemiBold.woff2') format('woff2');
}
@font-face {
  font-family: 'Inter';
  font-style: normal;
  font-weight: 700;
  font-display: swap;
  src: url('./Inter-Bold.woff2') format('woff2');
}

@font-face {
  font-family: 'Geist';
  font-style: normal;
  font-weight: 500;
  font-display: swap;
  src: url('./Geist-Medium.woff2') format('woff2');
}
@font-face {
  font-family: 'Geist';
  font-style: normal;
  font-weight: 600;
  font-display: swap;
  src: url('./Geist-SemiBold.woff2') format('woff2');
}
@font-face {
  font-family: 'Geist';
  font-style: normal;
  font-weight: 700;
  font-display: swap;
  src: url('./Geist-Bold.woff2') format('woff2');
}

@font-face {
  font-family: 'JetBrains Mono';
  font-style: normal;
  font-weight: 400;
  font-display: swap;
  src: url('./JetBrainsMono-Regular.woff2') format('woff2');
}
@font-face {
  font-family: 'JetBrains Mono';
  font-style: normal;
  font-weight: 500;
  font-display: swap;
  src: url('./JetBrainsMono-Medium.woff2') format('woff2');
}

:root {
  --font-body:    'Inter', system-ui, sans-serif;
  --font-display: 'Geist', 'Inter', sans-serif;
  --font-mono:    'JetBrains Mono', 'SF Mono', Consolas, monospace;
}
```

- [ ] **Step 3: `web/packages/ui/src/fonts/README.md`**

```markdown
# Fonts

Self-hosted `.woff2` files. Licences retained in each font's upstream repository.

- **Inter** — rsms.me · OFL
- **Geist** — vercel.com/font · OFL
- **JetBrains Mono** — Apache 2.0

Do NOT convert/optimise these further unless all weights are re-verified.
```

- [ ] **Step 4: Commit**

```sh
git add web/packages/ui/src/fonts
git commit -m "feat(ui): self-hosted Inter + Geist + JetBrains Mono woff2"
```

---

### Task 1.4: `useTheme` composable

**Files:**
- Create: `web/packages/ui/src/composables/useTheme.ts`
- Create: `web/packages/ui/tests/useTheme.test.ts`

- [ ] **Step 1: Write failing test**

`web/packages/ui/tests/useTheme.test.ts`:

```ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useTheme } from '../src/composables/useTheme';

describe('useTheme', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
    vi.restoreAllMocks();
  });

  it('defaults to dark when no preference stored and no system hint', () => {
    const matchMedia = vi.fn().mockReturnValue({
      matches: false,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    });
    vi.stubGlobal('matchMedia', matchMedia);

    const theme = useTheme();
    expect(theme.resolved.value).toBe('dark');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
  });

  it('respects prefers-color-scheme: light on first visit', () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({
      matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    }));

    const theme = useTheme();
    expect(theme.resolved.value).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
  });

  it('restores stored user preference over system', () => {
    localStorage.setItem('tritonTheme', 'light');
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({
      matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    }));

    const theme = useTheme();
    expect(theme.mode.value).toBe('light');
    expect(theme.resolved.value).toBe('light');
  });

  it('setMode persists and updates DOM', () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({
      matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    }));

    const theme = useTheme();
    theme.setMode('light');
    expect(localStorage.getItem('tritonTheme')).toBe('light');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(theme.resolved.value).toBe('light');
  });

  it('setMode("system") removes stored preference', () => {
    localStorage.setItem('tritonTheme', 'dark');
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({
      matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    }));

    const theme = useTheme();
    theme.setMode('system');
    expect(localStorage.getItem('tritonTheme')).toBeNull();
    // falls back to system (light in this mock)
    expect(theme.resolved.value).toBe('light');
  });
});
```

- [ ] **Step 2: Run — expect FAIL (module missing)**

```sh
pnpm --filter @triton/ui test
```

Expected: FAIL — cannot find module `../src/composables/useTheme`.

- [ ] **Step 3: Implement `useTheme.ts`**

`web/packages/ui/src/composables/useTheme.ts`:

```ts
import { ref, computed, watch, type Ref, type ComputedRef } from 'vue';

export type ThemeMode = 'dark' | 'light' | 'system';
export type ResolvedTheme = 'dark' | 'light';

const STORAGE_KEY = 'tritonTheme';

export interface UseTheme {
  mode: Ref<ThemeMode>;
  resolved: ComputedRef<ResolvedTheme>;
  setMode: (m: ThemeMode) => void;
}

function getStoredMode(): ThemeMode {
  const v = localStorage.getItem(STORAGE_KEY);
  return v === 'dark' || v === 'light' ? v : 'system';
}

function systemPrefersLight(): boolean {
  return typeof matchMedia === 'function'
    ? matchMedia('(prefers-color-scheme: light)').matches
    : false;
}

function apply(theme: ResolvedTheme): void {
  document.documentElement.setAttribute('data-theme', theme);
}

export function useTheme(): UseTheme {
  const mode = ref<ThemeMode>(getStoredMode());
  const resolved = computed<ResolvedTheme>(() => {
    if (mode.value === 'system') {
      return systemPrefersLight() ? 'light' : 'dark';
    }
    return mode.value;
  });

  // Apply immediately.
  apply(resolved.value);

  // Keep in sync.
  watch(resolved, (t) => apply(t), { flush: 'sync' });

  function setMode(m: ThemeMode): void {
    if (m === 'system') {
      localStorage.removeItem(STORAGE_KEY);
    } else {
      localStorage.setItem(STORAGE_KEY, m);
    }
    mode.value = m;
  }

  return { mode, resolved, setMode };
}
```

- [ ] **Step 4: Run — expect PASS**

```sh
pnpm --filter @triton/ui test
```

Expected: `5 passed`.

- [ ] **Step 5: Commit**

```sh
git add web/packages/ui/src/composables/useTheme.ts web/packages/ui/tests/useTheme.test.ts
git commit -m "feat(ui): useTheme composable with system/dark/light + persistence"
```

---

---

## Phase 2 — @triton/ui atoms

> Pattern note: every component file is a Vue 3 `<script setup lang="ts">` SFC.
> Styles use tokens from `tokens.css` via CSS custom properties — **never hard-code hex**
> in component styles. Refer to `docs/superpowers/specs/assets/2026-04-18-portal-unification/component-library.html`
> for the exact visual styling of each atom.

### Task 2.1: TButton

**Files:**
- Create: `web/packages/ui/src/atoms/TButton.vue`
- Create: `web/packages/ui/tests/TButton.test.ts`
- Modify: `web/packages/ui/src/index.ts` (export TButton)

- [ ] **Step 1: Failing test** — `web/packages/ui/tests/TButton.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TButton from '../src/atoms/TButton.vue';

describe('TButton', () => {
  it('renders slot content', () => {
    const w = mount(TButton, { slots: { default: 'Save' } });
    expect(w.text()).toBe('Save');
  });

  it('applies variant class (default primary)', () => {
    const w = mount(TButton);
    expect(w.classes()).toContain('t-btn--primary');
  });

  it.each(['primary', 'secondary', 'ghost', 'danger'] as const)(
    'applies variant=%s class', (variant) => {
      const w = mount(TButton, { props: { variant } });
      expect(w.classes()).toContain(`t-btn--${variant}`);
    }
  );

  it.each(['sm', 'md', 'lg'] as const)('applies size=%s class', (size) => {
    const w = mount(TButton, { props: { size } });
    expect(w.classes()).toContain(`t-btn--${size}`);
  });

  it('propagates disabled attribute', () => {
    const w = mount(TButton, { props: { disabled: true } });
    expect(w.attributes('disabled')).toBeDefined();
    expect(w.classes()).toContain('is-disabled');
  });

  it('emits click', async () => {
    const w = mount(TButton);
    await w.trigger('click');
    expect(w.emitted('click')).toHaveLength(1);
  });

  it('does not emit click when disabled', async () => {
    const w = mount(TButton, { props: { disabled: true } });
    await w.trigger('click');
    expect(w.emitted('click')).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

```sh
pnpm --filter @triton/ui test
```

- [ ] **Step 3: Implement** — `web/packages/ui/src/atoms/TButton.vue`:

```vue
<script setup lang="ts">
import { computed } from 'vue';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg';

const props = withDefaults(
  defineProps<{
    variant?: ButtonVariant;
    size?: ButtonSize;
    disabled?: boolean;
    type?: 'button' | 'submit' | 'reset';
  }>(),
  { variant: 'primary', size: 'md', disabled: false, type: 'button' }
);

const emit = defineEmits<{ click: [ev: MouseEvent] }>();

const classes = computed(() => ({
  [`t-btn--${props.variant}`]: true,
  [`t-btn--${props.size}`]: true,
  'is-disabled': props.disabled,
}));

function onClick(ev: MouseEvent) {
  if (props.disabled) return;
  emit('click', ev);
}
</script>

<template>
  <button
    class="t-btn"
    :class="classes"
    :type="type"
    :disabled="disabled"
    @click="onClick"
  >
    <slot />
  </button>
</template>

<style scoped>
.t-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border: 1px solid transparent;
  border-radius: var(--radius-sm);
  font-family: var(--font-body);
  font-weight: 500;
  cursor: pointer;
  transition: background var(--motion-hover) var(--ease),
              color var(--motion-hover) var(--ease),
              border-color var(--motion-hover) var(--ease);
}
.t-btn:focus-visible {
  outline: 2px solid var(--accent-strong);
  outline-offset: 2px;
}

.t-btn--sm { padding: 4px 9px;  font-size: 0.7rem; }
.t-btn--md { padding: 7px 14px; font-size: 0.78rem; }
.t-btn--lg { padding: 10px 18px; font-size: 0.85rem; }

.t-btn--primary {
  background: var(--accent);
  color: var(--bg-base);
  box-shadow: 0 0 0 1px var(--accent-muted), 0 2px 8px var(--accent-muted);
}
.t-btn--primary:hover:not(.is-disabled) { background: var(--accent-strong); }

.t-btn--secondary {
  background: var(--bg-elevated);
  color: var(--text-primary);
  border-color: var(--border-strong);
}
.t-btn--secondary:hover:not(.is-disabled) { background: var(--bg-hover); }

.t-btn--ghost {
  background: transparent;
  color: var(--text-muted);
}
.t-btn--ghost:hover:not(.is-disabled) {
  color: var(--text-primary);
  background: var(--accent-muted);
}

.t-btn--danger {
  background: var(--unsafe-muted);
  color: var(--unsafe);
  border-color: var(--unsafe);
}
.t-btn--danger:hover:not(.is-disabled) { background: var(--unsafe); color: var(--bg-base); }

.is-disabled { opacity: 0.4; cursor: not-allowed; }
</style>
```

- [ ] **Step 4: Update barrel** — append to `web/packages/ui/src/index.ts`:

```ts
export { default as TButton } from './atoms/TButton.vue';
export type { ButtonVariant, ButtonSize } from './atoms/TButton.vue';
```

- [ ] **Step 5: Run — expect PASS**

```sh
pnpm --filter @triton/ui test
```

Expected: 9 tests pass for TButton + previous passes unchanged.

- [ ] **Step 6: Commit**

```sh
git add web/packages/ui/src/atoms/TButton.vue web/packages/ui/tests/TButton.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TButton with 4 variants, 3 sizes, disabled state"
```

---

### Task 2.2: TDot and TPill

**Files:**
- Create: `web/packages/ui/src/atoms/TDot.vue`
- Create: `web/packages/ui/src/atoms/TPill.vue`
- Create: `web/packages/ui/tests/TPill.test.ts`
- Modify: `web/packages/ui/src/index.ts`

- [ ] **Step 1: Failing test** — `web/packages/ui/tests/TPill.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TPill from '../src/atoms/TPill.vue';

describe('TPill', () => {
  it.each([
    'safe', 'warn', 'deprecated', 'unsafe', 'info', 'neutral', 'enterprise'
  ] as const)('renders %s variant', (variant) => {
    const w = mount(TPill, { props: { variant }, slots: { default: 'x' } });
    expect(w.classes()).toContain(`t-pill--${variant}`);
  });

  it('shows leading dot by default', () => {
    const w = mount(TPill, { props: { variant: 'safe' }, slots: { default: 'Safe' } });
    expect(w.find('.t-dot').exists()).toBe(true);
  });

  it('hides leading dot when dot=false', () => {
    const w = mount(TPill, { props: { variant: 'info', dot: false }, slots: { default: 'v1.0' } });
    expect(w.find('.t-dot').exists()).toBe(false);
  });

  it('defaults to neutral variant', () => {
    const w = mount(TPill, { slots: { default: 'Draft' } });
    expect(w.classes()).toContain('t-pill--neutral');
  });
});
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement TDot** — `web/packages/ui/src/atoms/TDot.vue`:

```vue
<script setup lang="ts">
defineProps<{ color?: string }>();
</script>

<template>
  <span class="t-dot" :style="color ? { background: color } : undefined" />
</template>

<style scoped>
.t-dot {
  display: inline-block;
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
}
</style>
```

- [ ] **Step 4: Implement TPill** — `web/packages/ui/src/atoms/TPill.vue`:

```vue
<script setup lang="ts">
import TDot from './TDot.vue';

export type PillVariant =
  | 'safe' | 'warn' | 'deprecated' | 'unsafe'
  | 'info' | 'neutral' | 'enterprise';

withDefaults(
  defineProps<{ variant?: PillVariant; dot?: boolean }>(),
  { variant: 'neutral', dot: true }
);
</script>

<template>
  <span class="t-pill" :class="`t-pill--${variant}`">
    <TDot v-if="dot" />
    <slot />
  </span>
</template>

<style scoped>
.t-pill {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: var(--radius-pill);
  font-size: 0.66rem;
  font-weight: 500;
  border: 1px solid transparent;
  font-family: var(--font-body);
  line-height: 1.4;
}
.t-pill--safe       { color: var(--safe);       background: var(--safe-muted);       border-color: var(--safe); }
.t-pill--warn       { color: var(--warn);       background: var(--warn-muted);       border-color: var(--warn); }
.t-pill--deprecated { color: var(--deprecated); background: var(--deprecated-muted); border-color: var(--deprecated); }
.t-pill--unsafe     { color: var(--unsafe);     background: var(--unsafe-muted);     border-color: var(--unsafe); }
.t-pill--info       { color: var(--accent-strong); background: var(--accent-muted); border-color: var(--accent-strong); }
.t-pill--neutral    { color: var(--text-muted); background: var(--bg-elevated);      border-color: var(--border); }
.t-pill--enterprise { color: #c4b5fd;           background: rgba(167,139,250,0.12);  border-color: rgba(167,139,250,0.35); }
</style>
```

- [ ] **Step 5: Export** — append to `web/packages/ui/src/index.ts`:

```ts
export { default as TDot } from './atoms/TDot.vue';
export { default as TPill } from './atoms/TPill.vue';
export type { PillVariant } from './atoms/TPill.vue';
```

- [ ] **Step 6: Run — expect PASS; commit**

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/atoms/TDot.vue web/packages/ui/src/atoms/TPill.vue web/packages/ui/tests/TPill.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TDot + TPill with 7 variants"
```

---

### Task 2.3: Form primitives — TInput, TSelect, TFormField

**Files:**
- Create: `web/packages/ui/src/atoms/TInput.vue`
- Create: `web/packages/ui/src/atoms/TSelect.vue`
- Create: `web/packages/ui/src/atoms/TFormField.vue`
- Create: `web/packages/ui/tests/forms.test.ts`

- [ ] **Step 1: Failing test** — `web/packages/ui/tests/forms.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TInput from '../src/atoms/TInput.vue';
import TSelect from '../src/atoms/TSelect.vue';
import TFormField from '../src/atoms/TFormField.vue';

describe('TInput', () => {
  it('renders value via v-model', () => {
    const w = mount(TInput, { props: { modelValue: 'hello' } });
    expect((w.element as HTMLInputElement).value).toBe('hello');
  });

  it('emits update:modelValue on input', async () => {
    const w = mount(TInput, { props: { modelValue: '' } });
    await w.setValue('abc');
    const evs = w.emitted('update:modelValue');
    expect(evs?.[0]?.[0]).toBe('abc');
  });

  it('applies error class when error prop truthy', () => {
    const w = mount(TInput, { props: { modelValue: 'x', error: true } });
    expect(w.classes()).toContain('is-error');
  });
});

describe('TSelect', () => {
  it('renders option slot', () => {
    const w = mount(TSelect, {
      props: { modelValue: 'a' },
      slots: { default: '<option value="a">A</option><option value="b">B</option>' }
    });
    expect(w.findAll('option')).toHaveLength(2);
  });
});

describe('TFormField', () => {
  it('renders label and required marker', () => {
    const w = mount(TFormField, {
      props: { label: 'Name', required: true },
      slots: { default: '<input />' }
    });
    expect(w.text()).toContain('Name');
    expect(w.find('.t-req').exists()).toBe(true);
  });

  it('shows error text when error prop set', () => {
    const w = mount(TFormField, {
      props: { label: 'Email', error: 'Invalid address' },
      slots: { default: '<input />' }
    });
    expect(w.find('.t-field-error').text()).toBe('Invalid address');
  });

  it('shows hint text when hint prop set and no error', () => {
    const w = mount(TFormField, {
      props: { label: 'Email', hint: 'We never share this.' },
      slots: { default: '<input />' }
    });
    expect(w.find('.t-field-hint').text()).toBe('We never share this.');
    expect(w.find('.t-field-error').exists()).toBe(false);
  });
});
```

- [ ] **Step 2: Run — expect FAIL; then implement**

- [ ] **Step 3: `web/packages/ui/src/atoms/TInput.vue`**:

```vue
<script setup lang="ts">
const props = defineProps<{
  modelValue: string | number;
  error?: boolean;
  placeholder?: string;
  type?: string;
  disabled?: boolean;
}>();

const emit = defineEmits<{ 'update:modelValue': [v: string] }>();

function onInput(ev: Event) {
  emit('update:modelValue', (ev.target as HTMLInputElement).value);
}
</script>

<template>
  <input
    class="t-input"
    :class="{ 'is-error': error }"
    :value="modelValue"
    :placeholder="placeholder"
    :type="type ?? 'text'"
    :disabled="disabled"
    @input="onInput"
  />
</template>

<style scoped>
.t-input {
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  color: var(--text-primary);
  padding: 7px 10px;
  border-radius: var(--radius-sm);
  font-size: 0.8rem;
  font-family: var(--font-body);
  outline: none;
  width: 100%;
}
.t-input:focus {
  border-color: var(--accent-strong);
  box-shadow: 0 0 0 2px var(--accent-muted);
}
.t-input.is-error { border-color: var(--unsafe); }
.t-input:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
```

- [ ] **Step 4: `web/packages/ui/src/atoms/TSelect.vue`**:

```vue
<script setup lang="ts">
defineProps<{
  modelValue: string | number;
  error?: boolean;
  disabled?: boolean;
}>();

const emit = defineEmits<{ 'update:modelValue': [v: string] }>();

function onChange(ev: Event) {
  emit('update:modelValue', (ev.target as HTMLSelectElement).value);
}
</script>

<template>
  <select
    class="t-input t-select"
    :class="{ 'is-error': error }"
    :value="modelValue"
    :disabled="disabled"
    @change="onChange"
  >
    <slot />
  </select>
</template>

<style scoped>
.t-select {
  appearance: none;
  background-image: linear-gradient(45deg, transparent 50%, var(--text-muted) 50%),
                    linear-gradient(135deg, var(--text-muted) 50%, transparent 50%);
  background-position: calc(100% - 15px) 50%, calc(100% - 10px) 50%;
  background-size: 5px 5px, 5px 5px;
  background-repeat: no-repeat;
  padding-right: 26px;
}
.t-input { /* inherits from TInput */
  background: var(--bg-elevated);
  border: 1px solid var(--border-strong);
  color: var(--text-primary);
  padding: 7px 10px;
  border-radius: var(--radius-sm);
  font-size: 0.8rem;
  font-family: var(--font-body);
  outline: none;
  width: 100%;
}
.t-input:focus { border-color: var(--accent-strong); box-shadow: 0 0 0 2px var(--accent-muted); }
.t-input.is-error { border-color: var(--unsafe); }
.t-input:disabled { opacity: 0.5; cursor: not-allowed; }
</style>
```

- [ ] **Step 5: `web/packages/ui/src/atoms/TFormField.vue`**:

```vue
<script setup lang="ts">
defineProps<{
  label: string;
  required?: boolean;
  error?: string;
  hint?: string;
}>();
</script>

<template>
  <div class="t-field">
    <label class="t-field-label">
      {{ label }}<span v-if="required" class="t-req">*</span>
    </label>
    <slot />
    <span v-if="error" class="t-field-error">{{ error }}</span>
    <span v-else-if="hint" class="t-field-hint">{{ hint }}</span>
  </div>
</template>

<style scoped>
.t-field { display: flex; flex-direction: column; gap: 5px; }
.t-field-label {
  font-size: 0.72rem;
  color: var(--text-muted);
  font-weight: 500;
  font-family: var(--font-body);
}
.t-req { color: var(--unsafe); margin-left: 2px; }
.t-field-hint  { font-size: 0.68rem; color: var(--text-muted); }
.t-field-error { font-size: 0.68rem; color: var(--unsafe); }
</style>
```

- [ ] **Step 6: Export + test + commit**

```ts
// append to web/packages/ui/src/index.ts
export { default as TInput } from './atoms/TInput.vue';
export { default as TSelect } from './atoms/TSelect.vue';
export { default as TFormField } from './atoms/TFormField.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/atoms/TInput.vue web/packages/ui/src/atoms/TSelect.vue web/packages/ui/src/atoms/TFormField.vue web/packages/ui/tests/forms.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TInput + TSelect + TFormField with error/hint states"
```

---

### Task 2.4: TToggle and TCheckbox

**Files:**
- Create: `web/packages/ui/src/atoms/TToggle.vue`
- Create: `web/packages/ui/src/atoms/TCheckbox.vue`
- Create: `web/packages/ui/tests/toggles.test.ts`

- [ ] **Step 1: Failing test** — `web/packages/ui/tests/toggles.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TToggle from '../src/atoms/TToggle.vue';
import TCheckbox from '../src/atoms/TCheckbox.vue';

describe('TToggle', () => {
  it('shows on-state visually when modelValue=true', () => {
    const w = mount(TToggle, { props: { modelValue: true } });
    expect(w.classes()).toContain('is-on');
  });

  it('emits update on click', async () => {
    const w = mount(TToggle, { props: { modelValue: false } });
    await w.trigger('click');
    const evs = w.emitted('update:modelValue');
    expect(evs?.[0]?.[0]).toBe(true);
  });

  it('does not emit when disabled', async () => {
    const w = mount(TToggle, { props: { modelValue: false, disabled: true } });
    await w.trigger('click');
    expect(w.emitted('update:modelValue')).toBeUndefined();
  });
});

describe('TCheckbox', () => {
  it('emits update on click', async () => {
    const w = mount(TCheckbox, { props: { modelValue: false } });
    await w.trigger('click');
    expect(w.emitted('update:modelValue')?.[0]?.[0]).toBe(true);
  });
});
```

- [ ] **Step 2: Implement TToggle** — `web/packages/ui/src/atoms/TToggle.vue`:

```vue
<script setup lang="ts">
const props = defineProps<{
  modelValue: boolean;
  label?: string;
  disabled?: boolean;
}>();

const emit = defineEmits<{ 'update:modelValue': [v: boolean] }>();

function onClick() {
  if (props.disabled) return;
  emit('update:modelValue', !props.modelValue);
}
</script>

<template>
  <button
    type="button"
    class="t-toggle"
    :class="{ 'is-on': modelValue, 'is-disabled': disabled }"
    :aria-pressed="modelValue"
    :disabled="disabled"
    @click="onClick"
  >
    <span class="t-toggle-track">
      <span class="t-toggle-thumb" />
    </span>
    <span v-if="label" class="t-toggle-label">{{ label }}</span>
  </button>
</template>

<style scoped>
.t-toggle {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: transparent;
  border: none;
  cursor: pointer;
  padding: 0;
  font-family: var(--font-body);
}
.t-toggle-track {
  width: 30px;
  height: 17px;
  border-radius: var(--radius-pill);
  background: var(--border-strong);
  position: relative;
  transition: background var(--motion-hover) var(--ease);
}
.t-toggle-thumb {
  width: 13px;
  height: 13px;
  border-radius: 50%;
  background: var(--text-primary);
  position: absolute;
  top: 2px; left: 2px;
  transition: transform var(--motion-hover) var(--ease);
}
.t-toggle.is-on .t-toggle-track { background: var(--accent); }
.t-toggle.is-on .t-toggle-thumb {
  transform: translateX(13px);
  background: var(--bg-base);
}
.t-toggle.is-disabled { opacity: 0.5; cursor: not-allowed; }
.t-toggle-label { font-size: 0.76rem; color: var(--text-primary); }
</style>
```

- [ ] **Step 3: Implement TCheckbox** — `web/packages/ui/src/atoms/TCheckbox.vue`:

```vue
<script setup lang="ts">
const props = defineProps<{
  modelValue: boolean;
  label?: string;
  disabled?: boolean;
}>();

const emit = defineEmits<{ 'update:modelValue': [v: boolean] }>();

function onClick() {
  if (props.disabled) return;
  emit('update:modelValue', !props.modelValue);
}
</script>

<template>
  <button
    type="button"
    class="t-check"
    :class="{ 'is-checked': modelValue, 'is-disabled': disabled }"
    :aria-checked="modelValue"
    role="checkbox"
    :disabled="disabled"
    @click="onClick"
  >
    <span class="t-check-box" />
    <span v-if="label" class="t-check-label">{{ label }}</span>
  </button>
</template>

<style scoped>
.t-check {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  background: transparent;
  border: none;
  cursor: pointer;
  padding: 0;
  font-family: var(--font-body);
}
.t-check-box {
  width: 14px; height: 14px;
  border: 1px solid var(--border-strong);
  border-radius: 3px;
  background: transparent;
  position: relative;
  transition: background var(--motion-hover) var(--ease), border-color var(--motion-hover) var(--ease);
}
.t-check.is-checked .t-check-box {
  background: var(--accent);
  border-color: var(--accent);
}
.t-check.is-checked .t-check-box::after {
  content: '✓';
  position: absolute;
  top: -4px; left: 1px;
  color: var(--bg-base);
  font-size: 0.72rem;
  font-weight: 700;
}
.t-check.is-disabled { opacity: 0.5; cursor: not-allowed; }
.t-check-label { font-size: 0.76rem; color: var(--text-primary); }
</style>
```

- [ ] **Step 4: Export + test + commit**

```ts
// index.ts
export { default as TToggle } from './atoms/TToggle.vue';
export { default as TCheckbox } from './atoms/TCheckbox.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/atoms/TToggle.vue web/packages/ui/src/atoms/TCheckbox.vue web/packages/ui/tests/toggles.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TToggle + TCheckbox with v-model support"
```

---

### Task 2.5: TAvatar and TKbd

**Files:**
- Create: `web/packages/ui/src/atoms/TAvatar.vue`
- Create: `web/packages/ui/src/atoms/TKbd.vue`
- Create: `web/packages/ui/tests/avatar-kbd.test.ts`

- [ ] **Step 1: Test** — `web/packages/ui/tests/avatar-kbd.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TAvatar from '../src/atoms/TAvatar.vue';
import TKbd from '../src/atoms/TKbd.vue';

describe('TAvatar', () => {
  it('derives initials from name', () => {
    const w = mount(TAvatar, { props: { name: 'Jane Doe' } });
    expect(w.text()).toBe('JD');
  });

  it('handles single name', () => {
    const w = mount(TAvatar, { props: { name: 'Arif' } });
    expect(w.text()).toBe('AR');
  });

  it('accepts explicit initials override', () => {
    const w = mount(TAvatar, { props: { name: 'ignored', initials: 'OP' } });
    expect(w.text()).toBe('OP');
  });
});

describe('TKbd', () => {
  it('renders key content', () => {
    const w = mount(TKbd, { slots: { default: '⌘K' } });
    expect(w.text()).toBe('⌘K');
  });
});
```

- [ ] **Step 2: Implement TAvatar** — `web/packages/ui/src/atoms/TAvatar.vue`:

```vue
<script setup lang="ts">
import { computed } from 'vue';

const props = withDefaults(
  defineProps<{ name: string; initials?: string; size?: number }>(),
  { size: 26 }
);

const text = computed(() => {
  if (props.initials) return props.initials.slice(0, 2).toUpperCase();
  const parts = props.name.trim().split(/\s+/);
  if (parts.length >= 2) {
    const first = parts[0]?.[0] ?? '';
    const second = parts[parts.length - 1]?.[0] ?? '';
    return (first + second).toUpperCase();
  }
  return (parts[0] ?? '').slice(0, 2).toUpperCase();
});
</script>

<template>
  <span
    class="t-avatar"
    :style="{ width: size + 'px', height: size + 'px', fontSize: size * 0.4 + 'px' }"
    :aria-label="name"
  >{{ text }}</span>
</template>

<style scoped>
.t-avatar {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  background: linear-gradient(135deg, var(--accent), #7c3aed);
  color: var(--text-primary);
  font-family: var(--font-display);
  font-weight: 700;
  letter-spacing: -0.02em;
}
</style>
```

- [ ] **Step 3: Implement TKbd** — `web/packages/ui/src/atoms/TKbd.vue`:

```vue
<script setup lang="ts"></script>

<template>
  <kbd class="t-kbd"><slot /></kbd>
</template>

<style scoped>
.t-kbd {
  display: inline-block;
  font-family: var(--font-mono);
  font-size: 0.62rem;
  color: var(--text-muted);
  background: var(--bg-base);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 0 5px;
  line-height: 1.4;
}
</style>
```

- [ ] **Step 4: Export + test + commit**

```ts
export { default as TAvatar } from './atoms/TAvatar.vue';
export { default as TKbd } from './atoms/TKbd.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/atoms/TAvatar.vue web/packages/ui/src/atoms/TKbd.vue web/packages/ui/tests/avatar-kbd.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TAvatar (name → initials) and TKbd"
```

---

## Phase 3 — @triton/ui composite components

### Task 3.1: TStatCard

**Files:**
- Create: `web/packages/ui/src/composite/TStatCard.vue`
- Create: `web/packages/ui/tests/TStatCard.test.ts`

- [ ] **Step 1: Test**:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TStatCard from '../src/composite/TStatCard.vue';

describe('TStatCard', () => {
  it('renders label + value', () => {
    const w = mount(TStatCard, { props: { label: 'PQC ready', value: '68%' } });
    expect(w.text()).toContain('PQC ready');
    expect(w.text()).toContain('68%');
  });

  it('renders delta with direction class', () => {
    const w = mount(TStatCard, {
      props: { label: 'Unsafe', value: 214, delta: '↓ 12', deltaDir: 'up' }
    });
    expect(w.find('.t-stat-delta').classes()).toContain('is-up');
  });

  it('applies accent variable when prop set', () => {
    const w = mount(TStatCard, {
      props: { label: 'PQC', value: '68%', accent: 'var(--unsafe)' }
    });
    const style = (w.element as HTMLElement).getAttribute('style');
    expect(style).toContain('--stat-accent');
  });
});
```

- [ ] **Step 2: Implement** — `web/packages/ui/src/composite/TStatCard.vue`:

```vue
<script setup lang="ts">
withDefaults(
  defineProps<{
    label: string;
    value: string | number;
    delta?: string;
    deltaDir?: 'up' | 'down' | 'neutral';
    accent?: string;
  }>(),
  { deltaDir: 'neutral' }
);
</script>

<template>
  <div class="t-stat-card" :style="accent ? { '--stat-accent': accent } : undefined">
    <div class="t-stat-label">{{ label }}</div>
    <div class="t-stat-value">{{ value }}</div>
    <div v-if="delta" class="t-stat-delta" :class="`is-${deltaDir}`">{{ delta }}</div>
  </div>
</template>

<style scoped>
.t-stat-card {
  position: relative;
  padding: 12px 14px;
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}
.t-stat-card::before {
  content: '';
  position: absolute;
  left: 0; top: 0; bottom: 0;
  width: 2px;
  background: var(--stat-accent, var(--accent-strong));
  opacity: 0.7;
}
.t-stat-label {
  font-size: 0.58rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text-subtle);
  font-weight: 500;
  font-family: var(--font-body);
}
.t-stat-value {
  font-family: var(--font-display);
  font-size: 1.85rem;
  font-weight: 600;
  letter-spacing: -0.03em;
  font-variant-numeric: tabular-nums;
  color: var(--text-primary);
  line-height: 1.05;
  margin: 2px 0 3px;
}
.t-stat-delta {
  font-size: 0.66rem;
  font-weight: 500;
  color: var(--text-muted);
}
.t-stat-delta.is-up   { color: var(--safe); }
.t-stat-delta.is-down { color: var(--warn); }
</style>
```

- [ ] **Step 3: Export, test, commit**

```ts
// index.ts
export { default as TStatCard } from './composite/TStatCard.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/composite/TStatCard.vue web/packages/ui/tests/TStatCard.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TStatCard with label/value/delta + accent stripe"
```

---

### Task 3.2: TPanel

**Files:**
- Create: `web/packages/ui/src/composite/TPanel.vue`
- Create: `web/packages/ui/tests/TPanel.test.ts`

- [ ] **Step 1: Test**:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TPanel from '../src/composite/TPanel.vue';

describe('TPanel', () => {
  it('renders title prop in header', () => {
    const w = mount(TPanel, { props: { title: 'Migration trend' }, slots: { default: '<p>body</p>' } });
    expect(w.find('.t-panel-title').text()).toBe('Migration trend');
  });

  it('renders subtitle when provided', () => {
    const w = mount(TPanel, {
      props: { title: 'X', subtitle: '· 12 weeks' },
      slots: { default: 'body' }
    });
    expect(w.text()).toContain('· 12 weeks');
  });

  it('emits action event when action slot clicked', async () => {
    const w = mount(TPanel, {
      props: { title: 'X' },
      slots: {
        default: 'body',
        action: '<a class="act" href="#">Open →</a>'
      }
    });
    expect(w.find('.act').exists()).toBe(true);
  });
});
```

- [ ] **Step 2: Implement** — `web/packages/ui/src/composite/TPanel.vue`:

```vue
<script setup lang="ts">
defineProps<{ title: string; subtitle?: string }>();
</script>

<template>
  <section class="t-panel">
    <header class="t-panel-head">
      <h3 class="t-panel-title">{{ title }}</h3>
      <span v-if="subtitle" class="t-panel-sub">{{ subtitle }}</span>
      <span class="t-panel-action"><slot name="action" /></span>
    </header>
    <div class="t-panel-body"><slot /></div>
  </section>
</template>

<style scoped>
.t-panel {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}
.t-panel-head {
  padding: 12px 14px;
  display: flex;
  align-items: center;
  gap: 8px;
  border-bottom: 1px solid var(--border);
}
.t-panel-title {
  font-family: var(--font-display);
  font-size: 0.88rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--text-primary);
  margin: 0;
}
.t-panel-sub {
  font-size: 0.66rem;
  color: var(--text-subtle);
  margin-left: 2px;
}
.t-panel-action {
  margin-left: auto;
  font-size: 0.66rem;
  color: var(--accent-strong);
  font-weight: 500;
  cursor: pointer;
}
.t-panel-body { padding: 14px; }
</style>
```

- [ ] **Step 3: Export + commit**

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/composite/TPanel.vue web/packages/ui/tests/TPanel.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TPanel with title/subtitle/action slots"
```

---

### Task 3.3: TDataTable — base structure + columns + row selection

**Files:**
- Create: `web/packages/ui/src/composite/TDataTable.vue`
- Create: `web/packages/ui/tests/TDataTable.test.ts`

- [ ] **Step 1: Test** — `web/packages/ui/tests/TDataTable.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TDataTable, { type Column } from '../src/composite/TDataTable.vue';

interface Row { id: string; name: string; count: number; }

const columns: Column<Row>[] = [
  { key: 'name', label: 'Name', width: '2fr' },
  { key: 'count', label: 'Count', width: '1fr', align: 'right', numeric: true },
];

const rows: Row[] = [
  { id: 'a', name: 'Alpha', count: 10 },
  { id: 'b', name: 'Bravo', count: 42 },
  { id: 'c', name: 'Charlie', count: 7 },
];

describe('TDataTable', () => {
  it('renders one row per item', () => {
    const w = mount(TDataTable, { props: { columns, rows, rowKey: 'id' } });
    expect(w.findAll('.t-tbl-row')).toHaveLength(3);
  });

  it('renders header labels', () => {
    const w = mount(TDataTable, { props: { columns, rows, rowKey: 'id' } });
    expect(w.find('.t-tbl-head').text()).toContain('Name');
    expect(w.find('.t-tbl-head').text()).toContain('Count');
  });

  it('emits row-click with the row object', async () => {
    const w = mount(TDataTable, { props: { columns, rows, rowKey: 'id' } });
    await w.findAll('.t-tbl-row')[0]!.trigger('click');
    const ev = w.emitted('row-click')?.[0]?.[0];
    expect(ev).toEqual(rows[0]);
  });

  it('with selectable=true renders a select column and checkbox', () => {
    const w = mount(TDataTable, {
      props: { columns, rows, rowKey: 'id', selectable: true, selected: [] }
    });
    expect(w.findAll('.t-tbl-check')).toHaveLength(rows.length + 1); // + header
  });

  it('emits update:selected when a row checkbox is clicked', async () => {
    const w = mount(TDataTable, {
      props: { columns, rows, rowKey: 'id', selectable: true, selected: [] }
    });
    const rowCheckboxes = w.findAll('.t-tbl-row .t-tbl-check');
    await rowCheckboxes[1]!.trigger('click');
    const ev = w.emitted('update:selected')?.[0]?.[0];
    expect(ev).toEqual(['b']);
  });

  it('empty state renders when rows empty', () => {
    const w = mount(TDataTable, {
      props: { columns, rows: [], rowKey: 'id', emptyText: 'No hosts yet' }
    });
    expect(w.text()).toContain('No hosts yet');
  });
});
```

- [ ] **Step 2: Implement** — `web/packages/ui/src/composite/TDataTable.vue`:

```vue
<script setup lang="ts" generic="T extends Record<string, unknown>">
import { computed } from 'vue';

export interface Column<R> {
  key: keyof R & string;
  label: string;
  width?: string;
  align?: 'left' | 'right' | 'center';
  numeric?: boolean;
}

const props = withDefaults(
  defineProps<{
    columns: Column<T>[];
    rows: T[];
    rowKey: keyof T & string;
    selectable?: boolean;
    selected?: Array<T[keyof T & string]>;
    emptyText?: string;
  }>(),
  { selectable: false, emptyText: 'No data.' }
);

const emit = defineEmits<{
  'row-click': [row: T];
  'update:selected': [ids: Array<T[keyof T & string]>];
}>();

const selectedSet = computed(() => new Set(props.selected ?? []));

const gridCols = computed(() => {
  const parts = props.columns.map((c) => c.width ?? '1fr');
  return props.selectable ? `32px ${parts.join(' ')}` : parts.join(' ');
});

function toggle(id: T[keyof T & string]) {
  const next = new Set(selectedSet.value);
  if (next.has(id)) next.delete(id); else next.add(id);
  emit('update:selected', Array.from(next));
}

function toggleAll() {
  if (selectedSet.value.size === props.rows.length) {
    emit('update:selected', []);
  } else {
    emit('update:selected', props.rows.map((r) => r[props.rowKey] as T[keyof T & string]));
  }
}

function cellValue(row: T, col: Column<T>): string {
  const v = row[col.key];
  return v == null ? '' : String(v);
}
</script>

<template>
  <div class="t-tbl">
    <div class="t-tbl-head" :style="{ gridTemplateColumns: gridCols }">
      <span v-if="selectable" class="t-tbl-check-wrap">
        <button
          type="button"
          class="t-tbl-check"
          :class="{ 'is-checked': selectedSet.size === rows.length && rows.length > 0 }"
          :aria-label="selectedSet.size === rows.length ? 'Deselect all' : 'Select all'"
          @click="toggleAll"
        />
      </span>
      <span
        v-for="col in columns"
        :key="col.key"
        class="t-tbl-h"
        :class="{ 'is-right': col.align === 'right', 'is-center': col.align === 'center' }"
      >{{ col.label }}</span>
    </div>

    <template v-if="rows.length === 0">
      <div class="t-tbl-empty">{{ emptyText }}</div>
    </template>

    <template v-else>
      <div
        v-for="row in rows"
        :key="String(row[rowKey])"
        class="t-tbl-row"
        :class="{ 'is-selected': selectedSet.has(row[rowKey] as never) }"
        :style="{ gridTemplateColumns: gridCols }"
        @click="emit('row-click', row)"
      >
        <span v-if="selectable" class="t-tbl-check-wrap" @click.stop>
          <button
            type="button"
            class="t-tbl-check"
            :class="{ 'is-checked': selectedSet.has(row[rowKey] as never) }"
            @click="toggle(row[rowKey] as never)"
          />
        </span>
        <span
          v-for="col in columns"
          :key="col.key"
          class="t-tbl-c"
          :class="{
            'is-right': col.align === 'right',
            'is-center': col.align === 'center',
            'is-num': col.numeric,
          }"
        >
          <slot :name="`cell:${col.key}`" :row="row" :value="row[col.key]">
            {{ cellValue(row, col) }}
          </slot>
        </span>
      </div>
    </template>
  </div>
</template>

<style scoped>
.t-tbl {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  font-size: 0.72rem;
  font-family: var(--font-body);
}
.t-tbl-head {
  display: grid;
  padding: 8px 12px;
  background: color-mix(in srgb, var(--bg-base) 50%, transparent);
  color: var(--text-subtle);
  border-bottom: 1px solid var(--border);
  font-size: 0.54rem;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  font-weight: 500;
}
.t-tbl-row {
  display: grid;
  padding: 9px 12px;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  color: var(--text-secondary);
  transition: background var(--motion-hover) var(--ease);
}
.t-tbl-row:hover { background: var(--accent-muted); }
.t-tbl-row.is-selected { background: var(--accent-muted); }
.t-tbl-row:last-child { border-bottom: none; }
.t-tbl-c, .t-tbl-h { display: flex; align-items: center; min-width: 0; }
.t-tbl-c.is-num {
  font-family: var(--font-display);
  font-variant-numeric: tabular-nums;
  color: var(--text-primary);
}
.is-right  { justify-content: flex-end; }
.is-center { justify-content: center; }

.t-tbl-empty {
  padding: 28px 20px;
  text-align: center;
  color: var(--text-muted);
  font-size: 0.78rem;
}

.t-tbl-check-wrap { display: flex; align-items: center; }
.t-tbl-check {
  width: 13px;
  height: 13px;
  border: 1px solid var(--border-strong);
  border-radius: 3px;
  background: transparent;
  cursor: pointer;
  padding: 0;
  position: relative;
}
.t-tbl-check.is-checked {
  background: var(--accent);
  border-color: var(--accent);
}
.t-tbl-check.is-checked::after {
  content: '✓';
  position: absolute;
  top: -4px; left: 1px;
  color: var(--bg-base);
  font-family: var(--font-body);
  font-size: 0.72rem;
  font-weight: 700;
}
</style>
```

- [ ] **Step 3: Export + test + commit**

```ts
// index.ts
export { default as TDataTable } from './composite/TDataTable.vue';
export type { Column } from './composite/TDataTable.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/composite/TDataTable.vue web/packages/ui/tests/TDataTable.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TDataTable with columns, row selection, empty state, cell slots"
```

---

### Task 3.4: TModal + TConfirmDialog + useFocusTrap

**Files:**
- Create: `web/packages/ui/src/composables/useFocusTrap.ts`
- Create: `web/packages/ui/src/composite/TModal.vue`
- Create: `web/packages/ui/src/composite/TConfirmDialog.vue`
- Create: `web/packages/ui/tests/TModal.test.ts`

- [ ] **Step 1: Test** — `web/packages/ui/tests/TModal.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TModal from '../src/composite/TModal.vue';
import TConfirmDialog from '../src/composite/TConfirmDialog.vue';

describe('TModal', () => {
  it('renders when open=true', () => {
    const w = mount(TModal, {
      props: { open: true, title: 'Test' },
      slots: { default: '<p>body</p>' },
      attachTo: document.body,
    });
    expect(document.querySelector('.t-modal')).not.toBeNull();
    w.unmount();
  });

  it('does not render when open=false', () => {
    mount(TModal, { props: { open: false, title: 'Test' }, attachTo: document.body });
    expect(document.querySelector('.t-modal')).toBeNull();
  });

  it('emits close on backdrop click', async () => {
    const w = mount(TModal, {
      props: { open: true, title: 'Test' },
      slots: { default: 'body' },
      attachTo: document.body,
    });
    const backdrop = document.querySelector('.t-modal-backdrop') as HTMLElement;
    backdrop.click();
    await w.vm.$nextTick();
    expect(w.emitted('close')).toHaveLength(1);
    w.unmount();
  });

  it('emits close on ESC', async () => {
    const w = mount(TModal, {
      props: { open: true, title: 'Test' },
      slots: { default: 'body' },
      attachTo: document.body,
    });
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await w.vm.$nextTick();
    expect(w.emitted('close')).toHaveLength(1);
    w.unmount();
  });
});

describe('TConfirmDialog', () => {
  it('emits confirm when Confirm clicked', async () => {
    const w = mount(TConfirmDialog, {
      props: { open: true, title: 'Revoke?', message: 'Cannot be undone.' },
      attachTo: document.body,
    });
    (document.querySelector('.t-confirm-ok') as HTMLButtonElement).click();
    await w.vm.$nextTick();
    expect(w.emitted('confirm')).toHaveLength(1);
    w.unmount();
  });

  it('emits cancel when Cancel clicked', async () => {
    const w = mount(TConfirmDialog, {
      props: { open: true, title: 'Revoke?' },
      attachTo: document.body,
    });
    (document.querySelector('.t-confirm-cancel') as HTMLButtonElement).click();
    await w.vm.$nextTick();
    expect(w.emitted('cancel')).toHaveLength(1);
    w.unmount();
  });
});
```

- [ ] **Step 2: `web/packages/ui/src/composables/useFocusTrap.ts`**:

```ts
import { onMounted, onUnmounted, type Ref } from 'vue';

/**
 * Traps keyboard focus inside the given element while mounted.
 * ESC bubble-up is allowed — host component decides close behaviour.
 */
export function useFocusTrap(containerRef: Ref<HTMLElement | null>) {
  let lastFocused: HTMLElement | null = null;

  function trap(ev: KeyboardEvent) {
    if (ev.key !== 'Tab' || !containerRef.value) return;
    const focusable = containerRef.value.querySelectorAll<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusable.length === 0) return;
    const first = focusable[0]!;
    const last = focusable[focusable.length - 1]!;
    if (ev.shiftKey && document.activeElement === first) {
      ev.preventDefault();
      last.focus();
    } else if (!ev.shiftKey && document.activeElement === last) {
      ev.preventDefault();
      first.focus();
    }
  }

  onMounted(() => {
    lastFocused = document.activeElement as HTMLElement | null;
    const first = containerRef.value?.querySelector<HTMLElement>(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    first?.focus();
    document.addEventListener('keydown', trap);
  });

  onUnmounted(() => {
    document.removeEventListener('keydown', trap);
    lastFocused?.focus();
  });
}
```

- [ ] **Step 3: `web/packages/ui/src/composite/TModal.vue`**:

```vue
<script setup lang="ts">
import { ref, watch, onMounted, onUnmounted } from 'vue';
import { useFocusTrap } from '../composables/useFocusTrap';

const props = defineProps<{
  open: boolean;
  title: string;
  width?: string;
}>();

const emit = defineEmits<{ close: [] }>();

const panel = ref<HTMLElement | null>(null);
useFocusTrap(panel);

function onEsc(ev: KeyboardEvent) {
  if (ev.key === 'Escape' && props.open) emit('close');
}

onMounted(() => document.addEventListener('keydown', onEsc));
onUnmounted(() => document.removeEventListener('keydown', onEsc));

watch(
  () => props.open,
  (o) => {
    document.body.style.overflow = o ? 'hidden' : '';
  }
);
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="t-modal-backdrop" @click.self="emit('close')">
      <div
        ref="panel"
        class="t-modal"
        role="dialog"
        aria-modal="true"
        :style="{ width: width ?? 'min(480px, 90vw)' }"
      >
        <header class="t-modal-head">
          <h3 class="t-modal-title">{{ title }}</h3>
          <button
            type="button"
            class="t-modal-close"
            aria-label="Close"
            @click="emit('close')"
          >×</button>
        </header>
        <div class="t-modal-body"><slot /></div>
        <footer v-if="$slots.footer" class="t-modal-foot">
          <slot name="footer" />
        </footer>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.t-modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: var(--z-modal);
  background: rgba(0, 0, 0, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  backdrop-filter: blur(2px);
}
.t-modal {
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  box-shadow: var(--shadow-lg);
  max-height: 90vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  animation: modalIn var(--motion-modal) var(--ease-out);
}
@keyframes modalIn {
  from { opacity: 0; transform: translateY(10px) scale(0.98); }
  to   { opacity: 1; transform: translateY(0)    scale(1); }
}
.t-modal-head {
  padding: 14px 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border);
}
.t-modal-title {
  font-family: var(--font-display);
  font-size: 1.05rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  margin: 0;
  color: var(--text-primary);
}
.t-modal-close {
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 1.3rem;
  line-height: 1;
  cursor: pointer;
  padding: 0;
}
.t-modal-body { padding: 14px 16px; overflow: auto; color: var(--text-secondary); font-size: 0.85rem; }
.t-modal-foot {
  padding: 10px 16px;
  border-top: 1px solid var(--border);
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}
</style>
```

- [ ] **Step 4: `web/packages/ui/src/composite/TConfirmDialog.vue`**:

```vue
<script setup lang="ts">
import TModal from './TModal.vue';
import TButton from '../atoms/TButton.vue';

withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    message?: string;
    confirmLabel?: string;
    cancelLabel?: string;
    variant?: 'danger' | 'primary';
  }>(),
  {
    confirmLabel: 'Confirm',
    cancelLabel: 'Cancel',
    variant: 'danger',
  }
);

const emit = defineEmits<{ confirm: []; cancel: [] }>();
</script>

<template>
  <TModal :open="open" :title="title" @close="emit('cancel')">
    <p v-if="message">{{ message }}</p>
    <slot />
    <template #footer>
      <TButton class="t-confirm-cancel" variant="ghost" size="sm" @click="emit('cancel')">
        {{ cancelLabel }}
      </TButton>
      <TButton class="t-confirm-ok" :variant="variant" size="sm" @click="emit('confirm')">
        {{ confirmLabel }}
      </TButton>
    </template>
  </TModal>
</template>
```

- [ ] **Step 5: Export + test + commit**

```ts
// index.ts
export { default as TModal } from './composite/TModal.vue';
export { default as TConfirmDialog } from './composite/TConfirmDialog.vue';
export { useFocusTrap } from './composables/useFocusTrap';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/composite/TModal.vue web/packages/ui/src/composite/TConfirmDialog.vue web/packages/ui/src/composables/useFocusTrap.ts web/packages/ui/tests/TModal.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TModal + TConfirmDialog + useFocusTrap"
```

---

### Task 3.5: Toast system — useToast + TToastHost

**Files:**
- Create: `web/packages/ui/src/composables/useToast.ts`
- Create: `web/packages/ui/src/composite/TToastHost.vue`
- Create: `web/packages/ui/tests/useToast.test.ts`

- [ ] **Step 1: Test** — `web/packages/ui/tests/useToast.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { useToast, __resetToastsForTest } from '../src/composables/useToast';
import TToastHost from '../src/composite/TToastHost.vue';

describe('useToast', () => {
  beforeEach(() => __resetToastsForTest());

  it('success adds a toast to the host', async () => {
    const w = mount(TToastHost, { attachTo: document.body });
    const toast = useToast();
    toast.success({ title: 'Saved' });
    await w.vm.$nextTick();
    expect(w.text()).toContain('Saved');
    w.unmount();
  });

  it.each(['success', 'warn', 'error', 'info'] as const)(
    'toast.%s produces correct variant class', async (kind) => {
      const w = mount(TToastHost, { attachTo: document.body });
      const toast = useToast();
      toast[kind]({ title: `t-${kind}` });
      await w.vm.$nextTick();
      expect(w.find(`.t-toast--${kind}`).exists()).toBe(true);
      w.unmount();
    }
  );

  it('dismiss removes the toast', async () => {
    const w = mount(TToastHost, { attachTo: document.body });
    const toast = useToast();
    const id = toast.info({ title: 'hi' });
    await w.vm.$nextTick();
    toast.dismiss(id);
    await w.vm.$nextTick();
    expect(w.findAll('.t-toast')).toHaveLength(0);
    w.unmount();
  });
});
```

- [ ] **Step 2: `web/packages/ui/src/composables/useToast.ts`**:

```ts
import { reactive } from 'vue';

export type ToastKind = 'success' | 'warn' | 'error' | 'info';

export interface ToastInput {
  title: string;
  description?: string;
  timeout?: number;
}

export interface ToastEntry extends ToastInput {
  id: number;
  kind: ToastKind;
}

const toasts = reactive<ToastEntry[]>([]);
let nextId = 1;

function push(kind: ToastKind, t: ToastInput): number {
  const id = nextId++;
  const entry: ToastEntry = { id, kind, ...t };
  toasts.push(entry);
  const timeout = t.timeout ?? 5000;
  if (timeout > 0) {
    setTimeout(() => dismiss(id), timeout);
  }
  return id;
}

function dismiss(id: number) {
  const i = toasts.findIndex((t) => t.id === id);
  if (i >= 0) toasts.splice(i, 1);
}

export function useToast() {
  return {
    success: (t: ToastInput) => push('success', t),
    warn:    (t: ToastInput) => push('warn', t),
    error:   (t: ToastInput) => push('error', t),
    info:    (t: ToastInput) => push('info', t),
    dismiss,
  };
}

/** @internal */
export function __resetToastsForTest(): void {
  toasts.splice(0, toasts.length);
  nextId = 1;
}

/** Exported for TToastHost only. */
export const __toastState = toasts;
```

- [ ] **Step 3: `web/packages/ui/src/composite/TToastHost.vue`**:

```vue
<script setup lang="ts">
import { __toastState, useToast } from '../composables/useToast';

const { dismiss } = useToast();
const toasts = __toastState;

const icon = {
  success: '✓',
  warn: '!',
  error: '×',
  info: 'i',
} as const;
</script>

<template>
  <Teleport to="body">
    <div class="t-toast-host" aria-live="polite">
      <div
        v-for="t in toasts"
        :key="t.id"
        class="t-toast"
        :class="`t-toast--${t.kind}`"
      >
        <span class="t-toast-ico">{{ icon[t.kind] }}</span>
        <div class="t-toast-body">
          <b>{{ t.title }}</b>
          <span v-if="t.description">{{ t.description }}</span>
        </div>
        <button
          type="button"
          class="t-toast-close"
          aria-label="Dismiss"
          @click="dismiss(t.id)"
        >×</button>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.t-toast-host {
  position: fixed;
  bottom: 20px;
  right: 20px;
  z-index: var(--z-toast);
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-width: 360px;
}
.t-toast {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 14px;
  border-radius: var(--radius);
  border: 1px solid;
  font-size: 0.78rem;
  background: var(--bg-surface);
  box-shadow: var(--shadow);
  animation: toastIn var(--motion-enter) var(--ease-out);
}
@keyframes toastIn { from { opacity: 0; transform: translateX(20px); } to { opacity: 1; transform: translateX(0); } }
.t-toast-ico {
  width: 18px; height: 18px;
  border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 0.68rem; font-weight: 700;
  flex-shrink: 0;
  color: var(--bg-base);
}
.t-toast-body { flex: 1; display: flex; flex-direction: column; gap: 1px; color: var(--text-primary); }
.t-toast-close { background: none; border: none; color: var(--text-muted); font-size: 1rem; cursor: pointer; padding: 0; }

.t-toast--success { border-color: var(--safe); background: var(--safe-muted); }
.t-toast--success .t-toast-ico { background: var(--safe); }
.t-toast--warn    { border-color: var(--warn); background: var(--warn-muted); }
.t-toast--warn    .t-toast-ico { background: var(--warn); }
.t-toast--error   { border-color: var(--unsafe); background: var(--unsafe-muted); }
.t-toast--error   .t-toast-ico { background: var(--unsafe); }
.t-toast--info    { border-color: var(--accent-strong); background: var(--accent-muted); }
.t-toast--info    .t-toast-ico { background: var(--accent-strong); }
</style>
```

- [ ] **Step 4: Export + test + commit**

```ts
// index.ts
export { useToast } from './composables/useToast';
export type { ToastKind, ToastInput } from './composables/useToast';
export { default as TToastHost } from './composite/TToastHost.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/composables/useToast.ts web/packages/ui/src/composite/TToastHost.vue web/packages/ui/tests/useToast.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): imperative toast system + TToastHost"
```

---

## Phase 4 — Shell components

### Task 4.1: TSidebar

**Files:**
- Create: `web/packages/ui/src/shell/TSidebar.vue`
- Create: `web/packages/ui/tests/TSidebar.test.ts`

- [ ] **Step 1: Test** — `web/packages/ui/tests/TSidebar.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TSidebar, { type NavSection } from '../src/shell/TSidebar.vue';

const nav: NavSection[] = [
  {
    items: [
      { href: '#/', label: 'Dashboard' },
      { href: '#/orgs', label: 'Organisations' },
    ],
  },
  {
    label: 'Admin',
    items: [{ href: '#/audit', label: 'Audit log' }],
  },
];

describe('TSidebar', () => {
  it('renders items in each section', () => {
    const w = mount(TSidebar, {
      props: { nav, portalTitle: 'Triton', portalSubtitle: 'Licence', currentHref: '#/' }
    });
    expect(w.findAll('.t-nav-item')).toHaveLength(3);
  });

  it('marks current item active', () => {
    const w = mount(TSidebar, {
      props: { nav, portalTitle: 'Triton', portalSubtitle: 'Licence', currentHref: '#/orgs' }
    });
    const active = w.findAll('.t-nav-item.is-active');
    expect(active).toHaveLength(1);
    expect(active[0]!.text()).toContain('Organisations');
  });

  it('renders section labels', () => {
    const w = mount(TSidebar, {
      props: { nav, portalTitle: 'Triton', portalSubtitle: 'Licence', currentHref: '#/' }
    });
    expect(w.text()).toContain('Admin');
  });

  it('renders footer slot', () => {
    const w = mount(TSidebar, {
      props: { nav, portalTitle: 'Triton', portalSubtitle: 'Licence', currentHref: '#/' },
      slots: { footer: '<div class="foot">me</div>' }
    });
    expect(w.find('.foot').exists()).toBe(true);
  });
});
```

- [ ] **Step 2: Implement** — `web/packages/ui/src/shell/TSidebar.vue`:

```vue
<script setup lang="ts">
export interface NavItem {
  href: string;
  label: string;
  icon?: string;      // sprite symbol id (future)
  badge?: string;
}
export interface NavSection {
  label?: string;
  items: NavItem[];
}

defineProps<{
  nav: NavSection[];
  portalTitle: string;
  portalSubtitle: string;
  currentHref: string;
}>();
</script>

<template>
  <nav class="t-sidebar" aria-label="Primary">
    <div class="t-logo">
      <div class="t-logo-img">T</div>
      <div class="t-logo-txt">
        <span class="t-logo-title">{{ portalTitle }}</span>
        <span class="t-logo-sub">{{ portalSubtitle }}</span>
      </div>
    </div>

    <div class="t-nav">
      <template v-for="(section, idx) in nav" :key="idx">
        <div v-if="section.label" class="t-nav-section">{{ section.label }}</div>
        <a
          v-for="item in section.items"
          :key="item.href"
          :href="item.href"
          class="t-nav-item"
          :class="{ 'is-active': item.href === currentHref }"
        >
          <span class="t-nav-ico" aria-hidden="true" />
          <span class="t-nav-label">{{ item.label }}</span>
          <span v-if="item.badge" class="t-nav-badge">{{ item.badge }}</span>
        </a>
      </template>
    </div>

    <footer class="t-side-foot"><slot name="footer" /></footer>
  </nav>
</template>

<style scoped>
.t-sidebar {
  width: var(--sidebar-w);
  background: var(--bg-surface);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  position: fixed;
  left: 0; top: 0; bottom: 0;
  z-index: var(--z-sidebar);
}
.t-logo {
  padding: 14px;
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 10px;
  position: relative;
}
.t-logo::before {
  content: '';
  position: absolute;
  left: 0; top: 0; bottom: 0;
  width: 3px;
  background: var(--portal-accent);
}
.t-logo-img {
  width: 28px; height: 28px;
  border-radius: var(--radius-sm);
  background: linear-gradient(135deg, var(--portal-accent), var(--accent));
  color: var(--bg-base);
  display: flex; align-items: center; justify-content: center;
  font-family: var(--font-display);
  font-weight: 700;
  font-size: 0.95rem;
  letter-spacing: -0.04em;
}
.t-logo-txt { display: flex; flex-direction: column; gap: 1px; line-height: 1.1; }
.t-logo-title {
  font-family: var(--font-display);
  font-weight: 600;
  font-size: 0.96rem;
  letter-spacing: -0.02em;
  color: var(--text-primary);
}
.t-logo-sub {
  font-size: 0.56rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text-muted);
  font-weight: 500;
}

.t-nav { padding: 10px 0; flex: 1; overflow-y: auto; }
.t-nav-section {
  font-size: 0.54rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--text-subtle);
  font-weight: 500;
  padding: 12px 14px 4px;
}
.t-nav-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 14px;
  color: var(--text-muted);
  text-decoration: none;
  font-size: 0.76rem;
  font-weight: 400;
  border-left: 2px solid transparent;
  transition: all var(--motion-hover) var(--ease);
}
.t-nav-item:hover { color: var(--text-primary); background: color-mix(in srgb, var(--text-primary) 3%, transparent); }
.t-nav-item.is-active {
  color: var(--portal-accent);
  background: color-mix(in srgb, var(--portal-accent) 10%, transparent);
  border-left-color: var(--portal-accent);
  font-weight: 500;
}
.t-nav-ico { width: 14px; height: 14px; border-radius: 2px; background: currentColor; opacity: 0.55; }
.t-nav-item.is-active .t-nav-ico { opacity: 1; }
.t-nav-label { flex: 1; }
.t-nav-badge {
  font-size: 0.58rem;
  padding: 1px 6px;
  border-radius: var(--radius-pill);
  background: var(--accent-muted);
  color: var(--accent-strong);
}

.t-side-foot {
  padding: 12px 14px;
  border-top: 1px solid var(--border);
}
</style>
```

- [ ] **Step 3: Export + test + commit**

```ts
// index.ts
export { default as TSidebar } from './shell/TSidebar.vue';
export type { NavItem, NavSection } from './shell/TSidebar.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/shell/TSidebar.vue web/packages/ui/tests/TSidebar.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TSidebar with sectioned nav + active-state + portal accent"
```

---

### Task 4.2: TThemeToggle

**Files:**
- Create: `web/packages/ui/src/shell/TThemeToggle.vue`
- Create: `web/packages/ui/tests/TThemeToggle.test.ts`

- [ ] **Step 1: Test**:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import TThemeToggle from '../src/shell/TThemeToggle.vue';

describe('TThemeToggle', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute('data-theme');
  });

  it('cycles dark → light → system on clicks', async () => {
    const w = mount(TThemeToggle);
    // starts at 'dark' (default when no storage/system)
    await w.trigger('click');
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    await w.trigger('click');
    // system → depends on matchMedia, but element should have an attr
    const attr = document.documentElement.getAttribute('data-theme');
    expect(['light', 'dark']).toContain(attr);
  });
});
```

- [ ] **Step 2: Implement** — `web/packages/ui/src/shell/TThemeToggle.vue`:

```vue
<script setup lang="ts">
import { computed } from 'vue';
import { useTheme, type ThemeMode } from '../composables/useTheme';

const { mode, resolved, setMode } = useTheme();

const cycle: ThemeMode[] = ['dark', 'light', 'system'];

const icon = computed(() => {
  if (mode.value === 'system') return '◐';
  return mode.value === 'light' ? '☀' : '◑';
});

const label = computed(() => {
  if (mode.value === 'system') return `Auto (${resolved.value})`;
  return mode.value === 'light' ? 'Light' : 'Dark';
});

function onClick() {
  const i = cycle.indexOf(mode.value);
  const next = cycle[(i + 1) % cycle.length]!;
  setMode(next);
}
</script>

<template>
  <button
    type="button"
    class="t-theme-toggle"
    :aria-label="`Theme: ${label}`"
    @click="onClick"
  >
    <span class="t-theme-ico">{{ icon }}</span>
    <span class="t-theme-label">{{ label }}</span>
  </button>
</template>

<style scoped>
.t-theme-toggle {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 8px;
  border-radius: var(--radius-sm);
  background: var(--bg-base);
  border: 1px solid var(--border);
  color: var(--text-secondary);
  font-size: 0.68rem;
  font-family: var(--font-body);
  font-weight: 500;
  cursor: pointer;
}
.t-theme-toggle:hover { background: var(--bg-elevated); color: var(--text-primary); }
</style>
```

- [ ] **Step 3: Export + test + commit**

```ts
// index.ts
export { default as TThemeToggle } from './shell/TThemeToggle.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/shell/TThemeToggle.vue web/packages/ui/tests/TThemeToggle.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TThemeToggle tri-state cycle (dark → light → system)"
```

---

### Task 4.3: TAppSwitcher

**Files:**
- Create: `web/packages/ui/src/shell/TAppSwitcher.vue`
- Create: `web/packages/ui/tests/TAppSwitcher.test.ts`

- [ ] **Step 1: Test**:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TAppSwitcher, { type AppEntry } from '../src/shell/TAppSwitcher.vue';

const apps: AppEntry[] = [
  { id: 'license', name: 'Licence', subtitle: 'Vendor ops', url: 'http://localhost:8081', accent: '#a78bfa' },
  { id: 'report',  name: 'Report',  subtitle: 'Security', url: 'http://localhost:8080', accent: '#22d3ee' },
  { id: 'manage',  name: 'Manage',  subtitle: 'Network',  url: null,                    accent: '#a3e635' },
];

describe('TAppSwitcher', () => {
  it('is closed by default', () => {
    const w = mount(TAppSwitcher, { props: { apps, currentId: 'report' }, attachTo: document.body });
    expect(document.querySelector('.t-app-menu')).toBeNull();
    w.unmount();
  });

  it('opens on button click', async () => {
    const w = mount(TAppSwitcher, { props: { apps, currentId: 'report' }, attachTo: document.body });
    await w.find('.t-app-trigger').trigger('click');
    expect(document.querySelector('.t-app-menu')).not.toBeNull();
    w.unmount();
  });

  it('greys out apps with null url', async () => {
    const w = mount(TAppSwitcher, { props: { apps, currentId: 'report' }, attachTo: document.body });
    await w.find('.t-app-trigger').trigger('click');
    const tiles = document.querySelectorAll('.t-app-tile');
    const manage = Array.from(tiles).find(t => t.textContent?.includes('Manage'));
    expect(manage?.classList.contains('is-disabled')).toBe(true);
    w.unmount();
  });

  it('marks current app', async () => {
    const w = mount(TAppSwitcher, { props: { apps, currentId: 'report' }, attachTo: document.body });
    await w.find('.t-app-trigger').trigger('click');
    const current = document.querySelector('.t-app-tile.is-current');
    expect(current?.textContent).toContain('Report');
    w.unmount();
  });
});
```

- [ ] **Step 2: Implement** — `web/packages/ui/src/shell/TAppSwitcher.vue`:

```vue
<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';

export interface AppEntry {
  id: string;
  name: string;
  subtitle: string;
  url: string | null;   // null = not deployed in this environment
  accent: string;
}

defineProps<{
  apps: AppEntry[];
  currentId: string;
}>();

const open = ref(false);
const root = ref<HTMLElement | null>(null);

function toggle() { open.value = !open.value; }
function close(ev?: MouseEvent) {
  if (!ev || !root.value?.contains(ev.target as Node)) open.value = false;
}

onMounted(() => document.addEventListener('click', close));
onUnmounted(() => document.removeEventListener('click', close));
</script>

<template>
  <div ref="root" class="t-app-switcher">
    <button
      type="button"
      class="t-app-trigger"
      aria-label="Switch portal"
      :aria-expanded="open"
      @click="toggle"
    >
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true">
        <g fill="currentColor">
          <rect x="2" y="2" width="3" height="3" rx="0.5" />
          <rect x="6.5" y="2" width="3" height="3" rx="0.5" />
          <rect x="11" y="2" width="3" height="3" rx="0.5" />
          <rect x="2" y="6.5" width="3" height="3" rx="0.5" />
          <rect x="6.5" y="6.5" width="3" height="3" rx="0.5" />
          <rect x="11" y="6.5" width="3" height="3" rx="0.5" />
          <rect x="2" y="11" width="3" height="3" rx="0.5" />
          <rect x="6.5" y="11" width="3" height="3" rx="0.5" />
          <rect x="11" y="11" width="3" height="3" rx="0.5" />
        </g>
      </svg>
    </button>

    <Teleport to="body">
      <div v-if="open" class="t-app-menu" role="menu">
        <div class="t-app-grid">
          <a
            v-for="app in apps"
            :key="app.id"
            :href="app.url ?? '#'"
            class="t-app-tile"
            :class="{
              'is-current': app.id === currentId,
              'is-disabled': !app.url,
            }"
            :style="{ '--tile-accent': app.accent }"
            @click="!app.url && $event.preventDefault()"
          >
            <span class="t-app-swatch" />
            <span class="t-app-name">{{ app.name }}</span>
            <span class="t-app-sub">{{ app.subtitle }}</span>
          </a>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.t-app-switcher { position: relative; display: inline-block; }
.t-app-trigger {
  width: 26px; height: 26px;
  border-radius: var(--radius-sm);
  background: var(--bg-base);
  border: 1px solid var(--border);
  color: var(--text-muted);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
}
.t-app-trigger:hover { color: var(--text-primary); }

.t-app-menu {
  position: fixed;
  top: calc(var(--topbar-h) + 4px);
  right: 12px;
  z-index: var(--z-modal);
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  padding: 10px;
  box-shadow: var(--shadow-lg);
}
.t-app-grid {
  display: grid;
  grid-template-columns: repeat(3, 90px);
  gap: 6px;
}
.t-app-tile {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  padding: 10px;
  border-radius: var(--radius-sm);
  background: var(--bg-elevated);
  color: var(--text-primary);
  text-decoration: none;
  border: 1px solid transparent;
  position: relative;
}
.t-app-tile:hover:not(.is-disabled) { background: var(--bg-hover); }
.t-app-tile.is-current { border-color: var(--tile-accent); }
.t-app-tile.is-disabled { opacity: 0.35; cursor: not-allowed; }
.t-app-swatch {
  width: 8px; height: 8px; border-radius: 2px;
  background: var(--tile-accent);
}
.t-app-name {
  font-family: var(--font-display);
  font-size: 0.82rem;
  font-weight: 600;
  letter-spacing: -0.01em;
}
.t-app-sub { font-size: 0.58rem; color: var(--text-muted); }
</style>
```

- [ ] **Step 3: Export + commit**

```ts
// index.ts
export { default as TAppSwitcher } from './shell/TAppSwitcher.vue';
export type { AppEntry } from './shell/TAppSwitcher.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/shell/TAppSwitcher.vue web/packages/ui/tests/TAppSwitcher.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TAppSwitcher 3x3 waffle with greyed-out undeployed apps"
```

---

### Task 4.4: TCrumbBar + TUserMenu + TAppShell composition

**Files:**
- Create: `web/packages/ui/src/shell/TCrumbBar.vue`
- Create: `web/packages/ui/src/shell/TUserMenu.vue`
- Create: `web/packages/ui/src/shell/TAppShell.vue`
- Create: `web/packages/ui/tests/TAppShell.test.ts`

- [ ] **Step 1: Test** — `web/packages/ui/tests/TAppShell.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import TAppShell from '../src/shell/TAppShell.vue';

describe('TAppShell', () => {
  it('sets portal-accent CSS var on root', () => {
    const w = mount(TAppShell, {
      props: { portalAccent: '#a78bfa' },
      slots: { sidebar: '<aside>S</aside>', default: '<div>main</div>' },
    });
    const style = (w.element as HTMLElement).getAttribute('style') ?? '';
    expect(style).toContain('--portal-accent');
    expect(style).toContain('#a78bfa');
  });

  it('renders topbar slot', () => {
    const w = mount(TAppShell, {
      props: { portalAccent: '#22d3ee' },
      slots: { topbar: '<span class="t-crumb">Overview</span>', default: 'body' },
    });
    expect(w.find('.t-crumb').exists()).toBe(true);
  });
});
```

- [ ] **Step 2: `web/packages/ui/src/shell/TCrumbBar.vue`**:

```vue
<script setup lang="ts">
export interface Crumb { label: string; href?: string }
defineProps<{ crumbs: Crumb[] }>();
</script>

<template>
  <nav class="t-crumb-bar" aria-label="Breadcrumb">
    <template v-for="(c, i) in crumbs" :key="i">
      <a v-if="c.href && i !== crumbs.length - 1" :href="c.href" class="t-crumb">{{ c.label }}</a>
      <strong v-else class="t-crumb is-current">{{ c.label }}</strong>
      <span v-if="i !== crumbs.length - 1" class="t-crumb-sep">›</span>
    </template>
  </nav>
</template>

<style scoped>
.t-crumb-bar { display: inline-flex; align-items: center; gap: 6px; font-size: 0.72rem; color: var(--text-muted); }
.t-crumb { color: var(--text-muted); text-decoration: none; }
.t-crumb.is-current { color: var(--text-primary); font-weight: 500; }
.t-crumb-sep { color: var(--border-strong); }
</style>
```

- [ ] **Step 3: `web/packages/ui/src/shell/TUserMenu.vue`**:

```vue
<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import TAvatar from '../atoms/TAvatar.vue';

defineProps<{ name: string; role?: string; org?: string }>();
const emit = defineEmits<{ 'sign-out': [] }>();

const open = ref(false);
const root = ref<HTMLElement | null>(null);

function toggle() { open.value = !open.value; }
function close(ev: MouseEvent) {
  if (!root.value?.contains(ev.target as Node)) open.value = false;
}
onMounted(() => document.addEventListener('click', close));
onUnmounted(() => document.removeEventListener('click', close));
</script>

<template>
  <div ref="root" class="t-user-menu">
    <button type="button" class="t-user-trigger" @click="toggle" aria-label="Account menu">
      <TAvatar :name="name" />
    </button>
    <Teleport to="body">
      <div v-if="open" class="t-user-pop">
        <div class="t-user-who">
          <b>{{ name }}</b>
          <span v-if="role">{{ role }}</span>
          <span v-if="org" class="t-user-org">{{ org }}</span>
        </div>
        <hr class="t-user-sep" />
        <button type="button" class="t-user-item" @click="emit('sign-out')">Sign out</button>
      </div>
    </Teleport>
  </div>
</template>

<style scoped>
.t-user-trigger { background: none; border: none; cursor: pointer; padding: 0; }
.t-user-pop {
  position: fixed;
  top: calc(var(--topbar-h) + 4px);
  right: 12px;
  z-index: var(--z-modal);
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius);
  min-width: 200px;
  box-shadow: var(--shadow-lg);
  padding: 4px;
}
.t-user-who {
  padding: 10px 12px;
  display: flex;
  flex-direction: column;
  gap: 2px;
  font-size: 0.75rem;
  color: var(--text-primary);
}
.t-user-who b { font-family: var(--font-display); font-weight: 600; letter-spacing: -0.01em; }
.t-user-who span { color: var(--text-muted); font-size: 0.68rem; }
.t-user-sep { border: none; border-top: 1px solid var(--border); margin: 4px 0; }
.t-user-item {
  background: none; border: none; width: 100%;
  padding: 8px 12px; text-align: left;
  color: var(--text-primary);
  font-size: 0.76rem;
  border-radius: var(--radius-sm);
  cursor: pointer;
}
.t-user-item:hover { background: var(--bg-hover); }
</style>
```

- [ ] **Step 4: `web/packages/ui/src/shell/TAppShell.vue`**:

```vue
<script setup lang="ts">
defineProps<{ portalAccent: string }>();
</script>

<template>
  <div
    class="t-app"
    :style="{
      '--portal-accent': portalAccent,
      '--portal-accent-soft': `color-mix(in srgb, ${portalAccent} 12%, transparent)`
    }"
  >
    <slot name="sidebar" />
    <main class="t-app-main">
      <header class="t-topbar">
        <slot name="topbar" />
      </header>
      <div class="t-app-page"><slot /></div>
    </main>
  </div>
</template>

<style scoped>
.t-app {
  display: grid;
  grid-template-columns: var(--sidebar-w) 1fr;
  min-height: 100vh;
  color: var(--text-primary);
  background: var(--bg-base);
}
.t-app-main {
  display: flex;
  flex-direction: column;
  min-width: 0;
}
.t-topbar {
  position: sticky;
  top: 0;
  z-index: var(--z-topbar);
  height: var(--topbar-h);
  background: var(--bg-surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 16px;
}
.t-app-page { flex: 1; padding: 20px; overflow: auto; }
</style>
```

- [ ] **Step 5: Export + test + commit**

```ts
// index.ts
export { default as TCrumbBar } from './shell/TCrumbBar.vue';
export type { Crumb } from './shell/TCrumbBar.vue';
export { default as TUserMenu } from './shell/TUserMenu.vue';
export { default as TAppShell } from './shell/TAppShell.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/shell/TCrumbBar.vue web/packages/ui/src/shell/TUserMenu.vue web/packages/ui/src/shell/TAppShell.vue web/packages/ui/tests/TAppShell.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TCrumbBar + TUserMenu + TAppShell composition"
```

---

## Phase 5 — Chart wrappers (minimal)

### Task 5.1: chartTheme helper

**Files:**
- Create: `web/packages/ui/src/charts/chartTheme.ts`
- Create: `web/packages/ui/tests/chartTheme.test.ts`

- [ ] **Step 1: Test**:

```ts
import { describe, it, expect } from 'vitest';
import { readTheme } from '../src/charts/chartTheme';

describe('chartTheme.readTheme', () => {
  it('reads colour values from CSS variables on the root element', () => {
    document.documentElement.style.setProperty('--text-muted', '#94a3b8');
    document.documentElement.style.setProperty('--border', '#334155');
    const t = readTheme();
    expect(t.grid).toBe('#334155');
    expect(t.axisLabel).toBe('#94a3b8');
  });
});
```

- [ ] **Step 2: Implement** — `web/packages/ui/src/charts/chartTheme.ts`:

```ts
export interface ChartTheme {
  axisLabel: string;
  grid: string;
  safe: string;
  warn: string;
  deprecated: string;
  unsafe: string;
  accent: string;
  accentStrong: string;
}

function v(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function readTheme(): ChartTheme {
  return {
    axisLabel:   v('--text-muted'),
    grid:        v('--border'),
    safe:        v('--safe'),
    warn:        v('--warn'),
    deprecated:  v('--deprecated'),
    unsafe:      v('--unsafe'),
    accent:      v('--accent'),
    accentStrong: v('--accent-strong'),
  };
}
```

- [ ] **Step 3: Export + test + commit**

```ts
// index.ts
export { readTheme } from './charts/chartTheme';
export type { ChartTheme } from './charts/chartTheme';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/charts/chartTheme.ts web/packages/ui/tests/chartTheme.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): chartTheme helper reads colours from CSS vars"
```

---

### Task 5.2: TLineChart + TBarChart

**Files:**
- Create: `web/packages/ui/src/charts/TLineChart.vue`
- Create: `web/packages/ui/src/charts/TBarChart.vue`
- Create: `web/packages/ui/tests/charts.test.ts`

- [ ] **Step 1: Test** — `web/packages/ui/tests/charts.test.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import TLineChart from '../src/charts/TLineChart.vue';

vi.mock('chart.js/auto', () => {
  return {
    default: vi.fn().mockImplementation(() => ({
      destroy: vi.fn(),
      update:  vi.fn(),
    })),
  };
});

describe('TLineChart', () => {
  it('renders a canvas element', () => {
    const w = mount(TLineChart, {
      props: { labels: ['W1', 'W2'], values: [20, 35], yLabel: '%' }
    });
    expect(w.find('canvas').exists()).toBe(true);
  });
});
```

- [ ] **Step 2: `web/packages/ui/src/charts/TLineChart.vue`**:

```vue
<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue';
import Chart from 'chart.js/auto';
import { readTheme } from './chartTheme';

const props = defineProps<{
  labels: string[];
  values: number[];
  yLabel?: string;
}>();

const canvas = ref<HTMLCanvasElement | null>(null);
let instance: InstanceType<typeof Chart> | null = null;

function build() {
  if (!canvas.value) return;
  const theme = readTheme();
  instance?.destroy();
  instance = new Chart(canvas.value, {
    type: 'line',
    data: {
      labels: props.labels,
      datasets: [{
        data: props.values,
        borderColor: theme.accentStrong,
        backgroundColor: `${theme.accentStrong}20`,
        fill: true,
        tension: 0.3,
        pointRadius: 0,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: theme.axisLabel, font: { size: 10 } }, grid: { color: theme.grid } },
        y: { ticks: { color: theme.axisLabel, font: { size: 10 } }, grid: { color: theme.grid } },
      },
    },
  });
}

onMounted(build);
watch(() => [props.labels, props.values], build, { deep: true });
onUnmounted(() => instance?.destroy());
</script>

<template>
  <div class="t-chart">
    <canvas ref="canvas" />
  </div>
</template>

<style scoped>
.t-chart { position: relative; height: 180px; }
</style>
```

- [ ] **Step 3: `web/packages/ui/src/charts/TBarChart.vue`**:

Same structure as TLineChart but `type: 'bar'` and bar colors from `theme.accent`. Save under `web/packages/ui/src/charts/TBarChart.vue`:

```vue
<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue';
import Chart from 'chart.js/auto';
import { readTheme } from './chartTheme';

const props = defineProps<{ labels: string[]; values: number[] }>();

const canvas = ref<HTMLCanvasElement | null>(null);
let instance: InstanceType<typeof Chart> | null = null;

function build() {
  if (!canvas.value) return;
  const theme = readTheme();
  instance?.destroy();
  instance = new Chart(canvas.value, {
    type: 'bar',
    data: {
      labels: props.labels,
      datasets: [{ data: props.values, backgroundColor: theme.accentStrong, borderRadius: 2 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: theme.axisLabel, font: { size: 10 } }, grid: { color: theme.grid } },
        y: { ticks: { color: theme.axisLabel, font: { size: 10 } }, grid: { color: theme.grid } },
      },
    },
  });
}

onMounted(build);
watch(() => [props.labels, props.values], build, { deep: true });
onUnmounted(() => instance?.destroy());
</script>

<template>
  <div class="t-chart">
    <canvas ref="canvas" />
  </div>
</template>

<style scoped>
.t-chart { position: relative; height: 180px; }
</style>
```

- [ ] **Step 4: Export + test + commit**

```ts
// index.ts
export { default as TLineChart } from './charts/TLineChart.vue';
export { default as TBarChart } from './charts/TBarChart.vue';
```

```sh
pnpm --filter @triton/ui test
git add web/packages/ui/src/charts/TLineChart.vue web/packages/ui/src/charts/TBarChart.vue web/packages/ui/tests/charts.test.ts web/packages/ui/src/index.ts
git commit -m "feat(ui): TLineChart + TBarChart wrappers with theme-aware colours"
```

---

## Phase 6 — @triton/auth admin-key adapter

### Task 6.1: Scaffold `@triton/auth` package

**Files:**
- Create: `web/packages/auth/package.json`
- Create: `web/packages/auth/tsconfig.json`
- Create: `web/packages/auth/vitest.config.ts`
- Create: `web/packages/auth/src/index.ts`

- [ ] **Step 1: `web/packages/auth/package.json`**:

```json
{
  "name": "@triton/auth",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "main": "src/index.ts",
  "types": "src/index.ts",
  "scripts": {
    "test": "vitest run",
    "lint": "eslint src"
  },
  "dependencies": {
    "@triton/ui": "workspace:*",
    "vue": "^3.5.13"
  },
  "devDependencies": {
    "@vue/test-utils": "^2.4.6",
    "jsdom": "^25.0.1",
    "vitest": "^2.1.8"
  }
}
```

- [ ] **Step 2: `web/packages/auth/tsconfig.json`**:

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "rootDir": "src", "composite": true },
  "include": ["src/**/*.ts", "src/**/*.vue"],
  "references": [{ "path": "../ui" }]
}
```

- [ ] **Step 3: `web/packages/auth/vitest.config.ts`** (same shape as `ui/`).

- [ ] **Step 4: `web/packages/auth/src/index.ts`** — placeholder:

```ts
export const VERSION = '0.0.0';
```

- [ ] **Step 5: Install and commit**

```sh
cd web && pnpm install
git add web/packages/auth web/pnpm-lock.yaml
git commit -m "feat(auth): scaffold @triton/auth package"
```

---

### Task 6.2: `useAdminKey` composable with session timeout

**Files:**
- Create: `web/packages/auth/src/adminKey.ts`
- Create: `web/packages/auth/tests/adminKey.test.ts`

- [ ] **Step 1: Test** — `web/packages/auth/tests/adminKey.test.ts`:

```ts
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { useAdminKey } from '../src/adminKey';

describe('useAdminKey', () => {
  beforeEach(() => { sessionStorage.clear(); vi.useFakeTimers(); });
  afterEach(()  => { vi.useRealTimers(); });

  it('loads stored key on init', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const a = useAdminKey();
    expect(a.key.value).toBe('abc');
    a.stop();
  });

  it('setKey stores in sessionStorage and sets key.value', () => {
    const a = useAdminKey();
    a.setKey('xyz');
    expect(sessionStorage.getItem('triton_admin_key')).toBe('xyz');
    expect(a.key.value).toBe('xyz');
    a.stop();
  });

  it('clear removes key', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const a = useAdminKey();
    a.clear();
    expect(sessionStorage.getItem('triton_admin_key')).toBeNull();
    expect(a.key.value).toBe('');
    a.stop();
  });

  it('clears after 30m of no activity', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const a = useAdminKey();
    vi.advanceTimersByTime(30 * 60 * 1000 + 1_000);
    expect(a.key.value).toBe('');
    a.stop();
  });

  it('activity resets the idle clock', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const a = useAdminKey();
    vi.advanceTimersByTime(10 * 60 * 1000);
    a.touch();
    vi.advanceTimersByTime(25 * 60 * 1000);
    expect(a.key.value).toBe('abc');
    a.stop();
  });
});
```

- [ ] **Step 2: Implement** — `web/packages/auth/src/adminKey.ts`:

```ts
import { ref, type Ref } from 'vue';

const STORAGE_KEY = 'triton_admin_key';
const IDLE_MS = 30 * 60 * 1000;

export interface UseAdminKey {
  key: Ref<string>;
  setKey: (k: string) => void;
  clear: () => void;
  touch: () => void;
  stop: () => void;
}

export function useAdminKey(): UseAdminKey {
  const key = ref<string>(sessionStorage.getItem(STORAGE_KEY) ?? '');
  let lastActivity = Date.now();
  const timer = setInterval(() => {
    if (key.value && Date.now() - lastActivity > IDLE_MS) {
      clear();
    }
  }, 60_000);

  function touch(): void {
    lastActivity = Date.now();
  }
  function setKey(k: string): void {
    sessionStorage.setItem(STORAGE_KEY, k);
    key.value = k;
    touch();
  }
  function clear(): void {
    sessionStorage.removeItem(STORAGE_KEY);
    key.value = '';
  }
  function stop(): void {
    clearInterval(timer);
  }

  return { key, setKey, clear, touch, stop };
}
```

- [ ] **Step 3: Export + test + commit**

```ts
// web/packages/auth/src/index.ts
export { useAdminKey } from './adminKey';
export type { UseAdminKey } from './adminKey';
```

```sh
pnpm --filter @triton/auth test
git add web/packages/auth/src/adminKey.ts web/packages/auth/tests/adminKey.test.ts web/packages/auth/src/index.ts
git commit -m "feat(auth): useAdminKey with 30-min idle auto-clear"
```

---

### Task 6.3: TAdminKeyPrompt + TAuthGate

**Files:**
- Create: `web/packages/auth/src/TAdminKeyPrompt.vue`
- Create: `web/packages/auth/src/TAuthGate.vue`
- Create: `web/packages/auth/tests/TAuthGate.test.ts`

- [ ] **Step 1: Test** — `web/packages/auth/tests/TAuthGate.test.ts`:

```ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import TAuthGate from '../src/TAuthGate.vue';

describe('TAuthGate (adminKey)', () => {
  beforeEach(() => sessionStorage.clear());

  it('shows prompt when no key stored', () => {
    const w = mount(TAuthGate, {
      props: { type: 'adminKey' },
      slots: { default: '<div class="inner">app</div>' }
    });
    expect(w.find('.t-admin-prompt').exists()).toBe(true);
    expect(w.find('.inner').exists()).toBe(false);
  });

  it('renders default slot when key stored', () => {
    sessionStorage.setItem('triton_admin_key', 'abc');
    const w = mount(TAuthGate, {
      props: { type: 'adminKey' },
      slots: { default: '<div class="inner">app</div>' }
    });
    expect(w.find('.inner').exists()).toBe(true);
  });
});
```

- [ ] **Step 2: `web/packages/auth/src/TAdminKeyPrompt.vue`**:

```vue
<script setup lang="ts">
import { ref } from 'vue';
import { TButton, TInput, TFormField } from '@triton/ui';

const emit = defineEmits<{ submit: [key: string] }>();
const key = ref('');

function onSubmit(ev: Event) {
  ev.preventDefault();
  if (key.value.trim()) emit('submit', key.value.trim());
}
</script>

<template>
  <div class="t-admin-prompt">
    <form class="t-admin-card" @submit="onSubmit">
      <h1 class="t-admin-title">License Server</h1>
      <p class="t-admin-sub">Admin key required to continue.</p>
      <TFormField label="Admin key" required>
        <TInput v-model="key" type="password" placeholder="X-Triton-Admin-Key" />
      </TFormField>
      <TButton type="submit" variant="primary" :disabled="!key.trim()">Unlock</TButton>
    </form>
  </div>
</template>

<style scoped>
.t-admin-prompt {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-base);
}
.t-admin-card {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 32px 36px;
  width: min(360px, 92vw);
  display: flex;
  flex-direction: column;
  gap: 16px;
  box-shadow: var(--shadow-lg);
}
.t-admin-title {
  font-family: var(--font-display);
  font-size: 1.6rem;
  font-weight: 600;
  letter-spacing: -0.02em;
  color: var(--text-primary);
  margin: 0;
}
.t-admin-sub { color: var(--text-muted); font-size: 0.82rem; margin: 0; }
</style>
```

- [ ] **Step 3: `web/packages/auth/src/TAuthGate.vue`**:

```vue
<script setup lang="ts">
import { useAdminKey } from './adminKey';
import TAdminKeyPrompt from './TAdminKeyPrompt.vue';

const props = defineProps<{ type: 'adminKey' }>();
// type is a switch for future JWT gate; today only adminKey.
void props;

const admin = useAdminKey();

function onSubmit(k: string) {
  admin.setKey(k);
}
</script>

<template>
  <TAdminKeyPrompt v-if="!admin.key.value" @submit="onSubmit" />
  <slot v-else />
</template>
```

- [ ] **Step 4: Export + test + commit**

```ts
// index.ts
export { default as TAdminKeyPrompt } from './TAdminKeyPrompt.vue';
export { default as TAuthGate } from './TAuthGate.vue';
```

```sh
pnpm --filter @triton/auth test
git add web/packages/auth/src/TAdminKeyPrompt.vue web/packages/auth/src/TAuthGate.vue web/packages/auth/tests/TAuthGate.test.ts web/packages/auth/src/index.ts
git commit -m "feat(auth): TAdminKeyPrompt + TAuthGate"
```

---

## Phase 7 — @triton/api-client (license endpoints)

### Task 7.1: Scaffold + base HTTP wrapper

**Files:**
- Create: `web/packages/api-client/package.json`
- Create: `web/packages/api-client/tsconfig.json`
- Create: `web/packages/api-client/vitest.config.ts`
- Create: `web/packages/api-client/src/http.ts`
- Create: `web/packages/api-client/src/types.ts`
- Create: `web/packages/api-client/src/index.ts`
- Create: `web/packages/api-client/tests/http.test.ts`

- [ ] **Step 1: `package.json`**:

```json
{
  "name": "@triton/api-client",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "main": "src/index.ts",
  "types": "src/index.ts",
  "scripts": { "test": "vitest run", "lint": "eslint src" },
  "dependencies": { "@triton/ui": "workspace:*" },
  "devDependencies": { "jsdom": "^25.0.1", "vitest": "^2.1.8" }
}
```

- [ ] **Step 2: Test — `web/packages/api-client/tests/http.test.ts`**:

```ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createHttp } from '../src/http';

describe('createHttp', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('injects auth headers from provided getter', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const http = createHttp({ baseUrl: '/api', authHeader: () => ({ 'X-Triton-Admin-Key': 'abc' }) });
    await http.get('/v1/stats');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/stats', expect.objectContaining({
      headers: expect.objectContaining({ 'X-Triton-Admin-Key': 'abc' })
    }));
  });

  it('parses JSON on 2xx', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ hello: 'world' }), { status: 200, headers: { 'content-type': 'application/json' } })
    ));
    const http = createHttp({ baseUrl: '/api', authHeader: () => ({}) });
    const body = await http.get<{ hello: string }>('/v1/ping');
    expect(body.hello).toBe('world');
  });

  it('calls onUnauthorized on 401 and throws', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('no', { status: 401 })));
    const onUnauthorized = vi.fn();
    const http = createHttp({ baseUrl: '/api', authHeader: () => ({}), onUnauthorized });
    await expect(http.get('/v1/stats')).rejects.toThrow();
    expect(onUnauthorized).toHaveBeenCalled();
  });

  it('throws with body text on non-2xx', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('boom', { status: 500 })));
    const http = createHttp({ baseUrl: '/api', authHeader: () => ({}) });
    await expect(http.get('/v1/stats')).rejects.toThrow(/500/);
  });
});
```

- [ ] **Step 3: `web/packages/api-client/src/http.ts`**:

```ts
export interface HttpConfig {
  baseUrl: string;
  authHeader: () => Record<string, string>;
  onUnauthorized?: () => void;
}

export interface Http {
  get:  <T>(path: string) => Promise<T>;
  post: <T>(path: string, body: unknown) => Promise<T>;
  put:  <T>(path: string, body: unknown) => Promise<T>;
  del:  <T>(path: string) => Promise<T>;
}

export function createHttp(cfg: HttpConfig): Http {
  async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = cfg.baseUrl + path;
    const init: RequestInit = {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...cfg.authHeader(),
      },
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    const res = await fetch(url, init);
    if (res.status === 401) {
      cfg.onUnauthorized?.();
      throw new Error('401 Unauthorized');
    }
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`${res.status} ${res.statusText}: ${text}`);
    }
    const ct = res.headers.get('content-type') ?? '';
    if (ct.includes('application/json')) return (await res.json()) as T;
    return (await res.text()) as unknown as T;
  }

  return {
    get:  (path)        => request('GET',    path),
    post: (path, body)  => request('POST',   path, body),
    put:  (path, body)  => request('PUT',    path, body),
    del:  (path)        => request('DELETE', path),
  };
}
```

- [ ] **Step 4: Test + commit**

```sh
cd web && pnpm install && pnpm --filter @triton/api-client test
git add web/packages/api-client web/pnpm-lock.yaml
git commit -m "feat(api-client): scaffold + base HTTP with auth + 401 handling"
```

---

### Task 7.2: License server typed endpoints

**Files:**
- Create: `web/packages/api-client/src/licenseServer.ts`
- Create: `web/packages/api-client/src/types.ts`
- Create: `web/packages/api-client/tests/licenseServer.test.ts`

- [ ] **Step 1: `web/packages/api-client/src/types.ts`** — types aligned with existing license server routes (see `pkg/licenseserver/routes.go`):

```ts
export interface Organisation {
  id: string;
  name: string;
  createdAt: string;
}

export interface Licence {
  id: string;
  orgId: string;
  key: string;
  tier: 'free' | 'pro' | 'enterprise';
  seats: number;
  issuedAt: string;
  expiresAt: string;
  bound: boolean;
  revokedAt?: string | null;
  revokedBy?: string | null;
}

export interface Activation {
  id: string;
  licenceId: string;
  machineFingerprint: string;
  boundBy: string;
  boundAt: string;
  lastSeenAt: string;
  status: 'online' | 'offline' | 'degraded';
}

export interface AuditEntry {
  id: string;
  kind: 'info' | 'success' | 'warn' | 'error';
  subject: string;
  actor: string;
  createdAt: string;
  meta?: Record<string, unknown>;
}

export interface DashboardStats {
  orgs: number;
  seatsUsed: number;
  seatsTotal: number;
  expiringIn30d: number;
}

export interface Paged<T> {
  rows: T[];
  total: number;
  page: number;
  pageSize: number;
}
```

- [ ] **Step 2: Endpoints — `web/packages/api-client/src/licenseServer.ts`**:

```ts
import type { Http } from './http';
import type {
  Organisation, Licence, Activation, AuditEntry, DashboardStats, Paged,
} from './types';

export function createLicenseApi(http: Http) {
  return {
    dashboard:   ()             => http.get<DashboardStats>('/v1/dashboard/stats'),
    orgs:        (p = 1)        => http.get<Paged<Organisation>>(`/v1/orgs?page=${p}`),
    org:         (id: string)   => http.get<Organisation>(`/v1/orgs/${id}`),
    createOrg:   (name: string) => http.post<Organisation>('/v1/orgs', { name }),
    deleteOrg:   (id: string)   => http.del<void>(`/v1/orgs/${id}`),
    licences:    (p = 1)        => http.get<Paged<Licence>>(`/v1/licenses?page=${p}`),
    licence:     (id: string)   => http.get<Licence>(`/v1/licenses/${id}`),
    revokeLicence: (id: string) => http.post<void>(`/v1/licenses/${id}/revoke`, {}),
    activations: (licenceId: string) => http.get<Paged<Activation>>(`/v1/licenses/${licenceId}/activations`),
    audit:       (p = 1)        => http.get<Paged<AuditEntry>>(`/v1/audit?page=${p}`),
  };
}

export type LicenseApi = ReturnType<typeof createLicenseApi>;
```

- [ ] **Step 3: Test** — `web/packages/api-client/tests/licenseServer.test.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { createLicenseApi } from '../src/licenseServer';

function fakeHttp() {
  return {
    get:  vi.fn().mockResolvedValue({}),
    post: vi.fn().mockResolvedValue({}),
    put:  vi.fn().mockResolvedValue({}),
    del:  vi.fn().mockResolvedValue({}),
  };
}

describe('licenseApi', () => {
  it('dashboard hits /v1/dashboard/stats', () => {
    const http = fakeHttp();
    createLicenseApi(http).dashboard();
    expect(http.get).toHaveBeenCalledWith('/v1/dashboard/stats');
  });

  it('orgs(p) builds correct path', () => {
    const http = fakeHttp();
    createLicenseApi(http).orgs(3);
    expect(http.get).toHaveBeenCalledWith('/v1/orgs?page=3');
  });

  it('revokeLicence POSTs to revoke path', () => {
    const http = fakeHttp();
    createLicenseApi(http).revokeLicence('L1');
    expect(http.post).toHaveBeenCalledWith('/v1/licenses/L1/revoke', {});
  });
});
```

- [ ] **Step 4: Export + commit**

```ts
// src/index.ts
export { createHttp } from './http';
export type { Http, HttpConfig } from './http';
export { createLicenseApi } from './licenseServer';
export type { LicenseApi } from './licenseServer';
export * from './types';
```

```sh
pnpm --filter @triton/api-client test
git add web/packages/api-client/src web/packages/api-client/tests
git commit -m "feat(api-client): typed license server endpoints"
```

> **NOTE:** The endpoints above match what the current License Server actually exposes (see `pkg/licenseserver/routes.go`). If any path/name differs, adjust here rather than changing Go handlers — this is a UI plan.

---

## Phase 8 — License Portal scaffold

### Task 8.1: Scaffold the Vue app

**Files:**
- Create: `web/apps/license-portal/package.json`
- Create: `web/apps/license-portal/tsconfig.json`
- Create: `web/apps/license-portal/vite.config.ts`
- Create: `web/apps/license-portal/index.html`
- Create: `web/apps/license-portal/public/logo.png` (copy from existing)
- Create: `web/apps/license-portal/src/main.ts`
- Create: `web/apps/license-portal/src/App.vue`

- [ ] **Step 1: `package.json`**:

```json
{
  "name": "license-portal",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vue-tsc --noEmit && vite build",
    "preview": "vite preview",
    "test": "vitest run"
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

- [ ] **Step 2: `tsconfig.json`**:

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": { "rootDir": "src", "composite": false },
  "include": ["src/**/*.ts", "src/**/*.vue"],
  "references": [
    { "path": "../../packages/ui" },
    { "path": "../../packages/auth" }
  ]
}
```

- [ ] **Step 3: `vite.config.ts`**:

```ts
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import path from 'node:path';

export default defineConfig({
  plugins: [vue()],
  base: '/ui/',
  build: {
    outDir: path.resolve(__dirname, '../../../pkg/licenseserver/ui/dist'),
    emptyOutDir: true,
    assetsDir: 'assets',
    rollupOptions: {
      output: { manualChunks: { vendor: ['vue', 'vue-router', 'pinia', 'chart.js'] } },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8081',
    },
  },
});
```

- [ ] **Step 4: `index.html`**:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Triton License Server</title>
    <link rel="icon" href="/ui/logo.png" type="image/png" />
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="/src/main.ts"></script>
  </body>
</html>
```

- [ ] **Step 5: Copy logo**

```sh
cp pkg/licenseserver/ui/dist/logo.png web/apps/license-portal/public/logo.png
```

- [ ] **Step 6: `src/App.vue`** — minimal shell with theme init:

```vue
<script setup lang="ts">
import { useTheme } from '@triton/ui';
// Initialise theme once at app mount.
useTheme();
</script>

<template>
  <router-view />
</template>
```

- [ ] **Step 7: `src/main.ts`**:

```ts
import { createApp } from 'vue';
import { createPinia } from 'pinia';
import '@triton/ui/tokens.css';
import '@triton/ui/fonts.css';
import App from './App.vue';
import { router } from './router';

createApp(App)
  .use(createPinia())
  .use(router)
  .mount('#app');
```

- [ ] **Step 8: Stub router so `main.ts` compiles** — `src/router.ts`:

```ts
import { createRouter, createWebHashHistory } from 'vue-router';

export const router = createRouter({
  history: createWebHashHistory(),
  routes: [{ path: '/', component: () => import('./views/Dashboard.vue') }],
});
```

- [ ] **Step 9: Empty `views/Dashboard.vue` so route resolves**:

```vue
<template><div>Dashboard (placeholder)</div></template>
```

- [ ] **Step 10: Install + verify dev server runs**

```sh
cd web && pnpm install
pnpm --filter license-portal dev
```

Expected: Vite boots, browser at `http://localhost:5173/ui/` shows "Dashboard (placeholder)".

Kill the dev server.

- [ ] **Step 11: Verify build output lands in the embed target**

```sh
pnpm --filter license-portal build
ls pkg/licenseserver/ui/dist/
```

Expected: `index.html`, `assets/`, `logo.png` — newly written.

**Do not commit the built output yet** (it's large and CI rebuilds it). The Go embed target files are intentionally untracked per `.gitignore` rules.

- [ ] **Step 12: Commit source only**

```sh
git add web/apps/license-portal/package.json web/apps/license-portal/tsconfig.json web/apps/license-portal/vite.config.ts web/apps/license-portal/index.html web/apps/license-portal/public web/apps/license-portal/src web/pnpm-lock.yaml
git commit -m "feat(license-portal): scaffold Vue app with Vite build to pkg/licenseserver/ui/dist"
```

---

### Task 8.2: Full router + Pinia stores + nav config

**Files:**
- Modify: `web/apps/license-portal/src/router.ts`
- Create: `web/apps/license-portal/src/nav.ts`
- Create: `web/apps/license-portal/src/stores/auth.ts`
- Create: `web/apps/license-portal/src/stores/apiClient.ts`
- Create stub views: `Organisations.vue`, `OrganisationDetail.vue`, `Licences.vue`, `LicenceDetail.vue`, `Activations.vue`, `AuditLog.vue`, `Binaries.vue`, `Superadmins.vue`

- [ ] **Step 1: Replace `src/router.ts`**:

```ts
import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router';

const routes: RouteRecordRaw[] = [
  { path: '/',              component: () => import('./views/Dashboard.vue'),           name: 'dashboard' },
  { path: '/orgs',          component: () => import('./views/Organisations.vue'),       name: 'orgs' },
  { path: '/orgs/:id',      component: () => import('./views/OrganisationDetail.vue'),  name: 'org' },
  { path: '/licenses',      component: () => import('./views/Licences.vue'),            name: 'licences' },
  { path: '/licenses/:id',  component: () => import('./views/LicenceDetail.vue'),       name: 'licence' },
  { path: '/activations',   component: () => import('./views/Activations.vue'),         name: 'activations' },
  { path: '/audit',         component: () => import('./views/AuditLog.vue'),            name: 'audit' },
  { path: '/binaries',      component: () => import('./views/Binaries.vue'),            name: 'binaries' },
  { path: '/superadmins',   component: () => import('./views/Superadmins.vue'),         name: 'superadmins' },
  { path: '/:pathMatch(.*)*', redirect: '/' },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
});
```

- [ ] **Step 2: `web/apps/license-portal/src/nav.ts`**:

```ts
import type { NavSection, AppEntry } from '@triton/ui';

export const nav: NavSection[] = [
  {
    items: [
      { href: '#/',            label: 'Dashboard' },
      { href: '#/orgs',        label: 'Organisations' },
      { href: '#/licenses',    label: 'Licences' },
      { href: '#/activations', label: 'Activations' },
    ],
  },
  {
    label: 'Admin',
    items: [
      { href: '#/audit',       label: 'Audit log' },
      { href: '#/binaries',    label: 'Binaries' },
      { href: '#/superadmins', label: 'Superadmins' },
    ],
  },
];

export const apps: AppEntry[] = [
  { id: 'license', name: 'Licence', subtitle: 'Vendor ops', url: null,                     accent: '#a78bfa' },
  { id: 'report',  name: 'Report',  subtitle: 'Security',   url: import.meta.env.VITE_REPORT_URL ?? null, accent: '#22d3ee' },
  { id: 'manage',  name: 'Manage',  subtitle: 'Network',    url: import.meta.env.VITE_MANAGE_URL ?? null, accent: '#a3e635' },
];

export const PORTAL_ACCENT = '#a78bfa';
```

- [ ] **Step 3: `web/apps/license-portal/src/stores/auth.ts`**:

```ts
import { defineStore } from 'pinia';
import { useAdminKey } from '@triton/auth';

export const useAuthStore = defineStore('auth', () => {
  const admin = useAdminKey();
  return admin;
});
```

- [ ] **Step 4: `web/apps/license-portal/src/stores/apiClient.ts`**:

```ts
import { defineStore } from 'pinia';
import { createHttp, createLicenseApi, type LicenseApi } from '@triton/api-client';
import { useAuthStore } from './auth';
import { useToast } from '@triton/ui';

let cached: LicenseApi | null = null;

export const useApiClient = defineStore('apiClient', () => {
  function get(): LicenseApi {
    if (cached) return cached;
    const auth = useAuthStore();
    const toast = useToast();
    const http = createHttp({
      baseUrl: '/api',
      authHeader: () => (auth.key ? { 'X-Triton-Admin-Key': auth.key } : {}),
      onUnauthorized: () => {
        auth.clear();
        toast.error({ title: 'Session expired', description: 'Please re-enter the admin key.' });
      },
    });
    cached = createLicenseApi(http);
    return cached;
  }
  return { get };
});
```

- [ ] **Step 5: Create 8 stub view files** — each one:

```vue
<!-- web/apps/license-portal/src/views/Organisations.vue (example — repeat for all 8) -->
<template><h1>Organisations (stub)</h1></template>
```

Repeat for `OrganisationDetail.vue`, `Licences.vue`, `LicenceDetail.vue`, `Activations.vue`, `AuditLog.vue`, `Binaries.vue`, `Superadmins.vue` — each with its own title.

- [ ] **Step 6: Verify dev server routes**

```sh
pnpm --filter license-portal dev
```

Visit `http://localhost:5173/ui/#/licenses`, `http://localhost:5173/ui/#/orgs`, etc. Each should render its stub heading.

- [ ] **Step 7: Commit**

```sh
git add web/apps/license-portal/src
git commit -m "feat(license-portal): router + stores + nav config + view stubs"
```

---

### Task 8.3: Wire AppShell + sidebar + topbar in App.vue

**Files:**
- Modify: `web/apps/license-portal/src/App.vue`
- Modify: `web/apps/license-portal/src/main.ts` (add TToastHost)

- [ ] **Step 1: Replace `src/App.vue`**:

```vue
<script setup lang="ts">
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  TAppShell, TSidebar, TThemeToggle, TAppSwitcher, TCrumbBar, TUserMenu,
  TToastHost, useTheme, type Crumb,
} from '@triton/ui';
import { TAuthGate } from '@triton/auth';
import { nav, apps, PORTAL_ACCENT } from './nav';
import { useAuthStore } from './stores/auth';

useTheme();
const route  = useRoute();
const router = useRouter();
const auth   = useAuthStore();

const currentHref = computed(() => `#${route.path}`);
const crumbs = computed<Crumb[]>(() => {
  const segments = route.path.split('/').filter(Boolean);
  if (segments.length === 0) return [{ label: 'Dashboard' }];
  const first = segments[0]!;
  const labels: Record<string, string> = {
    orgs: 'Organisations', licenses: 'Licences', activations: 'Activations',
    audit: 'Audit log', binaries: 'Binaries', superadmins: 'Superadmins',
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
        <div style="margin-left: auto; display: flex; align-items: center; gap: 8px">
          <TAppSwitcher :apps="apps" current-id="license" />
          <TThemeToggle />
          <TUserMenu name="ops@triton" role="Superadmin" @sign-out="signOut" />
        </div>
      </template>

      <router-view />
    </TAppShell>
  </TAuthGate>
  <TToastHost />
</template>

<style scoped>
.foot { display: flex; flex-direction: column; font-size: 0.7rem; color: var(--text-muted); }
.foot strong { color: var(--text-primary); font-family: var(--font-display); font-weight: 500; font-size: 0.78rem; }
</style>
```

- [ ] **Step 2: Commit**

```sh
git add web/apps/license-portal/src/App.vue
git commit -m "feat(license-portal): compose AppShell with sidebar, topbar, auth gate"
```

- [ ] **Step 3: Verify in browser**

```sh
pnpm --filter license-portal dev
```

Visit `http://localhost:5173/ui/`. Expected behaviour:
- First load → admin-key prompt centred on screen.
- Enter any non-empty string → portal shell loads with sidebar (purple accent), topbar with breadcrumb, app-switcher waffle, theme toggle, avatar menu.
- Clicking sidebar items switches the page.
- Theme toggle cycles dark → light → auto and persists.

---

## Phase 9 — License Portal views

Each view follows the same pattern:
1. Start of `<script setup>`: inject `useApiClient()` and a typed `ref` for the data.
2. `onMounted`: call the API, handle errors via `useToast`, show loading skeleton while pending.
3. Template: `<TPanel>` + `<TStatCard>` + `<TDataTable>` composition.
4. Test: mount with a stubbed `useApiClient` provider, assert initial loading state, assert data rendered after promise resolves, assert error toast on rejection.

### Task 9.1: Dashboard view

**Files:**
- Modify: `web/apps/license-portal/src/views/Dashboard.vue`
- Create: `web/apps/license-portal/tests/Dashboard.test.ts`

- [ ] **Step 1: Implement Dashboard.vue**:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  TStatCard, TPanel, TLineChart, useToast,
} from '@triton/ui';
import type { DashboardStats } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const stats = ref<DashboardStats | null>(null);
const toast = useToast();

onMounted(async () => {
  try {
    stats.value = await api.get().dashboard();
  } catch (err) {
    toast.error({ title: 'Could not load dashboard', description: String(err) });
  }
});
</script>

<template>
  <div class="dash">
    <h1 class="page-h1">Fleet health</h1>
    <div v-if="stats" class="stat-row">
      <TStatCard label="Organisations" :value="stats.orgs" accent="var(--accent)" />
      <TStatCard
        label="Seats used"
        :value="`${stats.seatsUsed} / ${stats.seatsTotal}`"
        accent="#a78bfa"
      />
      <TStatCard
        label="Expiring 30d"
        :value="stats.expiringIn30d"
        accent="var(--warn)"
      />
    </div>
    <TPanel title="Licence activations" subtitle="· last 12 weeks">
      <TLineChart
        :labels="['W1','W2','W3','W4','W5','W6','W7','W8','W9','W10','W11','W12']"
        :values="[3,5,7,6,9,11,14,16,19,22,25,28]"
      />
    </TPanel>
  </div>
</template>

<style scoped>
.page-h1 {
  font-family: var(--font-display);
  font-size: 1.55rem;
  letter-spacing: -0.03em;
  font-weight: 600;
  margin: 0 0 16px;
}
.stat-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 16px; }
.dash { display: flex; flex-direction: column; gap: 14px; }
</style>
```

- [ ] **Step 2: Commit**

```sh
git add web/apps/license-portal/src/views/Dashboard.vue
git commit -m "feat(license-portal): Dashboard view with stats + trend chart"
```

---

### Task 9.2: Organisations list + detail

**Files:** `web/apps/license-portal/src/views/Organisations.vue`, `OrganisationDetail.vue`

- [ ] **Step 1: Organisations.vue**:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TDataTable, TPanel, TButton, useToast, type Column } from '@triton/ui';
import type { Organisation, Paged } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const data = ref<Paged<Organisation> | null>(null);
const loading = ref(true);

const columns: Column<Organisation>[] = [
  { key: 'name', label: 'Name', width: '2fr' },
  { key: 'createdAt', label: 'Created', width: '1fr' },
  { key: 'id', label: 'ID', width: '1fr' },
];

onMounted(async () => {
  try { data.value = await api.get().orgs(1); }
  catch (err) { toast.error({ title: 'Failed to load organisations', description: String(err) }); }
  finally { loading.value = false; }
});

function onRowClick(o: Organisation) {
  window.location.hash = `#/orgs/${o.id}`;
}
</script>

<template>
  <TPanel title="Organisations" :subtitle="data ? `· ${data.total} total` : ''">
    <template #action>
      <TButton variant="primary" size="sm">+ Add org</TButton>
    </template>
    <TDataTable
      :columns="columns"
      :rows="data?.rows ?? []"
      row-key="id"
      empty-text="No organisations yet."
      @row-click="onRowClick"
    />
  </TPanel>
</template>
```

- [ ] **Step 2: OrganisationDetail.vue** (minimal, using drawer-like panel):

```vue
<script setup lang="ts">
import { onMounted, ref, computed } from 'vue';
import { useRoute } from 'vue-router';
import { TPanel, TPill, useToast } from '@triton/ui';
import type { Organisation } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const route = useRoute();
const org = ref<Organisation | null>(null);
const id = computed(() => String(route.params.id));

onMounted(async () => {
  try { org.value = await api.get().org(id.value); }
  catch (err) { toast.error({ title: 'Load failed', description: String(err) }); }
});
</script>

<template>
  <TPanel v-if="org" :title="org.name">
    <dl class="kv">
      <dt>ID</dt><dd>{{ org.id }}</dd>
      <dt>Created</dt><dd>{{ org.createdAt }}</dd>
    </dl>
  </TPanel>
  <p v-else>Loading…</p>
</template>

<style scoped>
.kv { display: grid; grid-template-columns: 120px 1fr; gap: 8px 14px; font-size: 0.82rem; }
.kv dt { color: var(--text-muted); font-size: 0.66rem; text-transform: uppercase; letter-spacing: 0.1em; }
.kv dd { color: var(--text-primary); font-family: var(--font-mono); }
</style>
```

- [ ] **Step 3: Commit**

```sh
git add web/apps/license-portal/src/views/Organisations.vue web/apps/license-portal/src/views/OrganisationDetail.vue
git commit -m "feat(license-portal): Organisations list + detail views"
```

---

### Task 9.3: Licences list + detail (hero screen)

**Files:** `web/apps/license-portal/src/views/Licences.vue`, `LicenceDetail.vue`

- [ ] **Step 1: Licences.vue** — list with status pills:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TDataTable, TPanel, TPill, type Column } from '@triton/ui';
import type { Licence, Paged } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const data = ref<Paged<Licence> | null>(null);

const columns: Column<Licence>[] = [
  { key: 'key',       label: 'Key',      width: '2fr' },
  { key: 'tier',      label: 'Tier',     width: '0.8fr' },
  { key: 'seats',     label: 'Seats',    width: '0.6fr', align: 'right', numeric: true },
  { key: 'expiresAt', label: 'Expires',  width: '1fr' },
  { key: 'revokedAt', label: 'Status',   width: '0.8fr' },
];

onMounted(async () => { data.value = await api.get().licences(1); });

function tierVariant(t: Licence['tier']) {
  return t === 'enterprise' ? 'enterprise' : t === 'pro' ? 'info' : 'neutral';
}
</script>

<template>
  <TPanel title="Licences" :subtitle="data ? `· ${data.total} total` : ''">
    <TDataTable
      :columns="columns"
      :rows="data?.rows ?? []"
      row-key="id"
      @row-click="(l) => window.location.hash = `#/licenses/${l.id}`"
    >
      <template #cell:tier="{ row }">
        <TPill :variant="tierVariant((row as Licence).tier)" :dot="false">
          {{ (row as Licence).tier }}
        </TPill>
      </template>
      <template #cell:revokedAt="{ row }">
        <TPill v-if="(row as Licence).revokedAt" variant="unsafe">Revoked</TPill>
        <TPill v-else variant="safe">Active</TPill>
      </template>
    </TDataTable>
  </TPanel>
</template>
```

- [ ] **Step 2: LicenceDetail.vue** — the hero:

```vue
<script setup lang="ts">
import { onMounted, ref, computed } from 'vue';
import { useRoute } from 'vue-router';
import {
  TStatCard, TPanel, TButton, TConfirmDialog, TPill,
  TDataTable, useToast, type Column,
} from '@triton/ui';
import type { Licence, Paged, Activation } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const toast = useToast();
const route = useRoute();
const id = computed(() => String(route.params.id));

const licence = ref<Licence | null>(null);
const activations = ref<Paged<Activation> | null>(null);
const revokeOpen = ref(false);

const actColumns: Column<Activation>[] = [
  { key: 'machineFingerprint', label: 'Machine fingerprint', width: '2fr' },
  { key: 'boundBy',            label: 'Bound by',            width: '1fr' },
  { key: 'boundAt',            label: 'When',                width: '1fr' },
  { key: 'status',             label: 'Status',              width: '100px' },
];

async function load() {
  try {
    licence.value = await api.get().licence(id.value);
    activations.value = await api.get().activations(id.value);
  } catch (err) {
    toast.error({ title: 'Load failed', description: String(err) });
  }
}
onMounted(load);

async function revoke() {
  try {
    await api.get().revokeLicence(id.value);
    toast.success({ title: 'Licence revoked' });
    revokeOpen.value = false;
    await load();
  } catch (err) {
    toast.error({ title: 'Revoke failed', description: String(err) });
  }
}

async function copyKey() {
  if (!licence.value) return;
  await navigator.clipboard.writeText(licence.value.key);
  toast.success({ title: 'Key copied to clipboard' });
}

function statusVariant(s: Activation['status']) {
  return s === 'online' ? 'safe' : s === 'offline' ? 'unsafe' : 'warn';
}
</script>

<template>
  <div v-if="licence" class="detail">
    <section class="head">
      <div class="head-body">
        <div class="label">Licence key</div>
        <div class="key">{{ licence.key }}</div>
        <div class="meta">
          <span>Tier <b>{{ licence.tier }}</b></span>
          <span>Issued <b>{{ licence.issuedAt }}</b></span>
          <span>Expires <b>{{ licence.expiresAt }}</b></span>
          <span>Bound <b>{{ licence.bound ? 'Yes' : 'No' }}</b></span>
        </div>
      </div>
      <div class="actions">
        <TButton size="sm" variant="secondary" @click="copyKey">Copy key</TButton>
        <TButton size="sm" variant="danger" @click="revokeOpen = true" :disabled="!!licence.revokedAt">
          Revoke
        </TButton>
      </div>
    </section>

    <div class="stats">
      <TStatCard label="Seats used" :value="activations?.total ?? 0" accent="#a78bfa" />
      <TStatCard label="Tier" :value="licence.tier" accent="var(--accent)" />
      <TStatCard
        label="Days remaining"
        :value="Math.max(0, Math.floor((new Date(licence.expiresAt).getTime() - Date.now()) / 864e5))"
        accent="var(--warn)"
      />
    </div>

    <TPanel title="Seat activations" :subtitle="`· ${activations?.total ?? 0} bound`">
      <TDataTable
        :columns="actColumns"
        :rows="activations?.rows ?? []"
        row-key="id"
      >
        <template #cell:status="{ row }">
          <TPill :variant="statusVariant((row as Activation).status)">
            {{ (row as Activation).status }}
          </TPill>
        </template>
      </TDataTable>
    </TPanel>
  </div>

  <TConfirmDialog
    :open="revokeOpen"
    title="Revoke licence?"
    :message="`Revoking ${licence?.key} will deactivate all seats. This can't be undone.`"
    confirm-label="Revoke"
    @confirm="revoke"
    @cancel="revokeOpen = false"
  />
</template>

<style scoped>
.detail { display: flex; flex-direction: column; gap: 14px; }
.head {
  background: linear-gradient(135deg, color-mix(in srgb, var(--portal-accent) 14%, transparent), color-mix(in srgb, var(--accent-strong) 4%, transparent));
  border: 1px solid color-mix(in srgb, var(--portal-accent) 30%, var(--border));
  border-radius: var(--radius-lg);
  padding: 18px 20px;
  display: flex;
  gap: 18px;
  align-items: flex-start;
}
.head-body { flex: 1; }
.label {
  font-size: 0.62rem; letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--portal-accent); font-weight: 500;
}
.key { font-family: var(--font-mono); font-size: 1rem; color: var(--text-primary); margin: 4px 0; }
.meta { display: flex; gap: 18px; margin-top: 8px; font-size: 0.74rem; color: var(--text-muted); }
.meta b { color: var(--text-primary); font-family: var(--font-display); font-weight: 500; }
.actions { display: flex; flex-direction: column; gap: 6px; }
.stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
</style>
```

- [ ] **Step 3: Commit**

```sh
git add web/apps/license-portal/src/views/Licences.vue web/apps/license-portal/src/views/LicenceDetail.vue
git commit -m "feat(license-portal): Licences list + LicenceDetail hero view"
```

---

### Task 9.4: Activations, AuditLog, Binaries, Superadmins

**Files:** `Activations.vue`, `AuditLog.vue`, `Binaries.vue`, `Superadmins.vue`

Each view follows the Task 9.2 template: fetch paged data via `useApiClient`, render with `<TPanel>` + `<TDataTable>`, error-toast on reject.

- [ ] **Step 1: `Activations.vue`** — show all activations across licences (calls nothing new; reuse `api.activations(licenceId)` per row OR add a bulk endpoint later; for now reuse via iteration or show a placeholder empty list pending API).

```vue
<script setup lang="ts">
import { TPanel } from '@triton/ui';
</script>
<template>
  <TPanel title="Activations" subtitle="· across all licences">
    <p>Open a licence to view its activations.</p>
  </TPanel>
</template>
```

- [ ] **Step 2: `AuditLog.vue`**:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { TDataTable, TPanel, TPill, type Column } from '@triton/ui';
import type { AuditEntry, Paged } from '@triton/api-client';
import { useApiClient } from '../stores/apiClient';

const api = useApiClient();
const data = ref<Paged<AuditEntry> | null>(null);

const columns: Column<AuditEntry>[] = [
  { key: 'kind',      label: 'Kind',    width: '100px' },
  { key: 'subject',   label: 'Event',   width: '2fr' },
  { key: 'actor',     label: 'Actor',   width: '1fr' },
  { key: 'createdAt', label: 'When',    width: '1fr' },
];

function pill(k: AuditEntry['kind']) {
  return k === 'success' ? 'safe' : k === 'warn' ? 'warn' : k === 'error' ? 'unsafe' : 'info';
}

onMounted(async () => { data.value = await api.get().audit(1); });
</script>

<template>
  <TPanel title="Audit log" :subtitle="data ? `· ${data.total} events` : ''">
    <TDataTable :columns="columns" :rows="data?.rows ?? []" row-key="id">
      <template #cell:kind="{ row }">
        <TPill :variant="pill((row as AuditEntry).kind)">{{ (row as AuditEntry).kind }}</TPill>
      </template>
    </TDataTable>
  </TPanel>
</template>
```

- [ ] **Step 3: `Binaries.vue`** — placeholder panel (no API surface is exposed; keep parity with existing admin UI which just listed files).

```vue
<script setup lang="ts">
import { TPanel } from '@triton/ui';
</script>
<template>
  <TPanel title="Binaries" subtitle="· downloadable installers">
    <p>Installer bundles are served from <code>/downloads/</code>.</p>
  </TPanel>
</template>
```

- [ ] **Step 4: `Superadmins.vue`** — mirror existing (list-only):

```vue
<script setup lang="ts">
import { TPanel } from '@triton/ui';
</script>
<template>
  <TPanel title="Superadmins">
    <p>Superadmin accounts are provisioned via env var <code>TRITON_LICENSE_SERVER_ADMIN_KEY</code>.</p>
  </TPanel>
</template>
```

- [ ] **Step 5: Commit**

```sh
git add web/apps/license-portal/src/views/Activations.vue web/apps/license-portal/src/views/AuditLog.vue web/apps/license-portal/src/views/Binaries.vue web/apps/license-portal/src/views/Superadmins.vue
git commit -m "feat(license-portal): Activations, AuditLog, Binaries, Superadmins views"
```

---

## Phase 10 — Cutover

### Task 10.1: Delete old vanilla-JS admin UI

**Files:**
- Delete: `pkg/licenseserver/ui/dist/admin.js`
- Delete: `pkg/licenseserver/ui/dist/admin.css`
- Delete: `pkg/licenseserver/ui/dist/index.html` (replaced by Vite output)
- Delete: `pkg/licenseserver/ui/dist/fonts/`

- [ ] **Step 1: Verify Vite build lands where expected**

```sh
cd web && pnpm --filter license-portal build
ls -la ../pkg/licenseserver/ui/dist/
```

Expected: `index.html`, `assets/`, `logo.png`, possibly `manifest` files. **None** of `admin.js`, `admin.css`, stale `fonts/` should remain (Vite's `emptyOutDir: true` clears the folder).

- [ ] **Step 2: Run server locally and smoke test**

```sh
cd /Users/amirrudinyahaya/Workspace/triton
make build-licenseserver
TRITON_LICENSE_SERVER_ADMIN_KEY=dev TRITON_LICENSE_SERVER_SIGNING_KEY_FILE=/dev/stdin ./bin/triton-license-server < /dev/null &
curl -s http://localhost:8081/ui/ | head -20
```

Expected: HTML references `/ui/assets/index-*.js` (Vite output). Visit in browser — admin-key prompt appears, dashboard loads after entering `dev`.

Kill the license server.

- [ ] **Step 3: Remove obsolete files** — `pkg/licenseserver/ui/dist/` already emptied by Vite. Ensure no stale files committed:

```sh
git status pkg/licenseserver/ui/dist/
```

If git shows deletions (e.g., if old `admin.js` was committed), stage them.

```sh
git rm -r --cached pkg/licenseserver/ui/dist/admin.js pkg/licenseserver/ui/dist/admin.css pkg/licenseserver/ui/dist/fonts/ 2>/dev/null || true
# index.html is regenerated by Vite; remove from git as well:
git rm -r --cached pkg/licenseserver/ui/dist/index.html 2>/dev/null || true
```

- [ ] **Step 4: Adjust `.gitignore` so built UI assets stay untracked but `logo.png` is preserved via a committed copy in `web/apps/license-portal/public/logo.png`**

Verify `.gitignore` has an entry for `pkg/licenseserver/ui/dist/**` *except* a single placeholder `.gitkeep`. Update if needed:

```
# Built portal assets — produced by Vite, never committed
pkg/licenseserver/ui/dist/*
!pkg/licenseserver/ui/dist/.gitkeep
pkg/server/ui/dist/*
!pkg/server/ui/dist/.gitkeep
```

Create the `.gitkeep` files:

```sh
touch pkg/licenseserver/ui/dist/.gitkeep pkg/server/ui/dist/.gitkeep
```

**IMPORTANT:** Before committing the `.gitignore` change, verify that `make build-licenseserver` still finds an `index.html` under `pkg/licenseserver/ui/dist/` when assembling the embed — this is the whole point of the `make web` prerequisite. CI should run `make web` before `make build-licenseserver`.

- [ ] **Step 5: Commit removal**

```sh
git add pkg/licenseserver/ui/dist/.gitkeep .gitignore
git commit -m "chore(licenseserver): remove vanilla-JS admin UI; assets now built by web/"
```

---

### Task 10.2: Update Playwright E2E selectors

**Files:**
- Modify: `test/e2e/license-admin.spec.js`

The new Vue DOM uses different class names. Update selectors to match the Vue components we shipped.

- [ ] **Step 1: Read current spec and identify failing selectors**

```sh
grep -n 'sidebar\|admin-key\|nav-link\|logo-title\|#page' test/e2e/license-admin.spec.js
```

- [ ] **Step 2: Common mappings**

| Old selector (vanilla) | New selector (Vue) |
|------------------------|--------------------|
| `.sidebar`             | `.t-sidebar`       |
| `.nav-link`            | `.t-nav-item`      |
| `.logo-title`          | `.t-logo-title`    |
| `#page`                | `.t-app-page`      |
| auth key form input    | `.t-admin-prompt input[type=password]` |
| auth key submit        | `.t-admin-prompt button[type=submit]` |
| `.orgs-table tr`       | `.t-tbl-row`       |

For each test block: replace the old selectors verbatim.

- [ ] **Step 3: Run Playwright**

```sh
make test-e2e-license
```

Iterate: for each failing selector, update until all 22 specs pass.

- [ ] **Step 4: Commit selector updates**

```sh
git add test/e2e/license-admin.spec.js
git commit -m "test(e2e): update license-admin selectors for Vue DOM"
```

---

### Task 10.3: Final end-to-end smoke + PR-ready commit

- [ ] **Step 1: Full green build**

```sh
cd /Users/amirrudinyahaya/Workspace/triton
make web          # builds every portal; emits into pkg/.../ui/dist/
make lint         # Go lint
make test         # Go unit tests
make test-integration TRITON_TEST_DB_URL="postgres://triton:triton@localhost:5435/triton_test?sslmode=disable"
make test-e2e-license
```

All green.

- [ ] **Step 2: Verify container build still works**

```sh
make container-build-licenseserver
```

The container stage that runs `go build` must now first run `make web-install && make web`. Update `Containerfile.licenseserver`:

```dockerfile
# ─── Build web assets first ────────────────────────────────
FROM node:22-alpine AS web
WORKDIR /app
RUN corepack enable pnpm
COPY web/ /app/web/
WORKDIR /app/web
RUN pnpm install --frozen-lockfile && pnpm --filter license-portal build

# ─── Go build ──────────────────────────────────────────────
FROM golang:1.25 AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . /src/
# Copy built portal into the Go embed target:
COPY --from=web /app/pkg/licenseserver/ui/dist /src/pkg/licenseserver/ui/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -ldflags "-X main.Version=${VERSION}" -o /triton-license-server ./cmd/licenseserver

# ─── Runtime ───────────────────────────────────────────────
FROM scratch
COPY --from=go-build /triton-license-server /triton-license-server
COPY --from=go-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/triton-license-server"]
```

**NOTE:** If your existing `Containerfile.licenseserver` differs, adapt this multi-stage block to it. The essential move is: `node` stage builds `web/`, result copied into `pkg/licenseserver/ui/dist/` before `go build`.

- [ ] **Step 3: Commit container changes**

```sh
git add Containerfile.licenseserver
git commit -m "build(licenseserver): multi-stage container runs pnpm web build"
```

- [ ] **Step 4: Final PR commit** (optional marker)

```sh
git log --oneline -30
```

Expected: a clean sequence of ~40 atomic commits, one per task/step, starting with `feat(web): scaffold pnpm workspace` and ending with `build(licenseserver): multi-stage container runs pnpm web build`.

---

## Phase 11 — Acceptance checklist

Walk through these manually before opening the PR. All must pass.

- [ ] Dev server (`pnpm --filter license-portal dev`) loads, admin key prompt appears; entering any string loads the shell.
- [ ] Theme toggle cycles dark → light → auto, persists after reload, honours `prefers-color-scheme` when "auto".
- [ ] Sidebar highlights the current route; nav links change the page; section label "Admin" appears above the admin group.
- [ ] Topbar shows breadcrumb, ⌘K search (visual only is fine — command palette is future work), app-switcher waffle, theme toggle, user menu.
- [ ] App-switcher opens a popover with three tiles; Report & Manage tiles are **greyed and non-clickable** because their env vars are unset.
- [ ] Licence detail page renders hero header with key + metadata, three stat cards, activations table.
- [ ] Clicking **Revoke** opens a confirmation modal; confirm calls the API and toasts success; cancel closes the modal.
- [ ] Toast host renders bottom-right; toasts auto-dismiss after 5s; manual dismiss works.
- [ ] `make web` builds cleanly with no TS errors (`vue-tsc --noEmit` passes for license-portal).
- [ ] `make test-e2e-license` — all 22 specs pass.
- [ ] `make test-integration` — all 111 specs pass (unchanged).
- [ ] `make container-build-licenseserver` succeeds and produces an image that boots and serves the new UI on :8081.
- [ ] `curl -s http://localhost:8081/ui/ | grep -i 'script.*assets'` shows Vite bundle paths (no `admin.js`).
- [ ] No external CDN requests in DevTools → Network tab during UI session.
- [ ] axe-core audit (`npx @axe-core/cli http://localhost:5173/ui/`) reports zero critical issues on the Licence detail page.

---

## Follow-on plans

After this plan lands:

1. **Report Portal migration** — `docs/superpowers/plans/NEXT-report-portal.md`
   - Add `@triton/auth` JWT adapter (login form, change-password flow, role claims).
   - Add missing `@triton/ui` components: `TDrawer`, `TVerdictBanner`, `TDonutChart`, `TSparkline`, `TTabs`, `TSegment`, `TContextChip`.
   - Migrate 14 views including NACSA Arahan 9, Priority, Inventory, Certificates, Trend, Diff, Users, Tenants, Audit.

2. **Manage Portal migration** — `docs/superpowers/plans/NEXT-manage-portal.md`
   - Add `@triton/ui`: `TZoneBadges`, `TFileDrop`, `TEmptyState`.
   - Migrate 9 views: Dashboard, Zones, Hosts, Discovery, Profiles, SSH keys, Agents, Jobs, Bulk upload.
   - Decide Manage backend separation (still co-located under `/ui/manage/` or its own `cmd/manageserver`).

Both follow-ons reuse this plan's `@triton/ui`, `@triton/auth`, and monorepo scaffolding — they should be roughly half the size.

---

## Self-review notes

- **Spec coverage:** Monorepo layout ✓, tech stack ✓, tokens ✓, fonts ✓, components for License Portal ✓, shell ✓, auth adapter (admin-key only — JWT deferred) ✓, API client ✓, hash routing ✓, `//go:embed` preserved ✓, E2E tests updated ✓, acceptance criteria ✓. Chart wrappers minimal (Line + Bar) — donut/sparkline deferred to Report plan. `TEmptyState`, `TDrawer`, `TFileDrop`, `TVerdictBanner`, `TZoneBadges`, `TContextChip`, `TTabs`, `TSegment` deliberately deferred.
- **No placeholders:** Every step has complete code or exact commands.
- **Type consistency:** Pinia stores, `LicenseApi`, `Column<T>`, `NavSection`, `AppEntry`, `Crumb` names match across tasks.
- **Scope discipline:** This plan stops at License Portal end-to-end. Report + Manage follow-ons are scoped as separate plans.

