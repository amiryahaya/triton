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
