# Manage Server Password Change — Design

> **Status:** Approved 2026-04-21 (brainstorm transcript). Targets the literal-blocker gap surfaced after PR C: users created via `POST /api/v1/admin/users` are flagged `must_change_pw=true` and have no UI path to change their password.

## 1. Problem

`POST /api/v1/admin/users` creates new users with `must_change_pw=true` and returns a temporary password (shown once, in a `TCodeBlock`). On first login those users get a JWT carrying `mustChangePassword=true` — but there is no `/api/v1/auth/change-password` endpoint on Manage Server, and no `ChangePassword.vue` view in the portal. Forced-change users can log in but cannot proceed; they are softlocked. Voluntary password rotation is also impossible.

This design ships the missing endpoint + view + route + guard + menu entry as one small focused PR.

### Goals

- New backend endpoint `POST /api/v1/auth/change-password` mirroring Report Server's existing implementation (`pkg/server/handlers_auth.go::handleChangePassword`, lines 325–426).
- New manage-portal view `ChangePassword.vue` reachable from two paths: forced-change after login, and voluntary "Change password" from the user menu.
- Route guard pushes `mustChangePassword=true` sessions to the change-password view on every navigation until they comply.
- 80%+ test coverage on both backend handler and frontend view.

### Non-goals

- Password strength meter / zxcvbn integration. The existing `validatePassword` policy (≥12 chars + must contain digit) is the bar.
- Password reset / forgot-password flow. Out of scope; tracked as a separate gap.
- Per-user password history (no "can't reuse last N passwords" check).
- 2FA / MFA. Separate ticket.
- Admin-initiated password reset for other users. Different flow; the admin already has `POST /admin/users` to create a new account or reset by deleting + recreating.

## 2. Decisions captured from brainstorm

| # | Decision | Choice |
|---|---|---|
| 1 | Scope | (b) Forced + voluntary — both paths hit the same endpoint + same view |

## 3. Architecture

```
Forced path:                         Voluntary path:
  /auth/login                          (any logged-in route)
       ↓                                    ↓
  setToken(jwt)                       click "Change password"
       ↓                              in TUserMenu
  router.beforeEach                        ↓
       ↓                              router.push('/auth/change-password')
  mustChangePassword=true                  ↓
       ↓                              ChangePassword.vue
  redirect to /auth/change-password        ↓
       ↓                              POST /api/v1/auth/change-password
  ChangePassword.vue                       ↓
       ↓                              setToken(new jwt — mcp=false)
  POST /api/v1/auth/change-password        ↓
       ↓                              router.push('/dashboard')
  setToken(new jwt — mcp=false)
       ↓
  router.push('/dashboard')
```

Both paths converge on the same endpoint + view. The only difference is who triggered the navigation (the guard vs the menu).

## 4. Backend

### 4.1 Endpoint

**Route:** `POST /api/v1/auth/change-password`. Mounted inside the existing `/api/v1/auth` chi group (gated by `requireOperational`). The handler reads `Authorization: Bearer <jwt>` itself rather than going through `jwtAuth` middleware, because the standard middleware path may be tightened later to reject `must_change_pw=true` users from non-change-password routes — the change-password endpoint must remain reachable.

**Request body:**
```json
{ "current": "<plaintext>", "next": "<plaintext>" }
```

**Response 200:**
```json
{
  "token": "<new-jwt>",
  "expires_at": "2026-04-22T03:14:15Z",
  "must_change_password": false
}
```

**Error responses:**
| Status | Cause |
|---|---|
| 400 | Missing `current` or `next`; `next` fails `validatePassword` policy; `next == current` |
| 401 | Missing/invalid Authorization header; current password mismatch |
| 500 | Internal (hash, DB) — sanitised body "internal server error" |

### 4.2 Implementation notes

File: `pkg/manageserver/handlers_auth.go` gains `handleChangePassword`.

Flow:
1. Extract bearer token; reject 401 if absent.
2. `parseJWT(token, s.cfg.JWTSigningKey)` → claims; reject 401 on parse error.
3. `s.store.GetSessionByTokenHash(hashToken(token))` to verify session is live; reject 401 on `ErrNotFound`.
4. `s.store.GetUserByID(claims.Sub)` for the live user record.
5. Decode JSON body (`http.MaxBytesReader(w, r.Body, limits.MaxRequestBody)` per the established pattern). Reject 400 if either field empty.
6. Reject 400 if `next == current` ("new password must differ from current").
7. `validatePassword(next)` — reject 400 with the validator's message on policy fail.
8. `VerifyPassword(user.PasswordHash, current)` — reject 401 on mismatch ("current password incorrect").
9. `HashPassword(next)` → `s.store.UpdatePassword(ctx, user.ID, hash)`. The store method already atomically clears `must_change_pw`.
10. **Session rotation** — delete the old session via `s.store.DeleteSession(ctx, sessionID)`, mint a fresh JWT with the same claims minus `mcp`, persist a new session row. The delete-then-mint dance prevents the old token from being usable after the password change (defence-in-depth: even though the password is what authenticates re-login, the old JWT keeps working until natural expiry without rotation).
11. Respond 200 with `{token, expires_at, must_change_password: false}`.

### 4.3 What already exists

| Piece | Location | Status |
|---|---|---|
| `validatePassword(p string) error` | `pkg/manageserver/handlers_setup.go` | Reuse |
| `HashPassword(p string) (string, error)` | `pkg/manageserver/auth.go` | Reuse |
| `VerifyPassword(hash, plain string) error` | `pkg/manageserver/auth.go` | Reuse |
| `Store.UpdatePassword(ctx, id, hash)` | `pkg/managestore/postgres.go` | Reuse — already clears `must_change_pw` |
| JWT mint + session insert helpers | `pkg/manageserver/handlers_auth.go` (used by `handleLogin`) | Reuse — extract a helper if needed |
| `Store.DeleteSession(ctx, id)` | `pkg/managestore/postgres.go` | Verify exists; if not, add as part of this PR |
| `MaxRequestBody` constant | `pkg/manageserver/internal/limits/limits.go` | Reuse |

### 4.4 Reference implementation

`pkg/server/handlers_auth.go::handleChangePassword` (lines ~325–426) — Report Server has the same flow today. Fork verbatim with these substitutions:
- `pkg/server` → `pkg/manageserver`
- `model.User` → `managestore.ManageUser`
- `mustChangePassword` JSON key → `must_change_password` (manage uses snake_case throughout per Batch B convention)
- Use `validatePassword` from `handlers_setup.go` (Manage's policy: ≥12 chars + must contain digit). Report has its own.

## 5. Frontend

### 5.1 api-client method

File: `web/packages/api-client/src/manageServer.ts`. Append to the factory:

```ts
changePassword: (req: { current: string; next: string }) =>
  http.post<ManageLoginResp>('/v1/auth/change-password', req),
```

No new types. Reuses `ManageLoginResp` (already exported).

### 5.2 ChangePassword.vue

File: `web/apps/manage-portal/src/views/ChangePassword.vue`.

Standalone layout (no AppShell wrapper — same pattern as SetupAdmin / SetupLicense). Three `TInput type="password"` fields:

- **Current password**
- **New password** (≥ 12 chars, must contain a digit — inline help text)
- **Confirm new password**

Client-side validations (non-blocking until submit):
- `next.length >= 12`
- `/[0-9]/.test(next)`
- `next === confirm`
- `next !== current`

Submit button is disabled until all four pass. On click:
1. Call `api.get().changePassword({ current, next })`.
2. On 200: `auth.setToken(resp.token)` → `toast.success({ title: 'Password changed' })` → `router.push('/dashboard')`.
3. On 401: `toast.error({ title: 'Current password incorrect' })`. Form stays mounted; current field clears.
4. On 400: surface server message inline (the validator might catch a policy nuance the client missed).
5. On 500: `toast.error({ title: 'Failed', description: 'Try again' })`.

Show a small "First-time login? You must set a new password before continuing." banner when `auth.claims.value?.mustChangePassword === true` to soften the forced-change UX.

### 5.3 Router entry

File: `web/apps/manage-portal/src/router.ts`. Append:

```ts
{ path: '/auth/change-password', name: 'changePassword', component: () => import('./views/ChangePassword.vue') },
```

### 5.4 Route guard extension

In the same `router.ts` `router.beforeEach`, after the existing setup-required block:

```ts
// Forced-change: after login, if must_change_password is true, redirect
// to /auth/change-password and trap the user there until they comply.
const authed = Boolean(auth.token) && !auth.isExpired;
if (authed && auth.claims?.mustChangePassword) {
  if (to.path === '/auth/change-password') return true;
  return { path: '/auth/change-password' };
}
```

### 5.5 TUserMenu integration

File: `web/apps/manage-portal/src/App.vue`.

Inspect `web/packages/ui/src/shell/TUserMenu.vue` for its existing slot/event API. If it already supports an injected menu item via slot, use that. If not, attach an additional `<button>` adjacent to the menu (no need to extend `@triton/ui` for one item). Wire to `router.push('/auth/change-password')`.

If the cleanest path requires extending `TUserMenu` to accept a custom items array, do it as part of this PR — small additive change, no breakage to existing consumers (license-portal + report-portal don't pass the new prop, behaviour unchanged).

### 5.6 App.vue: setup-route bypass

`App.vue` already special-cases `route.path.startsWith('/setup/')` to render the bare router-view (no AppShell, no TAuthGate). Extend that condition to also bypass the shell for `/auth/change-password`:

```vue
<template v-if="route.path.startsWith('/setup/') || route.path === '/auth/change-password'">
  <router-view />
</template>
```

Reason: the change-password view shouldn't be cluttered by the sidebar/topbar on the forced-change path (when the user has nowhere else to go). Voluntary-change users still see the full shell on their way back to /dashboard after submitting.

## 6. Testing

### 6.1 Backend unit tests

File: `pkg/manageserver/handlers_auth_test.go` (existing — append).

| Test | Scenario | Assertion |
|---|---|---|
| `TestChangePassword_HappyPath` | valid current + policy-compliant next | 200, response carries new JWT, `must_change_password=false`, DB row updated, old session deleted |
| `TestChangePassword_WrongCurrent` | current password doesn't match bcrypt | 401, body "current password incorrect" |
| `TestChangePassword_PolicyFail_TooShort` | next < 12 chars | 400, body mentions "12 characters" |
| `TestChangePassword_PolicyFail_NoDigit` | next has no digit | 400, body mentions "digit" |
| `TestChangePassword_SameAsCurrent` | next == current | 400, body "new password must differ from current" |
| `TestChangePassword_MissingFields` | empty current or next | 400 |
| `TestChangePassword_NoAuthHeader` | no Bearer token | 401 |
| `TestChangePassword_ExpiredToken` | JWT exp in past | 401 |
| `TestChangePassword_OldTokenInvalidatedAfterSuccess` | use old token after successful change | 401 (session deleted) |

### 6.2 Frontend component tests

File: `web/apps/manage-portal/tests/views/ChangePassword.spec.ts`.

| Test | Scenario | Assertion |
|---|---|---|
| renders the three password fields + banner when `mustChangePassword=true` | initial mount with forced-change JWT | banner text visible, three inputs present |
| Submit button disabled until validations pass | empty / short / no-digit / mismatched confirm | button has `disabled` attr |
| Happy path | valid inputs | `api.changePassword` called with body, `setToken` called with new token, `router.push('/dashboard')` called |
| 401 on wrong current | `api.changePassword` rejects with `Error('401 ...')` | error toast fired, form stays mounted, no token update |
| Same-as-current rejected client-side | next == current | submit button disabled with inline error |

### 6.3 Guard test extension

File: `web/apps/manage-portal/tests/guards.spec.ts`. Add one case:

| Test | Scenario | Assertion |
|---|---|---|
| `mustChangePassword=true session redirected to /auth/change-password` | JWT with `mcp=true` claim, navigate to `/dashboard` | router.currentRoute.fullPath === '/auth/change-password' |

### 6.4 What's explicitly excluded

- E2E browser test (no Playwright in this PR).
- Voluntary-change UX from TUserMenu doesn't get a dedicated test — the route guard test + happy-path component test cover both forced and voluntary equivalently.

## 7. Acceptance criteria

- [ ] `POST /api/v1/auth/change-password` exists and behaves per §4.
- [ ] All 9 backend tests pass.
- [ ] `ChangePassword.vue` exists, routable, and styled like Setup* views.
- [ ] All 5 frontend component tests pass.
- [ ] Guard test asserts forced-change redirect works.
- [ ] TUserMenu has a "Change password" item that routes to `/auth/change-password`.
- [ ] Manual: create a new user via `/admin/users` → log in as that user → land on change-password view → submit valid new password → land on dashboard with new JWT.
- [ ] Manual: voluntary path — logged-in admin clicks user menu → "Change password" → submit → toast + dashboard.
- [ ] `pnpm --filter manage-portal build` clean; `pnpm --filter manage-portal test` green; `go build ./...` + `go vet ./...` + `golangci-lint run ./...` clean.

## 8. Known deferrals / follow-ups

- **Password strength meter / zxcvbn** — UI nicety; does not block.
- **Password history (N-prior reuse check)** — security hardening; does not block.
- **Forgot-password / reset flow** — separate ticket; this PR only handles users who already know their current password (or temp password).
- **Admin-initiated password reset for another user** — workaround today is to delete the user via DB then recreate via `POST /admin/users`. Real flow is a separate `POST /admin/users/{id}/reset-password` endpoint.

## 9. Risks / collision surface

- **`TUserMenu` extension** (if needed) is the only change to `@triton/ui`. Backward-compatible — existing consumers won't break since the new prop is optional.
- **Route guard extension** runs on every navigation. Already gates by `auth.token` + `claims.mustChangePassword` cheaply (no DB calls in the guard). No performance impact.
- **Session rotation** in the backend handler must be transactional to avoid a window where neither the old nor the new session is queryable. If `DeleteSession` + `CreateSession` aren't already transactional in `managestore`, wrap them in a single tx.
- **Backwards-compat:** existing users with `must_change_pw=false` are unaffected.
