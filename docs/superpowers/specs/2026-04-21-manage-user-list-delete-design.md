# Manage Server — User List + Delete Design

> **Status:** Approved 2026-04-21 (brainstorm transcript). Smallest item on the post-#88 gap list — user CRUD currently ships create-only. This design closes list + delete.

## 1. Problem

After PR #88 merged the Manage Portal hardening sprint, the Users view (`web/apps/manage-portal/src/views/Users.vue`) is wired to a Pinia store (`useUsersStore`) that expects two things the backend does not provide:

1. A `GET /api/v1/admin/users` endpoint for the list table (`users.items`).
2. A `DELETE /api/v1/admin/users/{id}` endpoint for the not-yet-shipped delete action.

Today the portal renders the list against a store whose `fetch()` call returns nothing useful (no handler registered), so the "No users yet" empty state is permanent — even after the admin creates users via the existing `POST /api/v1/admin/users` flow. The admin can add users but not see them or remove them.

This design ships both endpoints and the accompanying UI affordance. Scope is deliberately minimal — no edit, no role change, no password reset. Those are follow-up items on the gap list.

### Goals

- `GET /api/v1/admin/users` returns the full user list (array), newest first.
- `DELETE /api/v1/admin/users/{id}` removes a user, with guardrails against self-delete and last-admin removal.
- Users.vue gains a delete button per row (hidden on the caller's own row for UX) + confirm dialog.
- Cascade: deleting a user must also cancel the user's active JWT sessions. Achieved for free via the existing `manage_sessions.user_id ... ON DELETE CASCADE` foreign key (see `pkg/managestore/migrations.go:21`).
- Full CI green (lint / unit / integration / web build + test).

### Non-goals

- **User edit / role update / re-issue temp password.** Separate S-tier follow-up.
- **Audit trail.** The broader audit log is an M-tier item; once it lands, user lifecycle events slot in behind the same `WriteAudit` helper. No audit placeholders in this PR.
- **Session invalidation signalling beyond cascade.** JWTs are stateless; our invalidation path is session-row removal. After the cascade, the next authenticated request from the deleted user's token returns 401 via the existing session-lookup check in `jwtAuth`. Nothing else is needed.
- **Pagination.** Seat caps mean user count stays small (typically <50). A plain array response is sufficient.
- **API-surface changes to `POST /admin/users`.** Untouched.

## 2. Decisions captured from brainstorm

| # | Decision | Choice |
|---|---|---|
| 1 | Delete guardrails | (c) Both: self-delete prevention AND last-admin prevention |
| 2 | Session invalidation mechanism | (c) Cascade via existing ON DELETE CASCADE on `manage_sessions.user_id` |
| 3 | Delete confirmation UX | (a) Simple "Delete user {email}? This cannot be undone." dialog, matching zone/host pattern from PR #88 |

## 3. Architecture

All changes sit inside the already-established Manage Server patterns. No new packages, no new routes beyond the two listed.

| Layer | Files touched |
|---|---|
| Store | `pkg/managestore/store.go` (interface additions), `pkg/managestore/postgres.go` (three new methods), `pkg/managestore/postgres_test.go` (three new test funcs) |
| Handler | `pkg/manageserver/handlers_users.go` (append two handlers), `pkg/manageserver/handlers_users_test.go` (append test cases), `pkg/manageserver/server.go` (two route mounts) |
| Shared types | `web/packages/api-client/src/manageServer.types.ts` (no additions — `ManageUser` already defined), `web/packages/api-client/src/manageServer.ts` (two new factory methods), `web/packages/api-client/tests/manageServer.test.ts` (two new test cases) |
| Portal store | `web/apps/manage-portal/src/stores/users.ts` (add `remove(id)` action + state update on success) |
| Portal view | `web/apps/manage-portal/src/views/Users.vue` (new Actions column + delete button + confirm dialog), `web/apps/manage-portal/tests/views/Users.spec.ts` (append delete-flow tests) |

Total: ~8 files touched, ~300–350 LOC net (mostly tests).

### Contract details

`GET /api/v1/admin/users`

Response body:
```json
[
  {
    "id": "019e0c36-ea9f-7f1d-9d4a-0123456789ab",
    "email": "admin@example.com",
    "name": "Admin One",
    "role": "admin",
    "must_change_pw": false,
    "created_at": "2026-04-19T10:00:00Z"
  },
  …
]
```

- Ordering: `ORDER BY created_at DESC`. Stable identifier tie-break on `id DESC`.
- `password_hash` is never serialized. The store returns `*ManageUser` with the field populated; the handler constructs a DTO that omits it. Explicit DTO (not `json:"-"` on the store type) keeps the store type safe for callers that need the hash (auth).
- Status codes: 200 on success. 500 on DB error. No 403 path — upstream `RequireRole("admin")` already 403s non-admins before the handler runs.

`DELETE /api/v1/admin/users/{id}`

- 204 on success (no body).
- 400 if `{id}` is not a valid UUID.
- 403 if `{id}` equals the caller's JWT `sub` claim (self-delete prevention). Body: `{"error": "cannot delete your own account"}`.
- 404 if the user does not exist.
- 409 if the target user's role is `admin` and deleting them would drop the active-admin count to zero (last-admin prevention). Body: `{"error": "cannot delete the last admin"}`.
- 500 on DB error.

Handler logic:
1. Parse `{id}` from URL. On bad UUID → 400.
2. Read `caller = orgctx.FromContext(r).UserID` (populated by `jwtAuth`). If `caller == id` → 403.
3. `target := s.store.GetUserByID(r.Context(), id)`. If `ErrNotFound` → 404.
4. If `target.Role == "admin"`: `n := s.store.CountAdmins(r.Context())`. If `n <= 1` → 409.
5. `s.store.DeleteUser(r.Context(), id)`. Errors → 500.
6. 204 No Content.

The self-delete check runs *before* the DB read because it's cheaper and the caller always exists (JWT was validated upstream).

The last-admin check happens *after* the existence check because a caller trying to delete a non-existent admin should get 404, not 409. Order matters for test stability.

### Store methods

Appended to `managestore.Store` interface:
- `ListUsers(ctx context.Context) ([]*ManageUser, error)`
- `GetUserByID(ctx context.Context, id string) (*ManageUser, error)` — returns `*ErrNotFound` on miss
- `CountAdmins(ctx context.Context) (int, error)`
- `DeleteUser(ctx context.Context, id string) error`

The `GetUserByID` method is new; the existing `GetUser(email)` lookup is by email. Adding an ID-keyed lookup is necessary for the delete path (the URL gives us an ID, not an email).

### Frontend details

`Users.vue` (already exists, extend):

- New `actions` column at the end of the table. TButton with variant `danger` (or `ghost` + red icon class — to decide during implementation based on `@triton/ui` affordances; the hardening sprint pattern used variant + title tooltip).
- `v-if` on the delete button: `row.id !== auth.claims?.sub` — hides it on the caller's own row. The backend still enforces 403 in case someone crafts an API call.
- Click opens a `TConfirmDialog` (already used for zone/host deletes in PR #88, see `web/packages/ui/src/TConfirmDialog.vue`). Message: `Delete user ${email}? This cannot be undone.` Confirm calls `users.remove(id)`.
- On success: toast success `User deleted` + the store has already removed the row locally. No refetch needed.
- On 409 from backend: toast error with server message (`cannot delete the last admin`). Similarly for 403 (`cannot delete your own account`).

`stores/users.ts` `remove` action:
```ts
async function remove(id: string) {
  await useApiClient().get().deleteUser(id);
  items.value = items.value.filter((u) => u.id !== id);
}
```

No loading flag needed — the button can be disabled during the `await` via local component state.

## 4. Testing strategy

**Backend — TDD, red → green → refactor per method.**

Store tests in `pkg/managestore/postgres_test.go` (integration, requires Postgres):
1. `TestListUsers_ReturnsAllOrderedByCreatedAtDesc` — insert 3 users with distinct `created_at`, assert order + shape.
2. `TestGetUserByID_ReturnsNotFoundWhenMissing` — call with random UUID, assert `*ErrNotFound` via `errors.As`.
3. `TestCountAdmins_ReflectsRoleColumn` — 2 admins + 1 engineer, assert 2.
4. `TestDeleteUser_CascadesSessions` — insert user + session row with that user_id; call DeleteUser; assert session row is also gone.
5. `TestDeleteUser_NoopOnMissingID` — call with random UUID, assert no error (DELETE is idempotent at the DB layer; the 404 is a handler concern, not a store concern).

Handler tests in `pkg/manageserver/handlers_users_test.go` (integration, uses existing test server harness):
1. `TestListUsers_ReturnsArrayOfUsers_WithoutPasswordHash` — seed 2 users, GET returns 200 with array, assert no `password_hash` field in response body.
2. `TestListUsers_RequiresAdminRole` — network_engineer caller → 403 (asserts the existing middleware, mostly for regression protection).
3. `TestDeleteUser_SelfDeleteRejected` — admin A calls DELETE on own ID, 403.
4. `TestDeleteUser_LastAdminRejected` — single admin tries to delete themselves (covered above), and admin A tries to delete admin B where B is the only other admin — actually: admin A tries to delete admin A (covered); add: admin A is the only admin, tries to delete themselves, 403 takes priority; add: admin A deletes admin B where both are admins → success; add: admin A deletes user E (engineer) where A is sole admin → success (last-admin guard only fires when target is admin).
5. `TestDeleteUser_CascadeCleansSessions` — admin A creates session for engineer E, DELETE E, assert E's session row is gone.
6. `TestDeleteUser_UnknownIDReturns404` — DELETE random UUID, 404.
7. `TestDeleteUser_InvalidUUIDReturns400` — DELETE `/not-a-uuid`, 400.

**Frontend — Vitest component tests.**

In `web/apps/manage-portal/tests/views/Users.spec.ts` (new file — no existing spec):
1. Renders list from store `items`.
2. Delete button hidden on the row matching `auth.claims.sub`.
3. Click delete → confirm dialog opens with the email in the message text.
4. Confirm → calls `users.remove(id)` with the expected id.
5. On rejected promise with 409 → error toast.

No real HTTP in Vitest — stub the store's `remove` and the api-client factory per the pattern in `Licence.spec.ts` / `Settings.spec.ts`.

Api-client tests in `web/packages/api-client/tests/manageServer.test.ts` (append):
1. `listUsers GETs /v1/admin/users`
2. `deleteUser DELETEs /v1/admin/users/<id>`

## 5. Risk + rollback

- **Risk:** Cascade-delete on sessions is already in place; this design just starts relying on it. If the cascade ever gets reverted (unlikely), active sessions would survive user removal and the deleted user could act for up to the JWT TTL. Mitigation: a test explicitly asserts the cascade (TestDeleteUser_CascadesSessions) so a migration that weakens the FK will fail CI.
- **Risk:** A race where admin A deletes admin B while B deletes A — both could pass their last-admin checks and both get deleted, leaving zero admins. Mitigation: wrap the whole delete in a serializable transaction: `BEGIN ISOLATION LEVEL SERIALIZABLE` → `CountAdmins` → `DELETE` → `COMMIT`. Postgres will reject one of the two with a serialization failure, returned as 500; operator retries. This is the same pattern `handleCreateUser` doesn't need (count + insert is different) but delete needs. The plan will make this explicit in a dedicated task.
- **Rollback:** `git revert` the PR. No schema changes, no data migration. The portal's old behaviour (empty user list regardless of creates) is restored.

## 6. Open questions

None. Every decision traced either to a brainstorm answer or an existing code pattern.
