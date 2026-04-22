# Manage Server — Security Events (Login Lockouts) Design

> **Status:** Approved 2026-04-21 (brainstorm transcript). Item #2 on the post-#89 gap list. XS — narrow telemetry over the in-memory login rate limiter. Precedes the M-tier audit-log work.

## 1. Problem

The Manage Server has an in-memory per-(email, IP) login rate limiter at `pkg/manageserver/rate_limit.go` (50 lines). It silently drops a login request when the failure count exceeds 5 inside a 15-minute sliding window. Admins have no visibility into lockouts:

- A legitimate user reporting "I can't log in" has no operator-facing view confirming they're locked out.
- No way to manually unlock a legitimate user short of restarting the process or waiting 15 minutes.
- No signal of ongoing brute-force attempts that would warrant operational escalation (firewall rule, additional mitigations).

This design surfaces active lockouts via a dedicated admin endpoint and a Security view in the portal, with a manual unlock control.

### Goals

- `GET /api/v1/admin/security-events` returns an array of currently-active lockouts: `{email, ip, failures, first_failure, last_failure, locked_until}`.
- `DELETE /api/v1/admin/security-events?email=...&ip=...` clears the lockout for the named (email, IP) pair.
- Security.vue view in the portal: table of active lockouts + per-row Unlock button + manual refresh button.
- New "Security" sidebar entry.
- Tests at store (limiter), handler, and component layer.

### Non-goals

- **Persistence across process restart.** The limiter is intentionally transient — its threat model is "slow this attacker down until a real mitigation is put in place," not "durable audit trail."
- **Full audit log of every login success/failure.** That is the M-tier audit-log item; it will slot in under the same `/security-events` route later with a `type` discriminator. This PR only exposes lockouts.
- **Bulk clear.** Per-entry clear only. Admins can clear one-by-one; process restart clears everything.
- **Automatic polling / real-time updates.** Manual refresh button only. A future polling enhancement can be added if operators ask; keeping v1 simple.
- **Dashboard widget showing active-lockout count.** Separate concern; avoid bundling.

## 2. Decisions captured from brainstorm

| # | Decision | Choice |
|---|---|---|
| 1 | Endpoint scope | (a) Active lockouts only |
| 2 | Manual clear | (a) Yes — per-entry `DELETE` |
| 3 | Route name | (a) `/admin/security-events` (forward-compatible for audit log) |
| 4 | Frontend surface | (a) New Security sidebar entry + dedicated view |

## 3. Architecture

| Layer | Files touched |
|---|---|
| Rate limiter | `pkg/manageserver/rate_limit.go` — new `Lockout` type + `ActiveLockouts()` + `Clear(email, ip)` methods; `rate_limit_test.go` — new tests |
| Handler | `pkg/manageserver/handlers_security.go` (new) — two handlers; `handlers_security_test.go` (new) — integration tests |
| Routing | `pkg/manageserver/server.go` — mount two routes inside the existing admin-only group |
| api-client | `web/packages/api-client/src/manageServer.types.ts` — `Lockout` + `SecurityEventsResponse`; `manageServer.ts` — `listLockouts()` + `clearLockout(email, ip)`; test file additions |
| Portal store | `web/apps/manage-portal/src/stores/security.ts` (new) — `items` + `fetch()` + `remove(email, ip)` |
| Portal view | `web/apps/manage-portal/src/views/Security.vue` (new) — table + unlock + refresh |
| Sidebar nav | `web/apps/manage-portal/src/nav.ts` — add Security entry; `App.vue` — add `security: 'Security'` to the crumb-label map |

Total: ~10 files, ~350 LOC net (including tests).

### Contract details

**`GET /api/v1/admin/security-events`**

Response body:
```json
{
  "active_lockouts": [
    {
      "email": "user@example.com",
      "ip": "192.0.2.1",
      "failures": 5,
      "first_failure": "2026-04-21T08:45:12Z",
      "last_failure": "2026-04-21T08:47:33Z",
      "locked_until": "2026-04-21T09:00:12Z"
    }
  ]
}
```

- Empty list when no lockouts: `{"active_lockouts": []}`. Never null.
- Ordering: `locked_until DESC` (freshest lockouts first) so the most actionable entries are at the top.
- Status codes: 200 on success. 403 from `RequireRole("admin")` for non-admins. No other failure modes (read-only, no DB).

**`DELETE /api/v1/admin/security-events?email=<email>&ip=<ip>`**

- Both query params are required. Missing either → 400.
- 204 on success (no body).
- 404 if no entry matches the (email, IP) pair (whether because it never existed or has since expired).
- 403 for non-admin.

Query params (not path params) because email addresses contain `@` which would need URL encoding on a path segment; query string is cleaner and RFC-standard.

### Rate limiter exposure

Add to `pkg/manageserver/rate_limit.go`:

```go
// Lockout is the serialisable snapshot of one (email, IP) pair
// currently over the failure threshold.
type Lockout struct {
    Email        string    `json:"email"`
    IP           string    `json:"ip"`
    Failures     int       `json:"failures"`
    FirstFailure time.Time `json:"first_failure"`
    LastFailure  time.Time `json:"last_failure"`
    LockedUntil  time.Time `json:"locked_until"`
}

// ActiveLockouts returns a snapshot of all (email, IP) pairs currently
// over the failure threshold. Prunes expired entries inline (same
// semantics as Locked). Returned slice is freshly allocated — safe to
// mutate by the caller.
func (l *loginRateLimiter) ActiveLockouts() []Lockout { … }

// Clear removes the tracked failures for the given (email, IP) pair.
// Returns true if the entry existed, false otherwise.
func (l *loginRateLimiter) Clear(email, ip string) bool { … }
```

`ActiveLockouts` prunes in-place (same logic as `Locked`), iterates the map, filters for `len(kept) >= max`, builds the snapshot, and sorts by `LockedUntil DESC`. `LockedUntil` is `kept[0] + window` — when the oldest kept failure falls outside the window, the lockout ends.

`Clear` takes `l.mu`, deletes the map entry, returns whether the key was present. No pruning needed — deleting an already-expired entry is still a no-op success from the admin's perspective, but we return `false` so the handler can return 404 for "nothing to clear".

Both methods take `l.mu` to maintain concurrency safety with the existing `Locked` and `Record`.

### Frontend details

**`stores/security.ts`** mirrors `stores/users.ts`:

```ts
export const useSecurityStore = defineStore('security', () => {
  const items = ref<Lockout[]>([]);
  const loading = ref(false);

  async function fetch() {
    loading.value = true;
    try { items.value = (await useApiClient().get().listLockouts()).active_lockouts; }
    finally { loading.value = false; }
  }
  async function remove(email: string, ip: string): Promise<void> {
    await useApiClient().get().clearLockout(email, ip);
    items.value = items.value.filter((l) => !(l.email === email && l.ip === ip));
  }
  return { items, loading, fetch, remove };
});
```

**`Security.vue`** — table with columns: Email | IP | Failures | First failure (relative time) | Locked until (relative time) | Actions (Unlock button). Manual refresh button in the header ("Refresh"). Row-key is `${email}|${ip}`. `TConfirmDialog` before unlock with message "Unlock `email` from IP? They'll be able to log in again immediately."

**`nav.ts`** — add entry under the Admin section:
```ts
{ label: 'Security', href: '#/security' }
```

**Router route:** `{ path: '/security', component: Security.vue, meta: { requiresAuth: true } }` (admin-only enforcement still happens at the API layer; the UI doesn't check roles).

## 4. Testing strategy

**Unit tests** in `pkg/manageserver/rate_limit_test.go`:

1. `TestActiveLockouts_ReturnsOnlyOverThreshold` — record 3 failures for (a, ip1) and 5 for (b, ip2); assert only `b` is in the list.
2. `TestActiveLockouts_PrunesExpired` — record 5 failures, wait past the window (or use a test-injected clock), assert empty list.
3. `TestActiveLockouts_FieldsPopulated` — records with known timestamps, assert `FirstFailure`, `LastFailure`, `Failures`, `LockedUntil`.
4. `TestActiveLockouts_SortedByLockedUntilDesc` — multiple lockouts, assert ordering.
5. `TestClear_RemovesEntry` — record+lock, `Clear` returns true, `ActiveLockouts` is now empty.
6. `TestClear_MissingEntryReturnsFalse` — `Clear("nobody", "0.0.0.0")` returns false.
7. `TestActiveLockouts_IsConcurrencySafe` — goroutine-based race test using `-race`.

These need a test-friendly clock override. Today's `loginRateLimiter.Locked` uses `time.Now()` directly. Add a `now func() time.Time` field defaulting to `time.Now`, with a test helper `setNowForTest(now func() time.Time)`. Deterministic tests replace it with a fake; the shim is minimal.

**Integration tests** in `pkg/manageserver/handlers_security_test.go` (build tag `integration`):

1. `TestSecurityEvents_ListReturnsActiveLockouts` — seed an admin, hit the login endpoint 6 times with a bad password + same IP, GET `/admin/security-events`, assert the (email, IP) appears.
2. `TestSecurityEvents_ListEmptyWhenNoLockouts` — fresh server, GET returns `{"active_lockouts": []}`.
3. `TestSecurityEvents_NonAdminRejected` — engineer caller, 403.
4. `TestSecurityEvents_ClearRemovesLockout` — after a lockout, DELETE clears it; subsequent login attempt succeeds (if password is correct).
5. `TestSecurityEvents_ClearMissing404` — DELETE with unknown email/ip returns 404.
6. `TestSecurityEvents_ClearMissingQueryParams400` — DELETE without `email` or `ip`: 400.

**Vitest component tests** in `web/apps/manage-portal/tests/views/Security.spec.ts`:

1. Renders rows from store `items`.
2. Click Unlock → confirm dialog opens with email in message.
3. Confirm → `store.remove(email, ip)` called + dialog closes.
4. Click Refresh → `store.fetch()` called.

**api-client tests** (append to existing `manageServer.test.ts`):

1. `listLockouts GETs /v1/admin/security-events`.
2. `clearLockout DELETEs /v1/admin/security-events?email=<e>&ip=<i>`.

## 5. Risk + rollback

- **Risk:** Memory leak if admins never call `Clear` and the `failures` map accumulates `(email, ip)` keys indefinitely. Mitigation: existing `Locked` already prunes per key in-place when called; but keys with no recent activity linger in the map forever. Not new to this PR — same risk existed before. A future follow-up could add a periodic full-map sweeper, but it's out of scope here.
- **Risk:** Timing oracle — the 404 vs 204 split on `Clear` tells the admin whether an entry exists. Acceptable because the endpoint is admin-only; no privilege is leaked.
- **Risk:** Clock-abstraction refactor could introduce subtle bugs in the existing `Locked` path. Mitigation: existing tests for `Locked` should continue to pass unchanged after the refactor; the new `now` field defaults to `time.Now` so production behaviour is bit-for-bit identical.
- **Rollback:** `git revert` the PR. No schema changes, no data migration. Portal stops showing the Security view; rate limiter reverts to opaque operation.

## 6. Open questions

None. Every decision traces to a brainstorm answer or an existing code pattern.
