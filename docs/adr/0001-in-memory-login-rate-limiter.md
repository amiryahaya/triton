# ADR 0001 — In-Memory Per-Email Login Rate Limiter

- **Status:** Accepted (2026-04-08)
- **Phase:** 5 Sprint 1 (implementation), Sprint 2 (this record)
- **Scope:** `internal/auth.LoginRateLimiter`, wired into both
  `pkg/server` (report server) and `pkg/licenseserver`

## Context

With Keycloak integration postponed indefinitely, Triton is shipping the
self-managed auth path as its production story. That means the two
login endpoints — the license server's `/auth/login` for superadmins
and the report server's `/api/v1/auth/login` for org users — both
need a rate-limit / lockout control to defend against brute-force
credential guessing.

Options considered:

1. **In-memory per-email sliding window** (chosen). sync.Map-backed
   entries, 5 failures per 15-minute window → 15-minute lockout,
   janitor goroutine sweeps stale entries. Zero external dependencies.
2. **Redis-backed** lockout counter. Cross-replica coordination for
   free, durable across restarts, operationally familiar. But pulls
   in a runtime dependency Triton currently does not require, and
   makes the "get up and running" story dramatically more complex
   for single-binary deployments (the dominant Triton use case).
3. **PostgreSQL-backed** lockout counter. Keeps the dependency list
   the same (Postgres is already required) and gets durability for
   free. But every login attempt becomes an additional round trip
   through the DB connection pool, and the resulting lock contention
   is non-trivial under coordinated attack exactly when the
   control matters most.

## Decision

Implement the in-memory limiter as v1 and explicitly document its
trade-offs rather than pretending it is a complete defense.

## Consequences

### Accepted trade-offs

- **Not durable across process restart.** Rolling deploys reset every
  lockout on the restarted replica. Any active brute-force attacker
  gets a free reset window per deploy — practically 1–2 per day in
  a CD-heavy shop, which is tolerable given the 15-minute lockout
  duration.
- **Split-brain across replicas.** Each replica has its own
  `sync.Map`; a load balancer spreading attempts round-robin gives
  the attacker an effective budget of `MaxAttempts × replicas` per
  window instead of `MaxAttempts`. With 2 replicas and the default
  5/15min config that becomes 10 attempts per 15 minutes per email.
  Still a meaningful delay, but it IS a degradation at scale.
- **No cross-server coordination.** A user with the same email in
  both the superadmin and org-user populations can be attacked on
  both endpoints in parallel, doubling the effective budget. Sprint 2
  (S2) added structured failed-login logs so a future SIEM layer can
  correlate via `email=` and alert even before the limiter itself
  becomes shared.

### Promotion triggers

We will revisit this decision and promote to a shared backing store
(Redis or Postgres) when ANY of the following become true:

- Triton is deployed behind >1 replica in a production-weight
  environment where coordinated brute-force is a real threat model.
- A single customer crosses ~100 auth attempts per minute at baseline
  (at which rate the in-memory `sync.Map` hot path is no longer the
  bottleneck; the bottleneck shifts to coordination).
- An operator explicitly asks for durable lockouts across restarts.
- A compliance audit requires "lockout state survives maintenance
  windows".

### Operational mitigations in the interim

- The janitor goroutine caps memory by sweeping stale entries on
  a ticker equal to `LockoutDuration`. This prevents unbounded
  growth from dictionary-style attacks against unknown emails.
- `LoginRateLimiter.Stats()` exposes `Tracked` and `LockedEmails`
  counters so operators can wire alerting on a sudden spike in
  `LockedEmails` — the strongest in-process signal of a coordinated
  attack.
- Structured failed-login log events (`event=login_failure stage=…`)
  give a cross-replica, cross-server event stream that a downstream
  log aggregator can use for correlation that the in-process
  limiter cannot perform.

## Alternatives considered and rejected

- **Per-IP instead of per-email.** IPs are easy to rotate (proxies,
  NAT, CGNAT, residential pools) and collateral damage on shared
  IPs (corporate NAT) is high. Per-email is harder to rotate and
  concentrates damage on the actual attack target. Per-email chosen.
- **Exponential backoff on the client.** Voluntary; attackers ignore
  it. Not a substitute for a server-side control.
- **Fail2ban-style external process.** Adds a dependency and moves
  the control outside Triton's own logs, making audit harder. Kept
  the control inside the application.

## References

- Sprint 1 implementation: commit `451b8a1` (`internal/auth/ratelimit.go`)
- Sprint 1 D1 fix (memory leak via janitor): commit `1a75709`
- Sprint 1 D8 fix (janitor-delete race): commit `473ca2b`
- Sprint 1 architecture review S1 (this ADR's trigger): agent report,
  2026-04-08
