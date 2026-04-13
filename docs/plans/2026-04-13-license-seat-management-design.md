# License Seat Management — Design Spec

**Date:** 2026-04-13
**Branch:** `feat/analytics-phase-3`
**Status:** Approved

## Problem

The Triton agent does not communicate with the license server. When an agent starts, it uses a pre-signed license token from `agent.yaml` but never calls `/activate` to register the machine as a seat. The license server has no visibility into how many hosts are actually running agents.

Consequences:
- Seat limits are unenforceable for agents (only the CLI `triton license activate` command registers seats)
- Unclean agent uninstalls (binary deleted without deactivating) leave ghost seats that permanently consume capacity
- Admins cannot accurately track fleet size from the license server dashboard

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Agent-to-license-server communication | Direct (option A) | Clean separation; license server is single seat authority |
| Stale seat threshold | 14 days | Covers powered-off machines; reclaims ghosts within 2 weeks |
| Seats-full behavior | Graceful degradation to free tier | Consistent with existing "never block" philosophy |
| Reaper trigger | On-demand during activate | Simple; no background goroutine needed |
| Heartbeat frequency | Piggyback on scan interval | No extra goroutine; 14-day window tolerates 24h intervals |

## Architecture

### Agent Startup Flow

```
resolveAgentConfig()
  ├─ license_server + license_id configured?
  │   ├─ YES → ServerClient.Activate(licenseID)
  │   │   ├─ 201 Created → use server-issued token, set tier
  │   │   ├─ 409 Conflict (seats full) → warn, degrade to free tier
  │   │   ├─ 403 Forbidden (revoked/expired) → warn, degrade to free tier
  │   │   └─ network error → warn, fall back to license_key from yaml, else free tier
  │   └─ NO → existing behavior (license_key from yaml/env/flag)
  └─ continue: applyTierFiltering → printStartupBanner → scan loop
```

### Heartbeat Flow (per scan iteration)

```
for each scan iteration:
  ├─ activation succeeded?
  │   ├─ YES → ServerClient.Validate(licenseID, token)
  │   │   ├─ valid → update last_seen_at (server-side), check tier changes
  │   │   ├─ invalid → warn, degrade to free tier
  │   │   └─ network error → warn, continue with current tier
  │   └─ NO → skip (one-shot or degraded)
  └─ runAgentScan()
```

### Clean Shutdown

```
SIGINT/SIGTERM received:
  ├─ activation succeeded?
  │   ├─ YES → ServerClient.Deactivate(licenseID) (best-effort)
  │   └─ NO → skip
  └─ exit
```

### On-Demand Stale Seat Reaping (server-side)

```
store.Activate(ctx, act):
  ├─ check seat count
  ├─ activeCount >= seats?
  │   ├─ YES → ReapStaleActivations(licenseID, threshold)
  │   │   ├─ reaped > 0 → re-count seats
  │   │   │   ├─ room now → proceed with activation
  │   │   │   └─ still full → return ErrSeatsFull
  │   │   └─ reaped == 0 → return ErrSeatsFull
  │   └─ NO → proceed with activation
  └─ insert/update activation row
```

## Component Changes

### 1. Agent Config (`internal/agentconfig/loader.go`)

Add two fields to `Config`:

```go
// LicenseServer is the URL of the Triton License Server for seat
// management. When set alongside LicenseID, the agent registers
// itself on startup and heartbeats on each scan interval. When
// empty, no seat tracking occurs (backward compatible).
LicenseServer string `yaml:"license_server"`

// LicenseID is the license UUID to activate against. Required
// when LicenseServer is set; ignored otherwise.
LicenseID string `yaml:"license_id"`
```

Both are trimmed of whitespace (same as existing `LicenseKey`, `ReportServer`).

### 2. Agent Startup (`cmd/agent.go`)

New function `activateWithLicenseServer` called from `runAgent` after `resolveAgentConfig` and before `applyTierFiltering`:

- Creates `license.ServerClient` from `resolved.licenseServer`
- Calls `Activate(resolved.licenseID)`
- On success: stores the returned token as `resolved.licenseToken`, rebuilds `activeGuard` from the server-issued token
- On seats-full/revoked/expired/network-error: logs warning, continues with whatever `license_key` was already resolved (or free tier if none)
- Returns a `seatState` struct tracking whether activation succeeded and the `ServerClient` instance (needed for heartbeat and deactivate)

### 3. Heartbeat Before Each Scan (`cmd/agent.go`)

Inside the `for` loop, before `runAgentScan`:

- If `seatState.activated` is true, call `Validate(licenseID, token)`
- On valid response: update `activeGuard` if tier changed (admin changed the license tier mid-run)
- On invalid: degrade to free tier, set `seatState.activated = false` (stop heartbeating)
- On network error: log warning, continue with current tier

### 4. Deactivation on Shutdown (`cmd/agent.go`)

After the scan loop exits (context canceled):

- If `seatState.activated` is true, call `Deactivate(licenseID)` with a 5-second timeout
- Best-effort: log and ignore errors

### 5. Stale Seat Reaping (`pkg/licensestore/`)

**Store interface** — add to `store.go`:

```go
// ReapStaleActivations marks active seats as inactive when their
// last_seen_at exceeds the threshold. Returns the number of seats
// reaped. Intended to run inside the Activate transaction when
// seats are full.
ReapStaleActivations(ctx context.Context, licenseID string, threshold time.Duration) (int, error)
```

**Postgres implementation** — in `postgres.go`:

```sql
UPDATE activations
SET active = FALSE, deactivated_at = NOW()
WHERE license_id = $1
  AND active = TRUE
  AND last_seen_at < NOW() - $2::interval
```

**Integration into `Activate()`:**

The existing `Activate` method in `postgres.go` currently returns `ErrSeatsFull` immediately when `activeCount >= lic.Seats`. Change to:

1. When seats are full, call `ReapStaleActivations` within the same serializable transaction
2. If any seats were reaped, re-count and proceed if room
3. If still full, return `ErrSeatsFull`
4. Emit `auto_reap` audit event for each reaped activation

### 6. License Server Config (`pkg/licenseserver/`)

Add to `Config`:

```go
// StaleActivationThreshold is the duration after which an
// activation with no heartbeat is eligible for automatic reaping.
// Default: 336h (14 days). Configurable via
// TRITON_LICENSE_SERVER_STALE_THRESHOLD.
StaleActivationThreshold time.Duration
```

Wire in `cmd/licenseserver/main.go` from env var with 336h default.

Passed into `store.Activate()` as a parameter. The store method signature becomes `Activate(ctx, act, staleThreshold)` — this keeps the store stateless (no config field) and lets tests inject arbitrary thresholds without rebuilding the store.

## What Does NOT Change

- `internal/license/client.go` — `ServerClient` already has `Activate`, `Deactivate`, `Validate`
- `pkg/licenseserver/handlers_activation.go` handler signatures — reaping is inside the store layer
- Existing agent behavior when `license_server` is not in `agent.yaml` — fully backward compatible
- Existing CLI `triton license activate/deactivate` commands — unchanged

## Test Plan

### Unit Tests

- `internal/agentconfig/loader_test.go`: parse `license_server` and `license_id` from yaml, whitespace trimming
- `cmd/agent_test.go`: activation success/seats-full/network-error/revoked paths, heartbeat validate paths, deactivation on shutdown
- `pkg/licensestore/postgres_test.go`: `ReapStaleActivations` reaps only stale seats, leaves fresh ones; `Activate` with reap-on-full (seeds stale activation, verifies it gets reaped and new activation succeeds)

### Integration Tests

- `test/integration/license_server_test.go`: full lifecycle — activate machine A → activate machine B (fills seats) → machine A goes stale → activate machine C (triggers reap of A, succeeds) → validate machine C heartbeat updates `last_seen_at`
- `test/integration/license_flow_test.go`: agent startup with license server, graceful degradation on seats-full

## Rollback

All changes are additive. Rollback = deploy previous agent binary (no `license_server` field, no activation calls). License server changes (reap logic) are inert without agents calling activate — the on-demand reap only fires inside `Activate()`.
