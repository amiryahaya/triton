# Multi-Tenant Triton Server Design

**Date:** 2026-03-07
**Status:** Approved

## Overview

Single version of Triton server supporting multiple organizations. The license server is the single source of truth for orgs, licenses, users, and auth. On-prem deployments use the same code with a single org registered in the license server.

## Architecture

```
+-------------+  +-------------+  +-------------+
|   Agent 1   |  |   Agent 2   |  |   Agent N   |  (scanners)
|  Org: Acme  |  |  Org: Acme  |  | Org: Globex |
+------+------+  +------+------+  +------+------+
       |                |                |
       +--------+-------+----------------+
                |
                v
      +---------+---------+     +------------------+
      |   Triton Server   |---->|  License Server   |
      |   (scan data)     |<----|  (org/auth/seats) |
      |   :8080           |     |  :8081            |
      +---------+---------+     +---------+--------+
                |                         |
                v                         v
      +----------------+       +----------------+
      |   PostgreSQL   |       |   PostgreSQL   |
      |   (scans)      |       |   (orgs/lic)   |
      +----------------+       +----------------+

On-prem: same topology, just 1 org in license server
```

### Key Principles

- License server = single source of truth for orgs, licenses, seats, users
- Triton server = scan data plane, no org management
- Agent = scanner + local token validation, submits to triton server
- On-prem vs cloud = same code, different number of orgs
- Single binary for triton server (no mode flag)

## Two-Layer Validation

### Layer 1 -- Agent side (fast, offline)

- Local Ed25519 signature check + expiry on `~/.triton/license.key`
- Determines tier for scan config (which modules, profile)
- If token is expired/missing: free tier (scan still runs, just limited)
- No network call needed -- agent can scan air-gapped systems

### Layer 2 -- Triton server side (authoritative)

- When scan arrives, triton server validates token with license server
- License server checks: valid? revoked? seats? org active?
- If invalid: reject the scan submission (HTTP 403)
- If valid: stamp org_id, store scan
- Revocation is near-instant -- admin revokes in license server, next scan submission is rejected

```
Agent                     Triton Server              License Server
  |                            |                           |
  | 1. Local check             |                           |
  | (signature + expiry)       |                           |
  |                            |                           |
  | 2. Submit scan + token     |                           |
  |--------------------------->|                           |
  |                            | 3. Validate token         |
  |                            |-------------------------->|
  |                            |   (revoked? seats? tier?) |
  |                            |<--------------------------|
  |                            |   {org_id, tier, valid}   |
  |                            |                           |
  |    4. Accept/Reject        |                           |
  |<---------------------------|                           |
```

## Authentication & Authorization

### Token flow (end to end)

1. Admin creates org + license in License Server
2. User activates: `triton license activate --license-server ... --license-id ...`
   - License server checks seats, issues signed token
   - Token saved to `~/.triton/license.key`
3. Agent scans: `triton scan --server https://triton.example.com ...`
   - Local validation (signature + expiry) determines scan tier
   - Submits scan + token to Triton Server
4. Triton Server receives scan:
   - Extracts token from `X-Triton-License-Token` header
   - Calls License Server: `POST /api/v1/validate` with token
   - License Server returns: `{valid, org_id, org_name, tier, seats}`
   - If invalid/revoked: HTTP 403, scan rejected
   - If valid: stamps org_id on scan, stores it

### Auth methods

| Method | Purpose | Replaces |
|--------|---------|----------|
| License token (`X-Triton-License-Token`) | Agent scan submission | API key auth |
| JWT (`Authorization: Bearer`) | Human user UI/API access | None (new) |
| Admin key (`X-Triton-Admin-Key`) | License server admin API | Unchanged |

### Service-to-service auth

Triton server authenticates with license server using a shared service key (`--license-server-key` flag). The license server already supports `X-Triton-Admin-Key` -- reuse or add a separate service key role.

### Removing API key auth

The `--api-key` flag on triton server is deprecated. License tokens replace it. Keep working for one release cycle with a deprecation warning, then remove.

## User Model

### Roles

- **Platform admin** -- manages all orgs, sees all scans, global dashboard
- **Org admin** -- manages their org's scans, users, reports
- **Org user** -- views their org's scans and reports (read-only)
- **Agent** -- submits scans (machine identity, no human user)

### Users live in License Server

The license server is the identity authority. Users are stored there alongside orgs and licenses. Triton server delegates all identity to the license server via JWT validation.

### Permissions Matrix

| Action | Platform Admin | Org Admin | Org User | Agent |
|--------|---------------|-----------|----------|-------|
| View all orgs' scans | YES | NO | NO | NO |
| View own org's scans | YES | YES | YES | NO |
| Delete scans | YES | YES (own org) | NO | NO |
| Submit scans | YES | NO | NO | YES |
| Generate reports | YES | YES (own org) | YES (own org) | NO |
| Manage org users | YES | YES (own org) | NO | NO |
| Manage all orgs | YES | NO | NO | NO |
| Policy evaluate | YES | YES (own org) | YES (own org) | NO |
| Diff/Trend | YES | YES (own org) | YES (own org) | NO |
| View dashboard | YES (global) | YES (own org) | YES (own org) | NO |
| View audit log | YES (global) | YES (own org) | NO | NO |
| Manage licenses | YES | NO | NO | NO |
| View activations | YES | YES (own org) | YES (own org) | NO |

### Auth token format (JWT signed by license server)

```json
{
  "sub": "<user-uuid>",
  "org": "<org-uuid>",
  "role": "org_admin",
  "name": "Alice",
  "iat": 1772813899,
  "exp": 1772900299
}
```

Signed with the license server's Ed25519 signing key (same key used for license tokens). Triton server verifies using the corresponding public key.

## Data Model Changes

### License Server -- new tables

```sql
CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID REFERENCES organizations(id),  -- NULL = platform admin
    email       TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('platform_admin', 'org_admin', 'org_user')),
    password    TEXT NOT NULL,  -- bcrypt hash
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,  -- SHA-256 of session token
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Triton Server (scan store) -- no new tables

The scan store stays as-is. It already has `org_id` on scans. No user tables needed -- triton server delegates all identity to the license server.

## API Changes

### License Server -- new endpoints

```
# User management (platform_admin or org_admin for own org)
POST   /api/v1/admin/users          -- Create user
GET    /api/v1/admin/users          -- List users (filter by org_id)
GET    /api/v1/admin/users/{id}     -- Get user
PUT    /api/v1/admin/users/{id}     -- Update user
DELETE /api/v1/admin/users/{id}     -- Delete user

# Auth (public)
POST   /api/v1/auth/login           -- Email + password -> JWT
POST   /api/v1/auth/refresh         -- Refresh JWT
POST   /api/v1/auth/logout          -- Invalidate session

# Token validation (service-to-service, existing)
POST   /api/v1/validate             -- Returns org/tier info
```

### Triton Server -- route changes

All routes require either:
- `Authorization: Bearer <JWT>` (human users)
- `X-Triton-License-Token: <token>` (agents)

```
# Existing routes (unchanged paths, new auth + org scoping)
POST   /api/v1/scans                -- Agent submits scan (license token auth)
GET    /api/v1/scans                -- List scans (scoped by org from JWT/token)
GET    /api/v1/scans/{id}           -- Get scan detail (org-scoped)
DELETE /api/v1/scans/{id}           -- Delete scan (org_admin+ only)
GET    /api/v1/scans/{id}/findings  -- Get findings (org-scoped)
GET    /api/v1/diff                 -- Compare scans (org-scoped)
GET    /api/v1/trend                -- Trend data (org-scoped)
GET    /api/v1/machines             -- List machines (org-scoped)
GET    /api/v1/machines/{hostname}  -- Machine history (org-scoped)
POST   /api/v1/policy/evaluate      -- Evaluate policy (org-scoped)
GET    /api/v1/reports/{id}/{fmt}   -- Generate report (org-scoped)
GET    /api/v1/aggregate            -- Aggregate stats (org-scoped)
GET    /api/v1/health               -- Health (public, no auth)

# New: auth proxy (delegates to license server)
POST   /api/v1/auth/login           -- Proxy to license server
POST   /api/v1/auth/refresh         -- Proxy to license server
POST   /api/v1/auth/logout          -- Proxy to license server
GET    /api/v1/auth/me              -- Return current user info from JWT
```

## Validation Caching

Triton server caches license token validation results in memory to avoid hitting the license server on every request.

```
Cache behavior:
- Hit + fresh (< 5 min):    Use cached result, no network call
- Hit + stale (5-30 min):   Use cached result, async refresh in background
- Hit + expired (> 30 min): Block, must validate with license server
- Miss:                      Block, validate with license server
- License server down + cached:   Use cache up to grace period
- License server down + no cache: Reject request (503)
```

Cache key is SHA-256 of the token. Cache entry contains org_id, org_name, tier, validity.

## Migration Strategy

### Phase 1 -- License server: users + auth

- Add `users` and `sessions` tables (new migration)
- Add user CRUD endpoints (admin API)
- Add login/refresh/logout endpoints (public API)
- Add JWT signing with Ed25519 signing key
- Update license server admin UI with user management page
- Seed initial platform_admin user on first startup

### Phase 2 -- Triton server: new auth middleware

- Add `--license-server` required flag (replaces optional `--api-key`)
- Add dual auth middleware (JWT for humans, license token for agents)
- Add validation cache (in-memory, TTL-based)
- Add auth proxy endpoints (login/refresh/logout -> license server)
- Add role-based access control middleware
- Update all handlers to use org_id from auth context
- Deprecate `--api-key` with warning

### Phase 3 -- Web UI update

- Login page (email + password)
- Org-scoped dashboard (users see only their org's data)
- Platform admin view (cross-org global dashboard)
- User management page (org_admin+)

### Phase 4 -- Deprecation cleanup

- Remove `--api-key` flag
- Remove old API key auth middleware
- Update documentation and deployment guide
