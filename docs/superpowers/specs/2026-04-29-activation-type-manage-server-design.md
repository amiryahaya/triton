# Activation Type: Manage Server

**Date:** 2026-04-29
**Status:** Pending implementation
**Depends on:** `2026-04-29-activation-type-report-server-design.md` (license server foundation + client changes must be applied first)

## Overview

The Manage Server holds two kinds of license seats: one for itself (`manage_server`) and zero or more on behalf of triton-agents it has onboarded (`agent`). This spec documents the Manage Server call-site changes required once the shared foundation from the Report Server spec is in place.

---

## 1. Manage Server Own Activation

**File:** `pkg/manageserver/handlers_admin_licence_lifecycle.go`

The manage server calls `client.Activate(licenseID)` to register its own machine with the license server.

**Change:** pass `license.ActivationTypeManageServer`:

```go
resp, err := licClient.Activate(licenseID, license.ActivationTypeManageServer)
```

This applies to all call sites in the lifecycle handler — initial activation (`handleLicenceRefresh`, `handleLicenceReplace`). Deactivation is unchanged.

---

## 2. Agent Proxy Activation (New Flow)

When a triton-agent connects to the manage server, the manage server can activate a license seat on the agent's behalf using the agent's machine fingerprint. This occupies a seat typed `agent` in the license server, giving the admin UI a per-agent activation row without requiring the agent to reach the license server directly.

**New method call in manage server agent-onboarding path:**

```go
resp, err := licClient.ActivateForTenant(licenseID, agentMachineID, license.ActivationTypeAgent)
```

Where `agentMachineID` is the fingerprint reported by the agent during registration with the manage server.

**Symmetric deactivation:** when the agent deregisters or the manage server forcibly removes it, call `DeactivateForTenant(licenseID, agentMachineID)`.

> **Scope note:** if no agent-onboarding proxy flow exists today, this section is forward-looking. The type constant and client signature are ready; the caller is wired once the onboarding path is built.

---

## 3. Files Changed

| File | Change |
|------|--------|
| `pkg/manageserver/handlers_admin_licence_lifecycle.go` | Pass `ActivationTypeManageServer` to `Activate()` |
| `pkg/manageserver/` (agent onboarding handler, if exists) | Call `ActivateForTenant(..., ActivationTypeAgent)` on agent registration; `DeactivateForTenant` on removal |

All `internal/license/client.go` and license server changes are covered by the Report Server spec.

---

## 4. Testing

| Scenario | Expected activation_type in license server |
|----------|--------------------------------------------|
| Manage server activates its own license | `manage_server` |
| Manage server proxies agent onboarding | `agent` |
| Existing agent activating directly (unchanged) | `agent` (default) |
