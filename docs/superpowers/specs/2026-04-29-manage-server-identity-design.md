# Manage Server Identity: Name, ID, Display Name, and Agent Proxy Activation

**Date:** 2026-04-29
**Status:** Pending implementation

## Overview

Three related changes that establish manage server identity across the system:

1. **Part A — Setup page**: Collect a user-assigned `server_name` during license activation. Display the auto-generated `instance_id` post-activation. Forward `server_name` to the report server during enrolment.
2. **Part B — License server display name**: Store and show a `display_name` on activations so the license admin UI can distinguish which manage server (or agent) holds each seat.
3. **Part C — Agent proxy activation**: Wire the manage server to activate/deactivate license seats on behalf of enrolled agents (spec §2 from `2026-04-29-activation-type-manage-server-design.md`).

---

## Part A — Manage Server Setup: Name + ID

### A1. Database — `pkg/managestore/migrations.go`

Add **Migration v20**:

```sql
ALTER TABLE manage_setup
  ADD COLUMN IF NOT EXISTS server_name TEXT NOT NULL DEFAULT '';
```

### A2. Store — `pkg/managestore/store.go`

Add `ServerName string` to `SetupState`:

```go
type SetupState struct {
    AdminCreated        bool
    LicenseActivated    bool
    LicenseServerURL    string
    LicenseKey          string
    SignedToken         string
    InstanceID          string
    ServerName          string   // new
    PendingDeactivation bool
    UpdatedAt           time.Time
}
```

Update `GetSetup` SELECT and `SaveLicenseActivation` INSERT/UPDATE to include `server_name`.

### A3. Backend — `pkg/manageserver/handlers_setup.go`

**`handleSetupLicense`** request body gains:

```go
var req struct {
    LicenseServerURL string `json:"license_server_url"`
    LicenseKey       string `json:"license_key"`
    ServerName       string `json:"server_name"`
}
```

Validation: `server_name` is required (return 400 if empty or longer than 100 chars).

Pass `req.ServerName` to `store.SaveLicenseActivation(...)`.

**`autoEnrolWithReport`** — extend the enrol payload sent to the report server to include `server_name`:

```json
{
  "manage_instance_id": "...",
  "license_key": "...",
  "public_key_pem": "...",
  "server_name": "..."
}
```

The report server ignores unknown fields today; this makes the field available when the report server's manage-listing feature is built.

### A4. Frontend — `web/apps/manage-portal/src/views/SetupLicense.vue`

**Form state** (script setup):
- Add `serverName` ref (string, required)

**Form fields** — add Server Name input above the License Server URL field:

```
Server Name  [text input, required, placeholder: "e.g. KL HQ Manage Server"]
Licence Server URL  [url input]
Licence Key  [text input]
```

**Post-activation confirmation** — after successful `activateLicense()` response, replace the form with a read-only summary panel:

```
✓ Activation successful

Server Name   <serverName>
Server ID     <instanceID from response>
```

The `instanceID` is already returned in the `SetupState` response from `POST /api/v1/setup/license`. Extract it from the API response and display it.

**API client** — extend `activateLicense` payload to include `server_name`.

---

## Part B — License Server: Display Name on Activations

### B1. Database — `pkg/licensestore/migrations.go`

Add **Migration v12**:

```sql
ALTER TABLE activations
  ADD COLUMN IF NOT EXISTS display_name TEXT NOT NULL DEFAULT '';
```

### B2. Store — `pkg/licensestore/store.go`

Add `DisplayName string` to `Activation` struct (after `ActivationType`):

```go
DisplayName string `json:"displayName"`
```

Update all SELECT lists, Scan calls, INSERT, and UPDATE queries in `pkg/licensestore/postgres.go` (`GetActivation`, `GetActivationByMachine`, `ListActivations`, `Activate`) to include `display_name`.

### B3. Handler — `pkg/licenseserver/handlers_activation.go`

Extend the request struct:

```go
var req struct {
    LicenseID      string `json:"licenseID"`
    MachineID      string `json:"machineID"`
    Hostname       string `json:"hostname,omitempty"`
    OS             string `json:"os,omitempty"`
    Arch           string `json:"arch,omitempty"`
    ActivationType string `json:"activation_type,omitempty"`
    DisplayName    string `json:"display_name,omitempty"`   // new
}
```

No validation required — empty is allowed. Truncate to 200 chars if needed. Set `act.DisplayName = req.DisplayName` before calling `store.Activate`.

On the UPDATE paths (re-activate), also overwrite `display_name` with the incoming value.

### B4. Client — `internal/license/client.go`

Update both `Activate` and `ActivateForTenant` signatures to accept `displayName string` as the last parameter:

```go
func (c *ServerClient) Activate(licenseID, activationType, displayName string) (*ActivateResponse, error)
func (c *ServerClient) ActivateForTenant(licenceKey, machineID, activationType, displayName string) (*ActivateResponse, error)
```

Include `"display_name": displayName` in the body map.

### B5. Call sites — pass display names

| File | Current call | Updated call |
|------|-------------|-------------|
| `pkg/manageserver/handlers_setup.go` | `Activate(key, ActivationTypeManageServer)` | `Activate(key, ActivationTypeManageServer, req.ServerName)` |
| `pkg/manageserver/handlers_admin_licence_lifecycle.go` (×2) | `Activate(key, ActivationTypeManageServer)` | `Activate(key, ActivationTypeManageServer, state.ServerName)` — load setup state first |
| `pkg/manageserver/handlers_setup.go` — `autoEnrolWithReport` | N/A (not an activation call) | — |
| `pkg/server/handlers_platform_tenants.go` (×2) | `ActivateForTenant(key, machineID, ActivationTypeReportServer)` | `ActivateForTenant(key, machineID, ActivationTypeReportServer, "")` — report server has no user-assigned name yet |
| `cmd/license.go` | `Activate(id, ActivationTypeAgent)` | `Activate(id, ActivationTypeAgent, "")` |
| Agents enrol (new — see Part C) | — | `ActivateForTenant(key, agentID, ActivationTypeAgent, agent.Name)` |

All integration tests that call `Activate` or `ActivateForTenant` must be updated with an extra `""` display name argument.

### B6. License admin UI — `web/apps/license-portal/src/views/LicenceDetail.vue`

Add `displayName: string` to the `Activation` TypeScript interface in `web/packages/api-client/src/types.ts`.

Add a **Display Name** column to the activations table in `LicenceDetail.vue` (after the Type column):
- Column key: `displayName`, label: `Name`, width: `1fr`
- Render as plain text; if empty, render `—` (em dash)

Rebuild the license portal dist after Vue/TS changes.

---

## Part C — Agent Proxy Activation

### C1. Agent Enrolment — `pkg/manageserver/agents/handlers_admin.go`

In `Enrol`, after `agentsStore.Create(ctx, agent)` succeeds and before building the bundle, activate a license seat on behalf of the agent:

```go
// Load setup state for license credentials
state, err := s.setupStore.GetSetup(ctx)
if err != nil {
    // log and continue — setup state missing shouldn't block enrol response already created
    log.Printf("enrol: failed to load setup state for licence activation: %v", err)
} else if state.LicenseActivated {
    licClient := license.NewServerClient(state.LicenseServerURL)
    if _, err := licClient.ActivateForTenant(
        state.LicenseKey,
        agentID.String(),
        license.ActivationTypeAgent,
        agent.Name,
    ); err != nil {
        if strings.Contains(err.Error(), "all seats") || strings.Contains(err.Error(), "no seats") {
            // Seats exhausted — refuse enrolment
            _ = agentsStore.Delete(ctx, agentID) // or leave as orphan; see note
            writeError(w, http.StatusPaymentRequired, "no license seats available for new agent")
            return
        }
        // Transient error (network, timeout) — log and allow
        log.Printf("enrol: licence activation for agent %s failed (transient): %v", agentID, err)
    }
}
```

> **Note on seat-full rollback:** Add `Delete(ctx context.Context, id uuid.UUID) error` to the agents `Store` interface and implement it as `DELETE FROM manage_agents WHERE id = $1`. Call it before returning the 402 so no orphan row is left in the DB.

The `Enrol` handler needs access to `setupStore`. If `AdminHandlers` doesn't already hold a reference to the setup store, inject one via the constructor.

### C2. Agent Revocation — `pkg/manageserver/agents/handlers_admin.go`

In the existing revoke handler (find `Revoke` or `handleRevoke`), after `agentsStore.Revoke(ctx, id)` succeeds:

```go
// Best-effort licence seat release
state, err := s.setupStore.GetSetup(ctx)
if err == nil && state.LicenseActivated {
    licClient := license.NewServerClient(state.LicenseServerURL)
    if err := licClient.DeactivateForTenant(state.LicenseKey, agentID.String()); err != nil {
        log.Printf("revoke: licence deactivation for agent %s failed (best-effort): %v", agentID, err)
    }
}
```

Errors are logged only — never surface to the caller.

### C3. `AdminHandlers` struct injection

The setup store lives in `pkg/managestore` (interface `managestore.Store`, which has `GetSetup`). If `AdminHandlers` in `pkg/manageserver/agents/` does not already hold a reference to it, add one:

```go
type AdminHandlers struct {
    store      Store               // agents store (pkg/manageserver/agents)
    setupStore managestore.Store   // manage setup store (pkg/managestore)
    ca         *ca.CA
    cfg        Config
}
```

Update `NewAdminHandlers(...)` constructor to accept `managestore.Store` and update the call site in `pkg/manageserver/server.go` to pass `s.store` (the main manage store).

---

## Testing

| Layer | Scenario | Expected |
|-------|----------|---------|
| Migration | v20 runs; existing manage_setup row gets `server_name = ''` | Pass |
| Migration | v12 runs; existing activations get `display_name = ''` | Pass |
| Setup handler | POST /setup/license without server_name → 400 | Pass |
| Setup handler | POST /setup/license with valid name → SetupState.ServerName stored | Pass |
| Store | GetSetup returns ServerName; SetupState round-trips correctly | Pass |
| Client | Activate() includes display_name in request body | Pass |
| Client | ActivateForTenant() includes display_name in request body | Pass |
| Activation handler | display_name stored and returned in ListActivations | Pass |
| Agent enrol | ActivateForTenant called with ActivationTypeAgent + agent.Name | Pass |
| Agent enrol | Seats full → 402 returned, agent not enrolled | Pass |
| Agent revoke | DeactivateForTenant called after Revoke | Pass |
| UI | SetupLicense.vue shows Name field; post-activation shows Name + ID | Pass |
| UI | LicenceDetail shows DisplayName column | Pass |

---

## Files Changed

| File | Change |
|------|--------|
| `pkg/managestore/migrations.go` | Migration v20: `server_name` on `manage_setup` |
| `pkg/managestore/store.go` | `SetupState.ServerName`; GetSetup + SaveLicenseActivation updated |
| `pkg/manageserver/handlers_setup.go` | Accept + store `server_name`; send in enrol payload |
| `pkg/manageserver/agents/handlers_admin.go` | ActivateForTenant on enrol; DeactivateForTenant on revoke |
| `pkg/manageserver/agents/store.go` | Add `Delete(ctx, id UUID) error` to interface + postgres impl |
| `pkg/licensestore/migrations.go` | Migration v12: `display_name` on `activations` |
| `pkg/licensestore/store.go` | `Activation.DisplayName` |
| `pkg/licensestore/postgres.go` | All SELECT/INSERT/UPDATE paths include `display_name` |
| `pkg/licenseserver/handlers_activation.go` | Parse + store `display_name` |
| `internal/license/client.go` | `displayName string` param on Activate + ActivateForTenant |
| All call sites (see B5 table) | Pass display name |
| `web/packages/api-client/src/types.ts` | `displayName: string` on Activation |
| `web/apps/manage-portal/src/views/SetupLicense.vue` | Name field + confirmation panel |
| `web/apps/license-portal/src/views/LicenceDetail.vue` | DisplayName column |
| `web/apps/license-portal/` dist rebuild | After Vue/TS changes |
| `web/apps/manage-portal/` dist rebuild | After Vue changes |
| Integration tests | Update all Activate/ActivateForTenant call sites with `""` display name |
