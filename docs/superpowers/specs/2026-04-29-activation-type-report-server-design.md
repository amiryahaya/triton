# Activation Type: License Server Foundation + Report Server

**Date:** 2026-04-29
**Status:** Pending implementation

## Overview

Add an `activation_type` enum column to the `activations` table so the license admin UI can distinguish which kind of service holds each seat: `report_server`, `manage_server`, or `agent`. This spec covers the shared license server foundation changes and the Report Server call-site update.

---

## 1. License Server — Foundation Changes

### 1.1 Database — Migration v11

```sql
ALTER TABLE activations
  ADD COLUMN activation_type TEXT NOT NULL DEFAULT 'agent'
  CHECK (activation_type IN ('report_server', 'manage_server', 'agent'));
```

Add this as `Version 11` in `pkg/licensestore/migrations.go`.

### 1.2 Store — `Activation` struct (`pkg/licensestore/store.go`)

Add field:
```go
ActivationType string // "report_server" | "manage_server" | "agent"
```

Update the `activationSelectCols` constant and the row-scanner to include `activation_type`.

### 1.3 Activation request handler (`pkg/licenseserver/handlers_activation.go`)

Extend the request struct:
```go
type activationRequest struct {
    LicenseID      string `json:"licenseID"`
    MachineID      string `json:"machineID"`
    Hostname       string `json:"hostname,omitempty"`
    OS             string `json:"os,omitempty"`
    Arch           string `json:"arch,omitempty"`
    ActivationType string `json:"activation_type,omitempty"` // new; defaults to "agent"
}
```

In the handler: if `ActivationType` is empty or not one of the three valid values, default to `"agent"`. Store the value in the `activations` row (INSERT / UPSERT). On UPSERT (re-activation of an existing seat), overwrite `activation_type` with the incoming value.

### 1.4 List activations API

`GET /api/v1/admin/activations?license={id}` already returns `Activation` records. No route change — the field appears automatically once the struct is updated.

### 1.5 License detail page UI (`pkg/licenseserver/ui/`)

Three UI changes on the license detail page:

| Change | Action |
|--------|--------|
| "Download agent.yml" button | Remove entirely (button, modal, and the `POST /api/v1/admin/licenses/{id}/agent-yaml` call) |
| "Enabled features" pills section | Remove entirely |
| Activations table | Add a **Type** column (position: after Hostname, before Machine ID) rendering `activation_type` as a badge: `report_server` → blue "Report Server"; `manage_server` → purple "Manage Server"; `agent` → grey "Agent" |

The `POST /api/v1/admin/licenses/{id}/agent-yaml` backend route can remain in place (no breaking removal needed) but the UI no longer exposes it.

---

## 2. `internal/license/client.go` — Shared Client Change

Both `Activate()` and `ActivateForTenant()` send a JSON body to `POST /api/v1/license/activate`. Add `activation_type` to those bodies.

**Signature changes:**

```go
// Activate registers this machine with the license server.
// activationType must be one of "report_server", "manage_server", "agent".
func (c *ServerClient) Activate(licenseID, activationType string) (*ActivateResponse, error)

// ActivateForTenant activates a licence with a custom machineID.
func (c *ServerClient) ActivateForTenant(licenceKey, machineID, activationType string) (*ActivateResponse, error)
```

In both bodies, add `"activation_type": activationType` to the `map[string]string` before marshalling.

All existing callers must be updated to pass the appropriate constant (see §3 below and the Manage Server spec).

**Package constants:**
```go
const (
    ActivationTypeAgent        = "agent"
    ActivationTypeReportServer = "report_server"
    ActivationTypeManageServer = "manage_server"
)
```

---

## 3. Report Server — Call-Site Change

The Report Server calls `ActivateForTenant()` to occupy one seat per `(deployment, tenant)` pair.

**File:** wherever the report server invokes `client.ActivateForTenant(...)` (search `pkg/server/` and `cmd/` for `ActivateForTenant`).

**Change:** pass `license.ActivationTypeReportServer` as the third argument:

```go
resp, err := licClient.ActivateForTenant(licenseKey, machineID, license.ActivationTypeReportServer)
```

No other logic changes are needed in the report server.

---

## 4. Testing

| Layer | What to test |
|-------|-------------|
| Migration | v11 runs cleanly; existing rows default to `"agent"` |
| Store | `CreateActivation` stores the type; `ListActivations` returns it |
| Handler | Empty/invalid `activation_type` defaults to `"agent"`; valid values stored correctly |
| Client | `Activate` and `ActivateForTenant` include `activation_type` in request body |
| UI | "Download agent.yml" and "Enabled features" absent; Type column present with correct badges |

---

## 5. Files Changed

| File | Change |
|------|--------|
| `pkg/licensestore/migrations.go` | Migration v11: add `activation_type` column |
| `pkg/licensestore/store.go` | `Activation` struct + select cols + scanner |
| `pkg/licenseserver/handlers_activation.go` | Parse + store `activation_type` |
| `internal/license/client.go` | Add `activationType` param + package constants |
| `pkg/server/` (report server callers) | Pass `ActivationTypeReportServer` |
| `pkg/licenseserver/ui/` | Remove agent-yaml button + features pills; add Type column |
