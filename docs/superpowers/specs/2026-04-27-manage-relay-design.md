# Manage Server Relay — Design Spec

## Problem

Scan results from `triton-agent`, `triton-portscan`, and `triton-sshagent` currently flow directly
to the Report Server (or through `triton-engine`). This means:

- No centralised visibility into what was submitted and from where
- No retry/backpressure if the Report Server is temporarily unavailable
- `triton-engine` is a redundant relay tier with overlapping responsibility to `pkg/manageserver`
- No uniform source attribution (which program produced a given scan)

## Goal

Route all scan results through the Manage Server's existing outbox queue before they reach the
Report Server. Remove `triton-engine` and the old `triton agent` CLI subcommand. Build
`triton-sshagent` as a proper standalone worker binary that replaces `triton fleet-scan`.

## Architecture

```
triton-agent  (OS service, per host)
    ──mTLS──▶  Manage Server :8443 (existing gateway)
                    │  phone-home / poll-commands / ingest-scan
                    ▼
              manage_scan_results_queue  (existing outbox)
                    │  drain (existing)
                    ▼
              Report Server

triton-portscan  (dispatched worker)
    ──HTTPS──▶  Manage Server :8080  (claim job + submit result)
                    │
                    ▼  same outbox + drain

triton-sshagent  (dispatched worker)
    ──HTTPS──▶  Manage Server :8080  (claim job + submit result)
                    │
                    ▼  same outbox + drain
```

## Decisions

### D1 — Keep mTLS for triton-agent
Manage Server is already the CA (`pkg/manageserver/ca/`). The existing mTLS gateway at `:8443`
already handles phone-home, scan ingestion, cert rotation. triton-agent only needs its URL
config updated from `engine_url` to `manage_url`.

### D2 — Add `GET /agents/commands` to gateway
Manage Server stores a pending scan command per agent row (`pending_command JSONB`). Admin API
`POST /admin/agents/{id}/commands` sets the command. Gateway `GET /agents/commands` atomically
pops and returns it (or 204). Agent loop polls every 30 s.

### D3 — Worker key auth for portscan/sshagent
Shared secret (`TRITON_MANAGE_WORKER_KEY` env var) sent as `X-Worker-Key` header. Simple,
stateless, appropriate for machine-to-machine on a private network. Workers are not enrolled
as agents — they are ephemeral processes.

### D4 — Worker job submit endpoint
`POST /api/v1/worker/jobs/{id}/submit` on Manage Server. Handler validates worker key, calls
`scanjobs.Store.Complete(ctx, id)`, then `scanresults.Store.Enqueue(...)` with
`source_type = "worker_submit"`. No new Store methods needed.

### D5 — ScanSource field
Add `Source ScanSource` to `model.ScanMetadata`. Constants: `"triton-agent"`,
`"triton-portscan"`, `"triton-sshagent"`. Each binary sets this before submitting.
Flows through unchanged JSON in the outbox to Report Server.

### D6 — triton-sshagent migrates scanexec.Executor
`pkg/engine/scanexec` holds the SSH+`fsadapter.SshReader` pattern. This moves to
`pkg/sshagent/scanner.go`. `fsadapter.SshReader` is already in `pkg/scanner/fsadapter/`
(untouched). Credentials come from the job claim response rather than a local keystore.

### D7 — Outbox queue for reliability
A temporary Report Server outage must not lose scan results. The existing
`manage_scan_results_queue` + drain with 10-attempt exponential backoff handles this.
Workers get 202 Accepted immediately; Report Server delivery is asynchronous.

### D8 — Removals
| What | Why |
|---|---|
| `pkg/engine/` (all 8 sub-packages) | Functionality absorbed by Manage Server |
| `cmd/triton-engine/` | No engine tier in new architecture |
| `cmd/agent.go` + `cmd/agent_scheduler.go` | Superseded by new triton-agent OS service |
| `cmd/fleet_scan.go` + `pkg/scanner/netscan/fleet/` | Replaced by triton-sshagent |
| Report Server engine gateway packages | Protocol no longer used |

`pkg/engine/scanexec` is migrated (not deleted) → becomes `pkg/sshagent/scanner.go`.

### D9 — Report Server ?source filter
Add `?source=triton-agent` query filter to `GET /api/v1/scans/{id}/findings` alongside the
existing `?module=X` filter (already implemented). Simple in-memory filter on the findings
slice, same pattern as `filterByModule`.

## Components Unchanged

- `pkg/manageserver/ca/` — CA already exists
- `pkg/manageserver/agents/` — gateway already handles phone-home, ingest-scan, rotate-cert
- `pkg/manageserver/scanresults/` — outbox + drain already implemented
- `pkg/manageserver/scanjobs/` — job queue already implemented; `Complete()` already exists
- `pkg/scanner/fsadapter/ssh_reader.go` — SshReader stays in pkg/scanner/fsadapter
- `pkg/tritonagent/loop.go` — loop structure unchanged; only interface methods updated
