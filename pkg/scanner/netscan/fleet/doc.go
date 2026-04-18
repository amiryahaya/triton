// Package fleet implements the orchestrator for `triton fleet-scan`: an
// SSH fan-out that pushes the triton binary to each unix host in an
// inventory, runs `triton scan --detach` (PR #72's detached lifecycle),
// collects reports, and aggregates per-host results into a summary.
//
// The orchestrator is transport-agnostic above the SSHRunner interface.
// Production wires transport.SSHClient from pkg/scanner/netadapter;
// tests inject a fakeRunner that records commands and returns scripted
// responses.
//
// Per-host lifecycle (see orchestrator.go::scanHost for the full flow):
//  1. SSH dial + host-key verification
//  2. uname -s -m → arch resolution
//  3. Sudo pre-flight via `sudo -n true` (if device.sudo=true)
//  4. SFTP upload of binary to <workdir>/.triton-<random>
//  5. Launch: `triton scan --detach --quiet <forwarded flags>`
//  6. Poll: `triton scan --status --job-id <id> --json` every 10s
//  7. Collect: `triton scan --collect --job-id <id> -o -` (tar.gz stream)
//  8. Upload result.json to --report-server (optional)
//  9. Remote cleanup: `triton scan --cleanup --job-id <id>` + rm binary
//
// Failure at any phase is captured in HostResult.Phase; the worker
// returns early but the pool continues draining the device queue.
// --max-failures N cancels the outer context on breach.
package fleet
