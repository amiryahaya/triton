# Agentless Unix Scan Wiring — Design Spec

**Date:** 2026-04-14
**Status:** Approved
**Effort:** ~3 days
**Backward compatibility:** Full — local scans unchanged

## Problem

`Orchestrator.scanUnix()` (pkg/scanner/netscan/orchestrator.go:127) currently does an SSH probe (`uname -a`) and returns **empty findings**. The `FileReader`/`SshReader` abstraction (pkg/scanner/fsadapter) and the `walkerConfig.reader` hook are already in place and tested, but no path exists for the Engine to inject an alternate `FileReader` into modules.

Agentless Unix scans must produce findings equivalent to a local scan of the same paths.

## Goal

Plumb `FileReader` through the scanner `Engine` to all 17 file-based Tier 1 modules, so `scanUnix()` can construct an `SshReader`, register modules, and run a real scan whose output matches a local scan.

## Design

### 1. Engine API additions — `pkg/scanner/engine.go`

Add two optional interfaces mirroring `StoreAware`:

```go
type FileReaderAware interface {
    SetFileReader(r fsadapter.FileReader)
}

type CommandRunnerAware interface {
    SetCommandRunner(r netadapter.CommandRunner)
}
```

Add fields + setters to `Engine`:

```go
type Engine struct {
    config           *scannerconfig.Config
    modules          []Module
    store            store.Store
    reader           fsadapter.FileReader     // nil → LocalReader
    commandRunner    netadapter.CommandRunner // nil → local exec
    hostnameOverride string                   // "" → os.Hostname()
}

func (e *Engine) SetFileReader(r fsadapter.FileReader)        { e.reader = r }
func (e *Engine) SetCommandRunner(r netadapter.CommandRunner) { e.commandRunner = r }
func (e *Engine) SetHostnameOverride(h string)                { e.hostnameOverride = h }
```

Inject inside `Scan()` (mirror the `StoreAware` loop):

```go
if e.reader != nil {
    for _, m := range e.modules {
        if fa, ok := m.(FileReaderAware); ok {
            fa.SetFileReader(e.reader)
        }
    }
}
if e.commandRunner != nil {
    for _, m := range e.modules {
        if ca, ok := m.(CommandRunnerAware); ok {
            ca.SetCommandRunner(e.commandRunner)
        }
    }
}
```

Use hostname override:

```go
hostname := e.hostnameOverride
if hostname == "" {
    hostname, _ = os.Hostname()
}
```

### 2. Module updates (17 modules)

Each Tier 1 file-based module gains:
- a `reader fsadapter.FileReader` field
- a `SetFileReader(r fsadapter.FileReader)` method
- passes `m.reader` to `walkTarget` via `walkerConfig.reader`

**Modules to update:**
certificate, key, library, binary, kernel, config, script, webapp, web_server, vpn_config, container_signatures, password_hash, auth_material, deps_ecosystems, service_mesh, xml_dsig, mail_server.

**Out of scope for v1:** runtime/network modules (process, network, protocol, VPN runtime, K8s live, firmware, Kerberos runtime) keep local execution. `CommandRunnerAware` is defined but no module implements it yet.

### 3. Orchestrator wiring — `pkg/scanner/netscan/orchestrator.go`

Replace `scanUnix()` body:

```go
func (o *Orchestrator) scanUnix(ctx context.Context, d Device, cred *Credential) (*model.ScanResult, error) {
    sshCfg, err := o.credToSSHConfig(d, cred)
    if err != nil {
        return nil, err
    }
    client, err := transport.NewSSHClient(ctx, sshCfg)
    if err != nil {
        return nil, fmt.Errorf("ssh connect: %w", err)
    }
    defer func() { _ = client.Close() }()

    reader := fsadapter.NewSshReader(client)

    paths := d.ScanPaths
    if len(paths) == 0 {
        paths = []string{"/etc", "/usr/local/etc", "/opt"}
    }

    cfg := scannerconfig.Load("standard")
    cfg.DBUrl = ""
    cfg.Workers = 4
    cfg.ScanTargets = make([]model.ScanTarget, 0, len(paths))
    for _, p := range paths {
        cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
            Type:  model.TargetFilesystem,
            Value: p,
            Depth: 10,
        })
    }

    eng := scanner.New(cfg)
    eng.RegisterDefaultModules()
    eng.SetFileReader(reader)
    eng.SetHostnameOverride(d.Name)

    progressCh := make(chan scanner.Progress, 32)
    go func() { for range progressCh {} }()

    result := eng.Scan(ctx, progressCh)
    result.Metadata.AgentID = "triton-netscan"
    result.Metadata.ScanProfile = "agentless-unix"
    return result, nil
}
```

### 4. Tests

- **`engine_test.go`** — new test `TestEngineInjectsFileReader` verifies a stub module implementing `FileReaderAware` receives the injected reader after `Scan()`; verify `SetHostnameOverride` propagates to `result.Metadata.Hostname`.
- **Per-module test** — smoke test one module (certificate) with a stub `FileReader` returning a known PEM; assert findings match local-scan output of same fixture.
- **Orchestrator integration** — table test (build-tag `integration`) against an in-process SSH fake or real sshd container: confirm `scanUnix` returns non-empty findings for a fixture directory.

## Constraints & Defaults (v1)

- `DBUrl=""` — per-device scans skip DB persistence; results flow only through the report-server submit path.
- `Workers=4` — SSH round-trip bound, not CPU bound. Avoids overwhelming target sshd.
- Profile hardcoded to `standard` for v1. Per-device profile override is a follow-up.
- Default scan paths: `/etc`, `/usr/local/etc`, `/opt`. Overridable via `Device.ScanPaths` YAML field.
- `CommandRunnerAware` interface defined but not consumed by any module in v1 — enables future agentless Tier 2 work without another API revision.

## Non-Goals

- Windows/macOS remote scans (separate design).
- Runtime module execution over SSH.
- Per-device profile customization (YAML schema change is a follow-up).
- AIX / enterprise router deepening.
