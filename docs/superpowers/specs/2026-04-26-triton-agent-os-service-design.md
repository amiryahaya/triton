# triton-agent OS Service Design

**Date:** 2026-04-26
**Status:** Approved
**Worktree scope:** OS service shell only — install and uninstall `triton-agent` as a native OS service on Linux, macOS, Windows, and FreeBSD.

---

## 1. Problem Statement

`triton-agent` is currently a plain foreground daemon. Operators must keep a terminal open or write their own init scripts. On Windows, SIGTERM does not exist, so there is no standard shutdown signal. The binary has no mechanism to register itself as an OS service, survive reboots, or be managed via standard OS tools (`systemctl`, `launchctl`, `services.msc`, `service`).

---

## 2. Scope

**In scope:**
- `triton-agent install` — one-shot self-install as a native OS service (elevated privileges required)
- `triton-agent uninstall` — remove the service registration and stop the running instance
- Linux: systemd unit file
- macOS: launchd plist in `/Library/LaunchDaemons/`
- Windows: native Windows Service API (`golang.org/x/sys/windows/svc`) — no NSSM or external wrapper
- FreeBSD: rc.d script
- Service-context log detection — switches to plain structured output when no TTY

**Out of scope:**
- Bidirectional command dispatch (scan job push from portal to agent)
- Pause / resume / stop scan commands
- Resource caps (CPU, memory, time window)
- Remote deployment from manage portal
- OpenBSD, other BSDs (stub returns "not supported")

---

## 3. Command Surface

```
triton-agent install   [--config <path>]
triton-agent uninstall
```

### install

- Requires root (Linux/macOS/FreeBSD) or Administrator (Windows). Fails immediately with a clear message if not elevated.
- `--config <path>` — path to `agent.yaml`. Default resolution: `TRITON_AGENT_CONFIG` env → `/opt/triton/agent.yaml` (Unix) / `C:\ProgramData\Triton\agent.yaml` (Windows).
- Uses `os.Executable()` for `ExecStart` / `binPath` — installs the service pointing at the binary's current location. No copying.
- Bakes the config path into the service definition via `TRITON_AGENT_CONFIG` environment variable so the daemon picks it up correctly regardless of working directory.
- Warns (does not fail) if the config file does not exist at the resolved path at install time.
- Prints on success: `triton-agent service installed and started`

### uninstall

- Stops the running service, disables auto-start, removes the service definition.
- Idempotent: safe to run when the service is already stopped or not installed (logs a warning, exits 0).
- Prints on success: `triton-agent service stopped and removed`

---

## 4. File Structure

All new code lives in `cmd/triton-agent/`. No new packages.

```
cmd/triton-agent/
  main.go              — add Cobra subcommands; add shouldRunAsService() + runAsService() call
  config.go            — unchanged
  scanner.go           — unchanged
  service.go           — shared: resolveConfig(), privilege check helper, Cobra cmd wiring
  service_linux.go     — //go:build linux   — systemd install/uninstall
  service_darwin.go    — //go:build darwin  — launchd install/uninstall
  service_windows.go   — //go:build windows — Windows Service API + svc.Run handler
  service_freebsd.go   — //go:build freebsd — rc.d install/uninstall
  service_other.go     — //go:build !linux,!darwin,!windows,!freebsd — stub
```

Windows-only imports (`golang.org/x/sys/windows/svc`, `golang.org/x/sys/windows/svc/mgr`) are confined to `service_windows.go` and never appear in non-Windows builds.

---

## 5. Per-Platform Behaviour

### 5.1 Linux — systemd

**Install:**
1. Write `/etc/systemd/system/triton-agent.service`:
   ```ini
   [Unit]
   Description=Triton Agent — cryptographic asset scanner
   After=network.target

   [Service]
   Type=simple
   ExecStart=<current-exe>
   Environment=TRITON_AGENT_CONFIG=<config-path>
   Restart=on-failure
   RestartSec=10
   StandardOutput=journal
   StandardError=journal
   User=root

   [Install]
   WantedBy=multi-user.target
   ```
2. `systemctl daemon-reload`
3. `systemctl enable triton-agent`
4. `systemctl start triton-agent`

**Uninstall:**
1. `systemctl stop triton-agent` (ignore error if not running)
2. `systemctl disable triton-agent` (ignore error if not enabled)
3. `rm /etc/systemd/system/triton-agent.service`
4. `systemctl daemon-reload`

### 5.2 macOS — launchd

**Install:**
1. Write `/Library/LaunchDaemons/com.triton.agent.plist`:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
     "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
     <key>Label</key>
     <string>com.triton.agent</string>
     <key>ProgramArguments</key>
     <array>
       <string><current-exe></string>
     </array>
     <key>EnvironmentVariables</key>
     <dict>
       <key>TRITON_AGENT_CONFIG</key>
       <string><config-path></string>
     </dict>
     <key>RunAtLoad</key>
     <true/>
     <key>KeepAlive</key>
     <true/>
     <key>UserName</key>
     <string>root</string>
     <key>StandardOutPath</key>
     <string>/var/log/triton-agent.log</string>
     <key>StandardErrorPath</key>
     <string>/var/log/triton-agent.log</string>
   </dict>
   </plist>
   ```
2. `launchctl load -w /Library/LaunchDaemons/com.triton.agent.plist`

**Uninstall:**
1. `launchctl unload -w /Library/LaunchDaemons/com.triton.agent.plist` (ignore error)
2. `rm /Library/LaunchDaemons/com.triton.agent.plist`

### 5.3 Windows — native Windows Service API

**Install (requires Administrator):**
1. `mgr.OpenSCManager("", "", mgr.MODIFY_OBJECT)`
2. `mgr.CreateService("triton-agent", exePath, mgr.Config{StartType: mgr.StartAutomatic, DisplayName: "Triton Agent"}, "--config", cfgPath)`
   — passes config path as a CLI arg (cleaner than registry env var writes required by the SCM env var API)
3. `s.Start()`

**Uninstall:**
1. `mgr.OpenSCManager` → `mgr.OpenService("triton-agent")`
2. `s.Control(svc.Stop)` — poll `s.Query()` until `State == svc.Stopped` (timeout 30s)
3. `s.Delete()`

**Service dispatch in `main.go`:**

When the binary is launched by the Windows Service Control Manager, `svc.IsAnInteractiveSession()` returns `false`. `main()` detects this and calls:

```go
svc.Run("triton-agent", &agentHandler{cfgPath: cfgPath})
```

`agentHandler` implements `svc.Handler`. Its `Execute()` method:
- Accepts `svc.StartPending` → `svc.Running`
- Runs `tritonagent.Run()` in a goroutine
- On `svc.ChangeRequest` with `Cmd == svc.Stop`: cancels the context, waits for the goroutine, signals `svc.StopPending` → `svc.Stopped`

### 5.4 FreeBSD — rc.d

**Install:**
1. Write `/usr/local/etc/rc.d/triton_agent`:
   ```sh
   #!/bin/sh
   # PROVIDE: triton_agent
   # REQUIRE: NETWORKING
   # KEYWORD: shutdown

   . /etc/rc.subr

   name="triton_agent"
   rcvar="triton_agent_enable"
   command="<current-exe>"
   triton_agent_env="TRITON_AGENT_CONFIG=<config-path>"
   pidfile="/var/run/${name}.pid"
   command_args=""

   load_rc_config $name
   run_rc_command "$1"
   ```
2. `chmod 0555 /usr/local/etc/rc.d/triton_agent`
3. `sysrc triton_agent_enable="YES"`
4. `service triton_agent start`

**Uninstall:**
1. `service triton_agent stop` (ignore error)
2. `sysrc -x triton_agent_enable`
3. `rm /usr/local/etc/rc.d/triton_agent`

### 5.5 Other platforms — stub

`service_other.go` (build tag: `!linux,!darwin,!windows,!freebsd`) returns:

```
triton-agent: OS service install is not supported on this platform
```

Exit code 1.

---

## 6. Service-Context Log Detection

When launched by the OS service manager the process has no TTY. The binary detects this early in `run()` and switches to plain structured log output (no ANSI colour, timestamps always on via `log.SetFlags(log.Ldate | log.Ltime)`).

| Platform | Detection method |
|---|---|
| Linux | `os.Getenv("INVOCATION_ID") != ""` (systemd sets this unconditionally) |
| macOS | `!isatty(os.Stdout.Fd())` via `golang.org/x/term` |
| Windows | `!svc.IsAnInteractiveSession()` (already required for service dispatch) |
| FreeBSD | `!isatty(os.Stdout.Fd())` via `golang.org/x/term` |

`golang.org/x/term` is already a transitive dependency; no new module additions required.

---

## 7. Privilege Check

A shared helper in `service.go` validates elevation before any write:

- **Linux/macOS/FreeBSD:** `os.Getuid() == 0`
- **Windows:** calls `windows.OpenProcessToken` + `windows.GetTokenInformation` to read the elevation token — standard pattern for UAC-aware privilege detection.

Error message on failure:
```
error: triton-agent install requires root privileges (re-run with sudo)
error: triton-agent install requires Administrator privileges (re-run as Administrator)
```

---

## 8. Dependencies

| Dependency | Already in go.mod? | Used for |
|---|---|---|
| `golang.org/x/sys/windows/svc` | Yes — v0.43.0 | Windows service dispatch + install |
| `golang.org/x/sys/windows/svc/mgr` | Yes — v0.43.0 | Windows SCM management |
| `golang.org/x/term` | Yes — v0.41.0 | isatty check (macOS, FreeBSD) |

No new module additions required. All dependencies are already present in `go.mod`.

---

## 9. Testing Strategy

Unit tests avoid needing root or an actual OS service manager by testing the generated content, not the side effects:

- `TestSystemdUnitContent` — assert unit file text matches expected template given known exe + config paths
- `TestLaunchdPlistContent` — assert plist XML is valid and contains correct keys
- `TestRCScriptContent` — assert rc.d script contains correct `command=` and `rcvar=` lines
- `TestWindowsServiceConfig` — assert `mgr.Config` fields are set correctly (unit-testable without SCM)
- `TestResolveConfigPath` — assert default resolution logic (env → platform default)
- `TestPrivilegeCheckError` — assert privilege check returns a correctly-worded error message

Integration tests (tagged `//go:build integration`) test actual install/uninstall on CI runners with the appropriate OS available. These run in the CI matrix (`ubuntu-latest`, `macos-latest`, `windows-latest`).

---

## 10. Non-Goals (Explicitly Deferred)

- `triton-agent start` / `stop` / `status` / `restart` management commands
- Auto-update / self-upgrade
- Non-root service user with capability grants
- Remote deployment from Manage Portal
- Bidirectional scan command dispatch
- OpenBSD, NetBSD, other BSDs
