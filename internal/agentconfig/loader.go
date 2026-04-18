// Package agentconfig loads the optional agent.yaml file that sits
// next to the triton binary. It is the fool-proof-deployment primitive:
// operators unzip the release bundle, drop their license-provided
// agent.yaml in the same folder as the executable, and run it. No
// CLI flags, no environment variables, no shell knowledge required.
//
// Resolution order for `agent.yaml`:
//
//  1. <directory containing the triton executable>/agent.yaml
//  2. ~/.triton/agent.yaml
//
// When neither is present, the agent runs in fully-default mode:
// free-tier quick scan, JSON report written to ./reports/<timestamp>/
// relative to the exe directory.
//
// When the file exists but fields are empty, each field falls back
// independently to the built-in default — an operator with no license
// yet can ship a valid agent.yaml containing only `report_server: ""`
// and still have the agent start.
package agentconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultFileName is the file the loader looks for next to the
// executable and in ~/.triton. Exported so callers can construct
// path hints for diagnostics.
const DefaultFileName = "agent.yaml"

// Config is the on-disk shape of agent.yaml. Every field is
// optional — an empty file is valid and means "use all defaults".
type Config struct {
	// LicenseKey is the literal Ed25519-signed licence token. When
	// empty, the agent runs in FREE tier (quick scan, JSON only).
	// Separate from the CLI --license-key flag; flag wins if both
	// are set.
	LicenseKey string `yaml:"license_key"`

	// ReportServer is the URL of a Triton report server. When set,
	// scan results are submitted via POST /api/v1/scans with the
	// license token as the authentication credential. When empty,
	// reports are written to OutputDir locally.
	ReportServer string `yaml:"report_server"`

	// Profile is the scan profile: quick | standard | comprehensive.
	// When empty, defaults to "quick" so a license-less agent still
	// produces useful output. Tier gating can downgrade this at
	// runtime.
	Profile string `yaml:"profile"`

	// OutputDir is where local reports land. When ReportServer is
	// empty, this is the sole output destination. When ReportServer
	// is set, this path is still resolved but only used if AlsoLocal
	// is true (tee mode). Interpreted relative to the exe directory
	// when not absolute, so `./reports` means "<exe-dir>/reports"
	// regardless of the shell's cwd. When empty, defaults to
	// "./reports".
	OutputDir string `yaml:"output_dir"`

	// Formats restricts which report formats are written locally.
	// Nil or empty means "every format the licence tier allows".
	// Ignored when ReportServer is set AND AlsoLocal is false.
	Formats []string `yaml:"formats"`

	// AlsoLocal enables "tee" mode: when ReportServer is set, the
	// agent ALSO writes the scan to OutputDir in addition to
	// submitting it to the server. Defaults to false — existing
	// agents with no `also_local` in their yaml keep the same
	// server-only behavior. When true, local writes run before
	// submission, and local-write failures degrade to warnings
	// (the server submit is authoritative). Useful for:
	//
	//   - Operators who want a local audit copy of every scan
	//     alongside central submission
	//   - Regulated environments requiring an on-host forensic
	//     artifact that never leaves the endpoint
	//   - Operators moving from local-only to server-mode who
	//     want both paths exercised during transition
	//
	// Corresponds to the CLI flag `--also-local`. Flag wins over
	// yaml when explicitly set on the command line.
	AlsoLocal bool `yaml:"also_local"`

	// LicenseServer is the URL of the Triton License Server for seat
	// management. When set alongside LicenseID, the agent registers
	// itself on startup and heartbeats on each scan interval. When
	// empty, no seat tracking occurs (backward compatible).
	LicenseServer string `yaml:"license_server"`

	// LicenseID is the license UUID to activate against. Required
	// when LicenseServer is set; ignored otherwise.
	LicenseID string `yaml:"license_id"`

	// ResourceLimits caps memory, CPU, duration, nice on each scan
	// iteration. Nil means "no limits" (backward compatible). When
	// set, the agent builds a limits.Limits via ResolveLimits and
	// calls lim.Apply(ctx) before eng.Scan.
	ResourceLimits *ResourceLimitsConfig `yaml:"resource_limits,omitempty"`

	// Schedule is a standard 5-field cron expression evaluated in the
	// agent host's local timezone. When non-empty, this wins over
	// Interval and --interval. See docs/plans/2026-04-19-agent-cron-schedule-design.md.
	Schedule string `yaml:"schedule,omitempty"`

	// ScheduleJitter adds uniform random jitter in [0, ScheduleJitter)
	// to each cron-scheduled fire time. Defaults to 0 (disabled) —
	// unlike Interval mode which always jitters ±10%, cron's whole
	// point is "fire at X o'clock", so jitter is opt-in for fleet-wide
	// staggering. Written as a Go duration string ("30s", "5m").
	ScheduleJitter time.Duration `yaml:"schedule_jitter,omitempty"`

	// Interval is the existing repeat interval (24h, 1h, etc.). When
	// Schedule is non-empty this is ignored. Kept as a yaml-level
	// field so tests can round-trip it; the CLI --interval flag
	// remains authoritative in the absence of a yaml value.
	Interval time.Duration `yaml:"interval,omitempty"`

	// loadedFrom records the absolute path the Config was read from.
	// Empty when the loader returned the zero-value default (no
	// file found).
	loadedFrom string
}

// ResourceLimitsConfig is the agent.yaml `resource_limits:` block.
// Every field is optional; zero/empty values mean "no limit" for that
// dimension. Applied per-iteration by cmd/agent.go::runAgentScan via
// internal/runtime/limits.Limits.Apply. See
// docs/plans/2026-04-19-agent-resource-limits-design.md for the full
// model.
type ResourceLimitsConfig struct {
	MaxMemory     string        `yaml:"max_memory,omitempty"`
	MaxCPUPercent int           `yaml:"max_cpu_percent,omitempty"`
	MaxDuration   time.Duration `yaml:"max_duration,omitempty"`
	StopAt        string        `yaml:"stop_at,omitempty"`
	Nice          int           `yaml:"nice,omitempty"`
}

// LoadedFrom returns the absolute path of the file that provided
// this config, or the empty string if no file was found and the
// loader returned the zero-value default.
func (c *Config) LoadedFrom() string {
	return c.loadedFrom
}

// IsZeroValue reports whether this Config came from a file at all.
// Tests and the agent's startup banner use this to tell "no file
// found" from "file found but empty".
func (c *Config) IsZeroValue() bool {
	return c.loadedFrom == ""
}

// Load walks the resolution chain and returns the first valid file
// parsed, OR the zero-value Config if no file is found. A file that
// exists but fails to parse is a hard error — we do NOT silently
// fall through, because a typo in agent.yaml should surface loudly.
//
// The exeDirHint argument lets tests inject a directory without
// shelling out to os.Executable; production callers pass "" to use
// the real executable path.
func Load(exeDirHint string) (*Config, error) {
	for _, path := range candidatePaths(exeDirHint) {
		cfg, err := loadFile(path)
		if err == nil {
			cfg.loadedFrom = path
			return cfg, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		// A file exists but can't be parsed — fail loud.
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	// No file found anywhere. Return a zero-value Config so the
	// caller can proceed with all-default settings.
	return &Config{}, nil
}

// candidatePaths builds the ordered search list. Kept deterministic
// and pure so tests can assert on ordering.
func candidatePaths(exeDirHint string) []string {
	var paths []string

	exeDir := exeDirHint
	if exeDir == "" {
		exeDir = executableDir()
	}
	if exeDir != "" {
		paths = append(paths, filepath.Join(exeDir, DefaultFileName))
	}

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".triton", DefaultFileName))
	}
	return paths
}

// executableDir returns the absolute directory containing the
// running binary, or the empty string if it can't be determined
// (e.g., `go run` in a temp dir where os.Executable returns a
// path under /tmp, which is still usable but noisy in logs).
//
// Callers that care about the distinction between "no exe dir"
// and "exe dir exists" check the return value before using it.
func executableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	// Resolve any symlinks (e.g., /usr/local/bin/triton → the real
	// homebrew location) so agent.yaml is looked up next to the
	// actual binary, not the symlink.
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe)
}

// loadFile reads and parses a single candidate path. Returns
// os.ErrNotExist (unwrappable) if the file is missing so the
// caller can distinguish "try the next candidate" from "parse error".
//
// Whitespace normalization (Sprint 3 review F2): yaml.v3 preserves
// trailing newlines on block scalars (``` license_key: | ``` form),
// so a pasted token that used the multi-line form would carry a
// trailing \n and fail base64 decoding in the license verifier,
// producing a confusing silent free-tier fallback. Trim the
// credential-shaped fields (license_key, report_server) to stay
// robust against common paste patterns without being clever about
// the rest of the config.
func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid yaml: %w", err)
	}
	cfg.LicenseKey = strings.TrimSpace(cfg.LicenseKey)
	cfg.ReportServer = strings.TrimSpace(cfg.ReportServer)
	cfg.Profile = strings.TrimSpace(cfg.Profile)
	cfg.LicenseServer = strings.TrimSpace(cfg.LicenseServer)
	cfg.LicenseID = strings.TrimSpace(cfg.LicenseID)
	return &cfg, nil
}
