package agentconfig

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/runtime/limits"
)

// This file holds the runtime-apply helpers — functions that
// interpret Config fields and produce concrete values the agent
// feeds into scanner setup (output directories, effective
// formats, etc.). It is deliberately separated from loader.go
// (YAML parsing + file resolution) so changes to "how do we
// read credentials from disk" never need to touch "how do we
// resolve an output directory against the executable location",
// and vice versa.
//
// Sprint 4 SF1 — credential rotation concern: an operator
// regenerating agent.yaml to swap a license key should not be
// forced to re-read or re-reason about the runtime tuning path.
// Keeping these two concerns in sibling files makes the
// separation visible at the file tree level.

// ResolveOutputDir applies the "relative to exe directory" rule:
// absolute paths are returned unchanged, relative paths are joined
// with the exe directory (NOT the shell cwd). An empty input
// returns "<exe-dir>/reports" as the fool-proof default.
func (c *Config) ResolveOutputDir() string {
	exeDir := executableDir()
	dir := c.OutputDir
	if dir == "" {
		dir = "reports"
	}
	if filepath.IsAbs(dir) {
		return dir
	}
	if exeDir == "" {
		// No exe dir (unlikely) — fall back to shell cwd.
		return dir
	}
	return filepath.Join(exeDir, dir)
}

// ResolveLimits merges agent.yaml resource_limits with CLI flag values
// per the precedence rule: CLI flag wins when explicitly set, else
// yaml, else zero. When cmd is nil (programmatic use), only yaml values
// are consulted. Parse errors on malformed yaml values (bad memory
// string, out-of-range percent, bad HH:MM) surface as errors.
func (c *Config) ResolveLimits(cmd *cobra.Command) (limits.Limits, error) {
	var maxMem, maxCPU, stopAt string
	var maxDur time.Duration
	var nice int
	if c.ResourceLimits != nil {
		maxMem = c.ResourceLimits.MaxMemory
		maxDur = c.ResourceLimits.MaxDuration
		stopAt = c.ResourceLimits.StopAt
		nice = c.ResourceLimits.Nice
		if c.ResourceLimits.MaxCPUPercent > 0 {
			maxCPU = fmtInt(c.ResourceLimits.MaxCPUPercent)
		}
	}
	if cmd != nil {
		// Check both local Flags() (post-Execute merge) and
		// PersistentFlags() directly — before cobra runs Execute, the
		// persistent-flag set is not yet merged into Flags(), which
		// means tests that register flags as persistent and call
		// PersistentFlags().Set() need the resolver to look at both
		// sides. In production cmd/agent.go usage, Execute has already
		// merged them, so Flags().Changed sees the persistent flag.
		if flagChanged(cmd, "max-memory") {
			v, err := flagString(cmd, "max-memory")
			if err != nil {
				return limits.Limits{}, fmt.Errorf("reading --max-memory flag: %w", err)
			}
			maxMem = v
		}
		if flagChanged(cmd, "max-cpu-percent") {
			v, err := flagString(cmd, "max-cpu-percent")
			if err != nil {
				return limits.Limits{}, fmt.Errorf("reading --max-cpu-percent flag: %w", err)
			}
			maxCPU = v
		}
		if flagChanged(cmd, "max-duration") {
			v, err := flagDuration(cmd, "max-duration")
			if err != nil {
				return limits.Limits{}, fmt.Errorf("reading --max-duration flag: %w", err)
			}
			maxDur = v
		}
		if flagChanged(cmd, "stop-at") {
			v, err := flagString(cmd, "stop-at")
			if err != nil {
				return limits.Limits{}, fmt.Errorf("reading --stop-at flag: %w", err)
			}
			stopAt = v
		}
		if flagChanged(cmd, "nice") {
			v, err := flagInt(cmd, "nice")
			if err != nil {
				return limits.Limits{}, fmt.Errorf("reading --nice flag: %w", err)
			}
			nice = v
		}
	}

	memBytes, err := limits.ParseSize(maxMem)
	if err != nil {
		return limits.Limits{}, fmt.Errorf("resource_limits.max_memory: %w", err)
	}
	cpuPct, err := limits.ParsePercent(maxCPU)
	if err != nil {
		return limits.Limits{}, fmt.Errorf("resource_limits.max_cpu_percent: %w", err)
	}
	stopOffset, err := limits.ParseStopAt(stopAt, time.Now())
	if err != nil {
		return limits.Limits{}, fmt.Errorf("resource_limits.stop_at: %w", err)
	}
	return limits.Limits{
		MaxMemoryBytes: memBytes,
		MaxCPUPercent:  cpuPct,
		MaxDuration:    maxDur,
		StopAtOffset:   stopOffset,
		Nice:           nice,
	}, nil
}

func fmtInt(n int) string {
	return fmt.Sprintf("%d", n)
}

// flagChanged reports whether `name` was explicitly set via either the
// local or the persistent flag set on cmd. cobra merges persistent
// flags into Flags() at Execute time; callers that invoke ResolveLimits
// pre-Execute (unit tests, programmatic drivers) still need their
// persistent-flag changes respected.
func flagChanged(cmd *cobra.Command, name string) bool {
	if cmd.Flags().Changed(name) {
		return true
	}
	if cmd.PersistentFlags().Changed(name) {
		return true
	}
	return false
}

// flagString returns the flag value from whichever flag set has it
// registered. Same merge-timing rationale as flagChanged.
func flagString(cmd *cobra.Command, name string) (string, error) {
	if cmd.Flags().Lookup(name) != nil {
		return cmd.Flags().GetString(name)
	}
	return cmd.PersistentFlags().GetString(name)
}

func flagDuration(cmd *cobra.Command, name string) (time.Duration, error) {
	if cmd.Flags().Lookup(name) != nil {
		return cmd.Flags().GetDuration(name)
	}
	return cmd.PersistentFlags().GetDuration(name)
}

func flagInt(cmd *cobra.Command, name string) (int, error) {
	if cmd.Flags().Lookup(name) != nil {
		return cmd.Flags().GetInt(name)
	}
	return cmd.PersistentFlags().GetInt(name)
}
