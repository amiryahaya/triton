package agentconfig

import (
	"path/filepath"
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
