package scanner

import (
	"crypto/tls"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/model"
)

// CheckStatus represents the result status of a doctor check.
type CheckStatus int

const (
	CheckPass CheckStatus = iota
	CheckWarn
	CheckFail
)

func (s CheckStatus) String() string {
	switch s {
	case CheckPass:
		return "PASS"
	case CheckWarn:
		return "WARN"
	case CheckFail:
		return "FAIL"
	default:
		return "UNKNOWN"
	}
}

// CheckResult holds the outcome of a single doctor check.
type CheckResult struct {
	Module     string
	CheckName  string
	Status     CheckStatus
	Message    string
	Suggestion string
}

// DoctorReport aggregates all check results.
type DoctorReport struct {
	Platform  string
	Profile   string
	Checks    []CheckResult
	PassCount int
	WarnCount int
	FailCount int
}

// HasFailures returns true if any check has failed.
func (r *DoctorReport) HasFailures() bool {
	return r.FailCount > 0
}

func (r *DoctorReport) computeCounts() {
	r.PassCount = 0
	r.WarnCount = 0
	r.FailCount = 0
	for _, c := range r.Checks {
		switch c.Status {
		case CheckPass:
			r.PassCount++
		case CheckWarn:
			r.WarnCount++
		case CheckFail:
			r.FailCount++
		}
	}
}

// moduleDependencies maps module names to external tools required per platform.
func moduleDependencies() map[string][]platformTool {
	return map[string][]platformTool{
		"packages": {
			{os: "darwin", tool: "brew"},
			{os: "linux", tool: "dpkg-query"},
			{os: "linux", tool: "rpm"},
		},
		"processes": {
			{os: "darwin", tool: "ps"},
			{os: "linux", tool: "ps"},
		},
		"network": {
			{os: "darwin", tool: "lsof"},
			{os: "linux", tool: "ss"},
			{os: "linux", tool: "lsof"},
		},
	}
}

type platformTool struct {
	os   string
	tool string
}

// CheckExternalTool checks if an external tool is available in PATH.
func CheckExternalTool(module, tool string, lookupFunc func(string) (string, error)) CheckResult {
	path, err := lookupFunc(tool)
	if err != nil {
		return CheckResult{
			Module:     module,
			CheckName:  tool + " available",
			Status:     CheckWarn,
			Message:    tool + " not found in PATH",
			Suggestion: fmt.Sprintf("Install %s for %s module to work. Module will be skipped without it.", tool, module),
		}
	}
	return CheckResult{
		Module:    module,
		CheckName: tool + " available",
		Status:    CheckPass,
		Message:   path,
	}
}

// CheckFilesystemAccess checks if a directory is readable.
func CheckFilesystemAccess(module, path string) CheckResult {
	checkName := fmt.Sprintf("Read %s", path)

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return CheckResult{
			Module:     module,
			CheckName:  checkName,
			Status:     CheckFail,
			Message:    path + " not found",
			Suggestion: "Scan target does not exist. Findings for this path will be empty.",
		}
	}
	if err != nil {
		return CheckResult{
			Module:     module,
			CheckName:  checkName,
			Status:     CheckWarn,
			Message:    fmt.Sprintf("%s — %s", path, err),
			Suggestion: "Run with elevated permissions or adjust directory permissions.",
		}
	}

	// Check if we can actually open it
	if info.IsDir() {
		f, openErr := os.Open(path)
		if openErr != nil {
			return CheckResult{
				Module:     module,
				CheckName:  checkName,
				Status:     CheckWarn,
				Message:    path + " — permission denied",
				Suggestion: "Run with elevated permissions or adjust directory permissions.",
			}
		}
		f.Close()
	}

	return CheckResult{
		Module:    module,
		CheckName: checkName,
		Status:    CheckPass,
		Message:   "Readable",
	}
}

// CheckElevatedPermissions checks if the process is running as root (Unix only).
func CheckElevatedPermissions(getUID func() int) CheckResult {
	if runtime.GOOS == "windows" {
		return CheckResult{
			Module:    "system",
			CheckName: "Elevated permissions",
			Status:    CheckPass,
			Message:   "Permission check skipped on Windows",
		}
	}

	uid := getUID()
	if uid == 0 {
		return CheckResult{
			Module:    "system",
			CheckName: "Elevated permissions",
			Status:    CheckPass,
			Message:   "Running as root",
		}
	}
	return CheckResult{
		Module:     "system",
		CheckName:  "Elevated permissions",
		Status:     CheckWarn,
		Message:    "Not running as root",
		Suggestion: "Some processes and network connections may not be visible. Run with sudo for complete results.",
	}
}

// CheckGoTLS verifies that Go's TLS cipher suites are available.
func CheckGoTLS() CheckResult {
	suites := tls.CipherSuites()
	return CheckResult{
		Module:    "protocol",
		CheckName: "Go TLS available",
		Status:    CheckPass,
		Message:   fmt.Sprintf("%d cipher suites available", len(suites)),
	}
}

// RunDoctorChecks runs all readiness checks for the given profile.
func RunDoctorChecks(profile string) *DoctorReport {
	cfg := config.Load(profile)

	report := &DoctorReport{
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Profile:  cfg.Profile,
	}

	activeModules := make(map[string]bool)
	for _, m := range cfg.Modules {
		activeModules[m] = true
	}

	// 1. Filesystem access checks — map modules to their scan targets
	fsModules := filesystemModules()
	for _, target := range cfg.ScanTargets {
		if target.Type != model.TargetFilesystem {
			continue
		}
		// Find which modules use filesystem targets
		for _, modName := range fsModules {
			if !activeModules[modName] {
				continue
			}
			report.Checks = append(report.Checks, CheckFilesystemAccess(modName, target.Value))
			break // One check per target path is enough
		}
	}

	// 2. External tool checks (sorted for deterministic output)
	deps := moduleDependencies()
	depModules := make([]string, 0, len(deps))
	for modName := range deps {
		depModules = append(depModules, modName)
	}
	sort.Strings(depModules)

	for _, modName := range depModules {
		if !activeModules[modName] {
			continue
		}
		for _, pt := range deps[modName] {
			if pt.os != runtime.GOOS {
				continue
			}
			report.Checks = append(report.Checks, CheckExternalTool(modName, pt.tool, exec.LookPath))
		}
	}

	// 3. Elevated permissions check (for processes/network)
	needsElevated := activeModules["processes"] || activeModules["network"]
	if needsElevated && runtime.GOOS != "windows" {
		result := CheckElevatedPermissions(os.Getuid)
		// Associate with each module that benefits
		if activeModules["processes"] {
			r := result
			r.Module = "processes"
			report.Checks = append(report.Checks, r)
		}
		if activeModules["network"] {
			r := result
			r.Module = "network"
			report.Checks = append(report.Checks, r)
		}
	}

	// 4. Go TLS check (for protocol module)
	if activeModules["protocol"] {
		report.Checks = append(report.Checks, CheckGoTLS())
	}

	report.computeCounts()
	return report
}

// filesystemModules returns modules that scan filesystem targets.
func filesystemModules() []string {
	return []string{
		"certificates", "keys", "libraries", "binaries",
		"kernel", "scripts", "webapp",
	}
}
