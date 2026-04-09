package scanner

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckExternalTool_Found(t *testing.T) {
	t.Parallel()
	// Use a tool that exists on all platforms
	var tool string
	switch runtime.GOOS {
	case "windows":
		tool = "cmd"
	default:
		tool = "ls"
	}

	result := CheckExternalTool("test-module", tool, func(name string) (string, error) {
		return "/usr/bin/" + name, nil
	})

	assert.Equal(t, CheckPass, result.Status)
	assert.Equal(t, "test-module", result.Module)
	assert.Contains(t, result.CheckName, tool)
	assert.Contains(t, result.Message, "/usr/bin/"+tool)
	assert.Empty(t, result.Suggestion)
}

func TestCheckExternalTool_NotFound(t *testing.T) {
	t.Parallel()
	result := CheckExternalTool("packages", "brew", func(name string) (string, error) {
		return "", &os.PathError{Op: "lookpath", Path: name, Err: os.ErrNotExist}
	})

	assert.Equal(t, CheckWarn, result.Status)
	assert.Equal(t, "packages", result.Module)
	assert.Contains(t, result.CheckName, "brew")
	assert.Contains(t, result.Message, "not found")
	assert.NotEmpty(t, result.Suggestion)
}

func TestCheckFilesystemAccess_Readable(t *testing.T) {
	t.Parallel()
	// Use temp dir which always exists and is readable
	dir := t.TempDir()

	result := CheckFilesystemAccess("certificates", dir)

	assert.Equal(t, CheckPass, result.Status)
	assert.Equal(t, "certificates", result.Module)
	assert.Contains(t, result.Message, "Readable")
}

func TestCheckFilesystemAccess_NonExistent(t *testing.T) {
	t.Parallel()
	result := CheckFilesystemAccess("certificates", "/nonexistent/path/that/does/not/exist")

	assert.Equal(t, CheckFail, result.Status)
	assert.Contains(t, result.Message, "not found")
	assert.NotEmpty(t, result.Suggestion)
}

func TestCheckFilesystemAccess_PermissionDenied(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Permission test not reliable on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("Test cannot run as root")
	}

	// Create a directory with no read permission
	dir := t.TempDir()
	noReadDir := dir + "/noaccess"
	require.NoError(t, os.Mkdir(noReadDir, 0o000))
	t.Cleanup(func() { os.Chmod(noReadDir, 0o755) })

	result := CheckFilesystemAccess("certificates", noReadDir)

	assert.Equal(t, CheckWarn, result.Status)
	assert.Contains(t, result.Message, "permission denied")
	assert.NotEmpty(t, result.Suggestion)
}

func TestCheckElevatedPermissions_NotRoot(t *testing.T) {
	t.Parallel()
	result := CheckElevatedPermissions(func() int { return 1000 })

	assert.Equal(t, CheckWarn, result.Status)
	assert.Contains(t, result.Message, "Not running as root")
	assert.NotEmpty(t, result.Suggestion)
}

func TestCheckElevatedPermissions_Root(t *testing.T) {
	t.Parallel()
	result := CheckElevatedPermissions(func() int { return 0 })

	assert.Equal(t, CheckPass, result.Status)
	assert.Contains(t, result.Message, "Running as root")
}

func TestCheckGoTLS(t *testing.T) {
	t.Parallel()
	result := CheckGoTLS()

	assert.Equal(t, CheckPass, result.Status)
	assert.Equal(t, "protocol", result.Module)
	assert.Contains(t, result.Message, "cipher suites")
}

func TestDoctorReport_HasFailures_True(t *testing.T) {
	t.Parallel()
	r := &DoctorReport{FailCount: 1}
	assert.True(t, r.HasFailures())
}

func TestDoctorReport_HasFailures_False(t *testing.T) {
	t.Parallel()
	r := &DoctorReport{FailCount: 0, WarnCount: 3}
	assert.False(t, r.HasFailures())
}

func TestDoctorReport_Counts(t *testing.T) {
	t.Parallel()
	r := &DoctorReport{
		Checks: []CheckResult{
			{Status: CheckPass},
			{Status: CheckPass},
			{Status: CheckWarn},
			{Status: CheckFail},
			{Status: CheckPass},
		},
	}
	r.computeCounts()

	assert.Equal(t, 3, r.PassCount)
	assert.Equal(t, 1, r.WarnCount)
	assert.Equal(t, 1, r.FailCount)
}

func TestRunDoctorChecks_QuickProfile(t *testing.T) {
	t.Parallel()
	report := RunDoctorChecks("quick")

	assert.Equal(t, runtime.GOOS+"/"+runtime.GOARCH, report.Platform)
	assert.Equal(t, "quick", report.Profile)
	assert.NotEmpty(t, report.Checks)

	// Quick profile has certificates, keys, packages — no network/processes/protocol
	for _, c := range report.Checks {
		assert.NotEqual(t, "network", c.Module, "quick profile should not check network")
		assert.NotEqual(t, "processes", c.Module, "quick profile should not check processes")
		assert.NotEqual(t, "protocol", c.Module, "quick profile should not check protocol")
	}
}

func TestRunDoctorChecks_ComprehensiveProfile(t *testing.T) {
	t.Parallel()
	report := RunDoctorChecks("comprehensive")

	assert.Equal(t, "comprehensive", report.Profile)
	assert.NotEmpty(t, report.Checks)

	// Comprehensive should have more checks than quick
	quickReport := RunDoctorChecks("quick")
	assert.Greater(t, len(report.Checks), len(quickReport.Checks))

	// Should include network/processes checks
	modulesSeen := make(map[string]bool)
	for _, c := range report.Checks {
		modulesSeen[c.Module] = true
	}

	if runtime.GOOS != "windows" {
		assert.True(t, modulesSeen["processes"], "comprehensive should check processes")
		assert.True(t, modulesSeen["network"], "comprehensive should check network")
		assert.True(t, modulesSeen["protocol"], "comprehensive should check protocol")
	}
}

func TestRunDoctorChecks_InvalidProfile(t *testing.T) {
	t.Parallel()
	// Invalid profile falls back to standard
	report := RunDoctorChecks("nonexistent")
	assert.Equal(t, "standard", report.Profile)
}

func TestCheckStatus_String(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "PASS", CheckPass.String())
	assert.Equal(t, "WARN", CheckWarn.String())
	assert.Equal(t, "FAIL", CheckFail.String())
}
