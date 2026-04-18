package fleet

import (
	"fmt"
	"regexp"
	"strings"
)

// uuidPattern matches a canonical UUIDv4 string.
var uuidPattern = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// BuildLaunchCommand assembles the remote `triton scan --detach --quiet
// [forwarded flags]` command string. Prepends `sudo ` if useSudo is true.
// Omits empty/zero ScanFlags fields.
func BuildLaunchCommand(remoteBinary string, useSudo bool, f ScanFlags) string {
	parts := []string{}
	if useSudo {
		parts = append(parts, "sudo")
	}
	parts = append(parts, remoteBinary, "scan", "--detach", "--quiet")

	if f.Profile != "" {
		parts = append(parts, "--profile", f.Profile)
	}
	if f.Format != "" {
		parts = append(parts, "--format", f.Format)
	}
	if f.Policy != "" {
		parts = append(parts, "--policy", f.Policy)
	}
	if f.MaxMemory != "" {
		parts = append(parts, "--max-memory", f.MaxMemory)
	}
	if f.MaxCPUPercent != "" {
		parts = append(parts, "--max-cpu-percent", f.MaxCPUPercent)
	}
	if f.MaxDuration > 0 {
		parts = append(parts, "--max-duration", f.MaxDuration.String())
	}
	if f.StopAt != "" {
		parts = append(parts, "--stop-at", f.StopAt)
	}
	if f.Nice != 0 {
		parts = append(parts, "--nice", fmt.Sprintf("%d", f.Nice))
	}

	return strings.Join(parts, " ")
}

// ParseJobID extracts the UUID from the output of `triton scan --detach
// --quiet`. Handles both --quiet (bare UUID on stdout) and non-quiet
// ("Detached as job <uuid>\npid N...") formats by matching the first
// UUID-shaped string in the output.
func ParseJobID(out string) (string, error) {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return "", fmt.Errorf("empty launch output")
	}
	match := uuidPattern.FindString(out)
	if match == "" {
		return "", fmt.Errorf("no job-id (UUID) in launch output: %q", trimmed)
	}
	return match, nil
}
