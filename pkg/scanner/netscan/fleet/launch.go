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
	// Note: triton's scan is the ROOT command (not a subcommand), so the
	// invocation is `triton --detach ...` not `triton scan --detach ...`.
	parts = append(parts, remoteBinary, "--detach", "--quiet")

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
	if f.LicenseKey != "" {
		// Pass license via a shell-safe quoted form. The launch command
		// is executed via SSH which goes through a shell, so spaces and
		// shell metacharacters in the token (there shouldn't be any in
		// a real Ed25519-signed JSON license, but defense in depth)
		// would otherwise break argv splitting. Ed25519 tokens are
		// base64url + "." so they contain only [A-Za-z0-9._-]; single-
		// quoting is sufficient.
		parts = append(parts, "--license-key", "'"+f.LicenseKey+"'")
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
