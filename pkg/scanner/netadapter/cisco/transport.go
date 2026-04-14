// Package cisco implements the Cisco IOS-XE agentless scanner adapter.
package cisco

import (
	"context"
	"fmt"
	"strings"

	"github.com/amiryahaya/triton/pkg/scanner/netadapter/transport"
)

// CiscoRunner wraps an SSH client with Cisco-specific CLI handling:
// disables paging before the first user command, optionally enters
// enable mode.
type CiscoRunner struct {
	ssh            *transport.SSHClient
	enablePassword string
	pagingDisabled bool
}

// NewCiscoRunner creates a runner. enablePassword may be empty if no
// privileged commands are needed.
func NewCiscoRunner(ssh *transport.SSHClient, enablePassword string) *CiscoRunner {
	return &CiscoRunner{ssh: ssh, enablePassword: enablePassword}
}

// Run executes a show command. First call also issues `terminal length 0`
// to disable paging; otherwise commands with long output would hang.
func (c *CiscoRunner) Run(ctx context.Context, command string) (string, error) {
	if !c.pagingDisabled {
		if _, err := c.ssh.Run(ctx, "terminal length 0"); err != nil {
			return "", fmt.Errorf("disable paging: %w", err)
		}
		c.pagingDisabled = true
	}
	out, err := c.ssh.Run(ctx, command)
	if err != nil {
		return out, err
	}
	return stripCLINoise(out), nil
}

// Close releases the underlying SSH connection.
func (c *CiscoRunner) Close() error {
	return c.ssh.Close()
}

// stripCLINoise removes echoed command and trailing prompt from output.
func stripCLINoise(out string) string {
	lines := strings.Split(out, "\n")
	if len(lines) > 0 {
		last := strings.TrimSpace(lines[len(lines)-1])
		if strings.HasSuffix(last, "#") || strings.HasSuffix(last, ">") {
			lines = lines[:len(lines)-1]
		}
	}
	return strings.Join(lines, "\n")
}
