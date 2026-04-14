// Package netadapter provides transports and vendor adapters for
// agentless scanning of Unix hosts and network devices.
package netadapter

import "context"

// CommandRunner executes a command and returns its combined stdout.
// Implementations handle transport details (SSH, timeouts, etc.).
type CommandRunner interface {
	Run(ctx context.Context, command string) (string, error)
	Close() error
}
