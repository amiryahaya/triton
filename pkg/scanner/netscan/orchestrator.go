// Package netscan orchestrator — full implementation in Task 17.
package netscan

import (
	"context"
	"time"
)

// Orchestrator runs per-device scans concurrently. Stub — implemented in Task 17.
type Orchestrator struct {
	Inventory        *Inventory
	Credentials      *CredentialStore
	Concurrency      int
	PerDeviceTimeout time.Duration
	ReportServerURL  string
}

// Scan is a stub — Task 17 implements the real worker pool.
func (o *Orchestrator) Scan(ctx context.Context, devices []Device) error {
	_ = ctx
	_ = devices
	return nil
}
