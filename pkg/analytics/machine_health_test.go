package analytics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/amiryahaya/triton/pkg/store"
)

func TestComputeMachineHealth_EmptySlice(t *testing.T) {
	got := ComputeMachineHealth(nil)
	assert.Equal(t, 0, got.Red)
	assert.Equal(t, 0, got.Yellow)
	assert.Equal(t, 0, got.Green)
	assert.Equal(t, 0, got.Total)
}

func TestComputeMachineHealth_SingleRedAnyUnsafe(t *testing.T) {
	machines := []store.ScanSummary{
		scanSummaryAt("host-1", time.Now(), 100, 0, 0, 1),
	}
	got := ComputeMachineHealth(machines)
	assert.Equal(t, store.MachineHealthTiers{Red: 1, Total: 1}, got)
}

func TestComputeMachineHealth_SingleYellowDeprecatedOnly(t *testing.T) {
	machines := []store.ScanSummary{
		scanSummaryAt("host-1", time.Now(), 50, 0, 3, 0),
	}
	got := ComputeMachineHealth(machines)
	assert.Equal(t, store.MachineHealthTiers{Yellow: 1, Total: 1}, got)
}

func TestComputeMachineHealth_SingleGreenZeroFindings(t *testing.T) {
	machines := []store.ScanSummary{
		scanSummaryAt("host-1", time.Now(), 0, 0, 0, 0),
	}
	got := ComputeMachineHealth(machines)
	assert.Equal(t, store.MachineHealthTiers{Green: 1, Total: 1}, got)
}

func TestComputeMachineHealth_SingleGreenOnlySafeAndTransitional(t *testing.T) {
	machines := []store.ScanSummary{
		scanSummaryAt("host-1", time.Now(), 80, 15, 0, 0),
	}
	got := ComputeMachineHealth(machines)
	assert.Equal(t, store.MachineHealthTiers{Green: 1, Total: 1}, got)
}

func TestComputeMachineHealth_MixedTiersCountCorrectly(t *testing.T) {
	now := time.Now()
	machines := []store.ScanSummary{
		scanSummaryAt("host-1", now, 10, 0, 0, 5),  // red (unsafe > 0)
		scanSummaryAt("host-2", now, 20, 0, 3, 0),  // yellow
		scanSummaryAt("host-3", now, 100, 0, 0, 0), // green
		scanSummaryAt("host-4", now, 0, 0, 0, 0),   // green (zero findings)
		scanSummaryAt("host-5", now, 50, 20, 0, 1), // red
		scanSummaryAt("host-6", now, 30, 10, 5, 0), // yellow
	}
	got := ComputeMachineHealth(machines)
	assert.Equal(t, store.MachineHealthTiers{Red: 2, Yellow: 2, Green: 2, Total: 6}, got)
}

func TestComputeMachineHealth_UnsafeWinsOverDeprecated(t *testing.T) {
	// A machine with BOTH unsafe AND deprecated findings is RED,
	// not yellow. Red takes precedence.
	machines := []store.ScanSummary{
		scanSummaryAt("host-1", time.Now(), 10, 0, 20, 1),
	}
	got := ComputeMachineHealth(machines)
	assert.Equal(t, store.MachineHealthTiers{Red: 1, Total: 1}, got)
}
