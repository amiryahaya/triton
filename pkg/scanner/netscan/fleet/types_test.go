package fleet

import (
	"errors"
	"testing"
	"time"
)

func TestHostResult_IsSuccess(t *testing.T) {
	cases := []struct {
		name string
		r    HostResult
		want bool
	}{
		{"empty", HostResult{}, false},
		{"error set", HostResult{Err: errors.New("boom")}, false},
		{"phase set but no err", HostResult{Phase: "launch"}, false},
		{"success", HostResult{Device: "web-1", JobID: "abc"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.IsSuccess(); got != tc.want {
				t.Errorf("IsSuccess() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHostResult_Fail(t *testing.T) {
	r := HostResult{Device: "web-1"}
	r.Fail("scp binary", errors.New("permission denied"))
	if r.Phase != "scp binary" {
		t.Errorf("Phase = %q, want %q", r.Phase, "scp binary")
	}
	if r.Err == nil || r.Err.Error() != "permission denied" {
		t.Errorf("Err = %v, want 'permission denied'", r.Err)
	}
}

func TestFleetConfig_ValidateRequiresOutput(t *testing.T) {
	cfg := FleetConfig{
		InventoryPath:   "x",
		CredentialsPath: "y",
		Concurrency:     1,
		DeviceTimeout:   time.Minute,
	}
	// Neither output-dir nor report-server nor dry-run set.
	if err := cfg.Validate(); err == nil {
		t.Error("Validate should require at least one of OutputDir, ReportServerURL, DryRun")
	}
	cfg.DryRun = true
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate with DryRun should succeed, got: %v", err)
	}
}

func TestFleetConfig_ValidateConcurrency(t *testing.T) {
	cfg := FleetConfig{
		InventoryPath:   "x",
		CredentialsPath: "y",
		OutputDir:       "z",
		DeviceTimeout:   time.Minute,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("Validate should reject zero Concurrency")
	}
	cfg.Concurrency = 20
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate with Concurrency=20 should succeed, got: %v", err)
	}
}
