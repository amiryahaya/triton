package cmd

import (
	"testing"
	"time"
)

// TestBuildLimitsFromFlags verifies the flag-value → Limits struct conversion.
// Does not test Cobra wiring; that's integration territory.
func TestBuildLimitsFromFlags(t *testing.T) {
	cases := []struct {
		name          string
		maxMemory     string
		maxCPUPercent string
		maxDuration   time.Duration
		stopAt        string
		nice          int
		wantMem       int64
		wantCPU       int
		wantDur       time.Duration
		wantStopSet   bool // stop-at should produce non-zero offset when set
		wantNice      int
		wantErr       bool
	}{
		{
			name: "all empty", wantErr: false,
		},
		{
			name:      "memory and cpu",
			maxMemory: "2GB", maxCPUPercent: "50",
			wantMem: 2 << 30, wantCPU: 50,
		},
		{
			name:        "duration",
			maxDuration: 4 * time.Hour,
			wantDur:     4 * time.Hour,
		},
		{
			name:        "stop-at at 23:59",
			stopAt:      "23:59",
			wantStopSet: true,
		},
		{
			name:      "invalid memory",
			maxMemory: "nope",
			wantErr:   true,
		},
		{
			name:          "invalid percent",
			maxCPUPercent: "200",
			wantErr:       true,
		},
		{
			name: "nice",
			nice: 10, wantNice: 10,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildLimits(tc.maxMemory, tc.maxCPUPercent, tc.maxDuration, tc.stopAt, tc.nice)
			if (err != nil) != tc.wantErr {
				t.Fatalf("buildLimits err=%v, wantErr=%v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got.MaxMemoryBytes != tc.wantMem {
				t.Errorf("MaxMemoryBytes=%d want %d", got.MaxMemoryBytes, tc.wantMem)
			}
			if got.MaxCPUPercent != tc.wantCPU {
				t.Errorf("MaxCPUPercent=%d want %d", got.MaxCPUPercent, tc.wantCPU)
			}
			if got.MaxDuration != tc.wantDur {
				t.Errorf("MaxDuration=%v want %v", got.MaxDuration, tc.wantDur)
			}
			if (got.StopAtOffset > 0) != tc.wantStopSet {
				t.Errorf("StopAtOffset=%v wantStopSet=%v", got.StopAtOffset, tc.wantStopSet)
			}
			if got.Nice != tc.wantNice {
				t.Errorf("Nice=%d want %d", got.Nice, tc.wantNice)
			}
		})
	}
}
