package limits

import (
	"runtime"
	"testing"
)

func TestApplyCPUPercent(t *testing.T) {
	origProcs := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(origProcs) })

	numCPU := runtime.NumCPU()
	cases := []struct {
		name    string
		percent int
		want    int
	}{
		{"zero disables", 0, origProcs}, // no change
		{"100%", 100, numCPU},
		{"50%", 50, max(1, numCPU*50/100)},
		{"1%", 1, 1},                           // clamped to at least 1
		{"over-range ignored", 200, origProcs}, // no change, no panic
		{"negative ignored", -1, origProcs},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GOMAXPROCS(origProcs) // reset
			ApplyCPUPercent(tc.percent)
			got := runtime.GOMAXPROCS(0)
			if got != tc.want {
				t.Errorf("ApplyCPUPercent(%d) → GOMAXPROCS=%d, want %d (numCPU=%d)",
					tc.percent, got, tc.want, numCPU)
			}
		})
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
