package limits

import "runtime"

// ApplyCPUPercent caps GOMAXPROCS to max(1, NumCPU * pct / 100).
// Values outside (0,100] are a silent no-op.
func ApplyCPUPercent(pct int) {
	if pct <= 0 || pct > 100 {
		return
	}
	n := runtime.NumCPU() * pct / 100
	if n < 1 {
		n = 1
	}
	runtime.GOMAXPROCS(n)
}
