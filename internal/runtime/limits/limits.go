// Package limits provides in-process resource limits for triton scans.
//
// The Limits struct bundles memory, CPU, duration, and scheduling priority
// caps. A single Apply() call installs all configured limits and returns a
// context whose deadline matches MaxDuration/StopAtOffset (tightest wins) plus
// a cleanup function that must be deferred by the caller.
//
// All fields are optional. A zero-value Limits is a no-op; Enabled() returns
// false and Apply() returns the input context unchanged plus a no-op cleanup.
package limits

import (
	"fmt"
	"strings"
	"time"
)

// Limits bundles all in-process resource caps that Apply() installs.
// Zero values mean "no limit" for that dimension.
type Limits struct {
	// MaxMemoryBytes is the soft memory limit installed via
	// runtime/debug.SetMemoryLimit. A hard watchdog kills the process at
	// 1.5x this value. Zero disables both.
	MaxMemoryBytes int64

	// MaxCPUPercent caps GOMAXPROCS to max(1, NumCPU*pct/100). Values
	// outside (0,100] are ignored.
	MaxCPUPercent int

	// MaxDuration is the wall-clock budget for the scan. Translates to
	// context.WithTimeout on the context returned by Apply.
	MaxDuration time.Duration

	// StopAtOffset is an alternative expression of MaxDuration: computed
	// at flag-parse time from --stop-at HH:MM as "duration until that
	// clock time today (or tomorrow if already past)". If both are set,
	// the smaller of the two wins.
	StopAtOffset time.Duration

	// Nice is passed to syscall.Setpriority (unix only). Range is
	// typically [-20, 19]; higher = nicer = lower priority. Zero skips.
	Nice int
}

// Enabled reports whether any limit is configured.
func (l Limits) Enabled() bool {
	return l.MaxMemoryBytes > 0 ||
		l.MaxCPUPercent > 0 ||
		l.MaxDuration > 0 ||
		l.StopAtOffset > 0 ||
		l.Nice != 0
}

// String produces a single-line human summary for startup logs.
func (l Limits) String() string {
	if !l.Enabled() {
		return "limits=none"
	}
	parts := []string{"limits:"}
	if l.MaxMemoryBytes > 0 {
		parts = append(parts, fmt.Sprintf("memory=%d", l.MaxMemoryBytes))
	}
	if l.MaxCPUPercent > 0 {
		parts = append(parts, fmt.Sprintf("cpu=%d%%", l.MaxCPUPercent))
	}
	if d := l.effectiveDuration(); d > 0 {
		parts = append(parts, fmt.Sprintf("duration=%s", d))
	}
	if l.Nice != 0 {
		parts = append(parts, fmt.Sprintf("nice=%d", l.Nice))
	}
	return strings.Join(parts, " ")
}

// effectiveDuration returns the tighter of MaxDuration and StopAtOffset, or
// zero if neither is set.
func (l Limits) effectiveDuration() time.Duration {
	switch {
	case l.MaxDuration > 0 && l.StopAtOffset > 0:
		if l.MaxDuration < l.StopAtOffset {
			return l.MaxDuration
		}
		return l.StopAtOffset
	case l.MaxDuration > 0:
		return l.MaxDuration
	case l.StopAtOffset > 0:
		return l.StopAtOffset
	default:
		return 0
	}
}
