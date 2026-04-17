package limits

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// ParseSize parses a size string like "2GB" into bytes. Supports KB/MB/GB/TB
// suffixes (case-insensitive, optional space). Bare integer is bytes. Empty
// string returns (0, nil). Fractional values are not supported.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	upper := strings.ToUpper(strings.ReplaceAll(s, " ", ""))

	var mult int64 = 1
	for _, suf := range []struct {
		unit string
		val  int64
	}{
		{"TB", 1 << 40},
		{"GB", 1 << 30},
		{"MB", 1 << 20},
		{"KB", 1 << 10},
	} {
		if strings.HasSuffix(upper, suf.unit) {
			mult = suf.val
			upper = strings.TrimSuffix(upper, suf.unit)
			break
		}
	}
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid size %q: must be non-negative", s)
	}
	if mult > 1 && n > math.MaxInt64/mult {
		return 0, fmt.Errorf("invalid size %q: value overflows int64", s)
	}
	return n * mult, nil
}

// ParsePercent parses an integer in [0,100]. Accepts trailing "%" for human
// input. Empty string returns (0, nil).
func ParsePercent(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	orig := s
	s = strings.TrimSuffix(s, "%")
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid percent %q: %w", orig, err)
	}
	if n < 0 || n > 100 {
		return 0, fmt.Errorf("invalid percent %q: must be in [0,100]", orig)
	}
	return n, nil
}

// ParseStopAt parses a clock time "HH:MM" into a duration from `now` until
// that time today. If the time is at or before `now`, rolls over to tomorrow.
// Empty string returns (0, nil). Uses the local location of `now`.
func ParseStopAt(s string, now time.Time) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	t, err := time.ParseInLocation("15:04", s, now.Location())
	if err != nil {
		return 0, fmt.Errorf("invalid stop-at %q (expect HH:MM): %w", s, err)
	}
	target := time.Date(now.Year(), now.Month(), now.Day(),
		t.Hour(), t.Minute(), 0, 0, now.Location())
	if !target.After(now) {
		target = target.Add(24 * time.Hour)
	}
	return target.Sub(now), nil
}
