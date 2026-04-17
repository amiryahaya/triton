package limits

import (
	"testing"
	"time"
)

func TestLimitsZeroValueIsDisabled(t *testing.T) {
	var l Limits
	if l.Enabled() {
		t.Errorf("zero-value Limits should report Enabled() == false")
	}
}

func TestLimitsEnabled(t *testing.T) {
	cases := []struct {
		name string
		l    Limits
		want bool
	}{
		{"empty", Limits{}, false},
		{"memory set", Limits{MaxMemoryBytes: 1 << 20}, true},
		{"cpu set", Limits{MaxCPUPercent: 50}, true},
		{"duration set", Limits{MaxDuration: time.Second}, true},
		{"stop-at set", Limits{StopAtOffset: time.Hour}, true},
		{"nice set", Limits{Nice: 10}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.l.Enabled(); got != tc.want {
				t.Errorf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLimitsString(t *testing.T) {
	l := Limits{
		MaxMemoryBytes: 2 * (1 << 30),
		MaxCPUPercent:  50,
		MaxDuration:    4 * time.Hour,
		Nice:           10,
	}
	got := l.String()
	for _, want := range []string{"memory=2147483648", "cpu=50%", "duration=4h0m0s", "nice=10"} {
		if !containsSubstr(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}

func containsSubstr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
