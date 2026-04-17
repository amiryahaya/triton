package limits

import (
	"testing"
	"time"
)

func TestParseSize(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"1024", 1024, false},
		{"1KB", 1 << 10, false},
		{"1MB", 1 << 20, false},
		{"1GB", 1 << 30, false},
		{"2GB", 2 << 30, false},
		{"512MB", 512 << 20, false},
		{"1kb", 1 << 10, false},
		{"1 GB", 1 << 30, false},
		{"  2MB  ", 2 << 20, false},
		{"1TB", 1 << 40, false},
		{"1.5GB", 0, true}, // fractional unsupported — keep it simple
		{"GB", 0, true},
		{"1ZB", 0, true},
		{"-1GB", 0, true},
		{"abc", 0, true},
		{"9999999TB", 0, true}, // overflow
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseSize(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseSize(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParsePercent(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"50", 50, false},
		{"100", 100, false},
		{"1", 1, false},
		{"101", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
		{"50%", 50, false}, // accept trailing % for human convenience
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParsePercent(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParsePercent(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("ParsePercent(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseStopAt(t *testing.T) {
	// Fixed reference time: 2026-04-17 14:00:00 UTC
	now := time.Date(2026, 4, 17, 14, 0, 0, 0, time.UTC)
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"15:00", 1 * time.Hour, false},                // later today
		{"14:00", 24 * time.Hour, false},               // exactly now → tomorrow
		{"13:00", 23 * time.Hour, false},               // earlier → tomorrow
		{"23:59", 9*time.Hour + 59*time.Minute, false}, // late today
		{"00:00", 10 * time.Hour, false},               // midnight → tomorrow
		{"25:00", 0, true},
		{"abc", 0, true},
		{"15", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseStopAt(tc.in, now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseStopAt(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("ParseStopAt(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}
