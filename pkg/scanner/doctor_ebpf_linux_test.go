//go:build linux

package scanner

import "testing"

func TestAtLeastKernel58(t *testing.T) {
	cases := map[string]bool{
		"5.8.0":             true,
		"5.7.999":           false,
		"5.15.0-91-generic": true,
		"6.0.0-rc1":         true,
		"5":                 false, // missing minor
		"":                  false,
		"invalid":           false,
		"5.8":               true,
		"5.7":               false,
		"10.0.0":            true,
		"4.19.0":            false,
		"5.0.0":             false,
	}
	for in, want := range cases {
		if got := atLeastKernel58(in); got != want {
			t.Errorf("atLeastKernel58(%q) = %v, want %v", in, got, want)
		}
	}
}
