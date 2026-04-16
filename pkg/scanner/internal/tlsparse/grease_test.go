package tlsparse

import (
	"testing"
)

func TestIsGREASE(t *testing.T) {
	grease := []uint16{
		0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
		0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
		0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
	}
	for _, v := range grease {
		if !IsGREASE(v) {
			t.Errorf("IsGREASE(%#04x) = false, want true", v)
		}
	}

	nonGREASE := []uint16{
		0x0000, 0x0001, 0x002f, 0x0035, 0x1301, 0x1302, 0x1303,
		0xc02b, 0xc02c, 0xff01, 0x0b0b, 0x1b1b,
	}
	for _, v := range nonGREASE {
		if IsGREASE(v) {
			t.Errorf("IsGREASE(%#04x) = true, want false", v)
		}
	}
}

func TestFilterGREASE(t *testing.T) {
	input := []uint16{0x0a0a, 0x1301, 0xfafa, 0xc02b, 0x2a2a}
	got := FilterGREASE(input)
	want := []uint16{0x1301, 0xc02b}

	if len(got) != len(want) {
		t.Fatalf("FilterGREASE len = %d, want %d; got %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("FilterGREASE[%d] = %#04x, want %#04x", i, got[i], want[i])
		}
	}
}

func TestFilterGREASE_Empty(t *testing.T) {
	got := FilterGREASE(nil)
	if got != nil && len(got) != 0 {
		t.Errorf("FilterGREASE(nil) = %v, want nil or empty", got)
	}
}

func TestFilterGREASE_AllGREASE(t *testing.T) {
	input := []uint16{0x0a0a, 0x1a1a, 0xfafa}
	got := FilterGREASE(input)
	if len(got) != 0 {
		t.Errorf("FilterGREASE(all GREASE) = %v, want empty", got)
	}
}
