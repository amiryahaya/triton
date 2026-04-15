package ebpftrace

import (
	"os"
	"sort"
	"testing"
)

func TestDiscoverLibs_DedupsByInode(t *testing.T) {
	f, err := os.Open("testdata/fake_maps")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	libs, err := DiscoverLibsFromMaps(f)
	if err != nil {
		t.Fatalf("DiscoverLibsFromMaps: %v", err)
	}
	if len(libs) != 2 {
		t.Fatalf("len(libs) = %d, want 2 (libcrypto dedup'd, libgnutls)", len(libs))
	}
	paths := make([]string, len(libs))
	for i, l := range libs {
		paths[i] = l.Path
	}
	sort.Strings(paths)
	want := []string{
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
		"/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
	}
	for i, p := range paths {
		if p != want[i] {
			t.Errorf("paths[%d] = %q, want %q", i, p, want[i])
		}
	}
}

func TestDiscoverLibs_IgnoresNonCryptoLibs(t *testing.T) {
	f, err := os.Open("testdata/fake_maps")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	libs, err := DiscoverLibsFromMaps(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range libs {
		if l.Path == "/usr/lib/x86_64-linux-gnu/libc.so.6" {
			t.Error("libc.so.6 should not be returned")
		}
		if l.Path == "/usr/bin/nginx" {
			t.Error("nginx executable should not be returned")
		}
	}
}
