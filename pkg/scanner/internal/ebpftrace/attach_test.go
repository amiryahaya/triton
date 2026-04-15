package ebpftrace

import (
	"os"
	"sort"
	"strings"
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
	if len(libs) != 4 {
		t.Fatalf("len(libs) = %d, want 4 (libcrypto+deleted-libcrypto+libgnutls+spaced-libgnutls)", len(libs))
	}
	paths := make([]string, len(libs))
	for i, l := range libs {
		paths[i] = l.Path
	}
	sort.Strings(paths)
	want := []string{
		"/opt/my path/libgnutls.so.30",
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
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

func TestDiscoverLibs_HandlesDeletedSuffix(t *testing.T) {
	f, err := os.Open("testdata/fake_maps")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	libs, _ := DiscoverLibsFromMaps(f)
	foundDeleted := false
	for _, l := range libs {
		if l.Inode == "333" {
			foundDeleted = true
			if strings.HasSuffix(l.Path, "(deleted)") {
				t.Errorf("path still has (deleted) suffix: %q", l.Path)
			}
		}
	}
	if !foundDeleted {
		t.Error("expected to discover the (deleted) libcrypto by inode 333")
	}
}

func TestDiscoverLibs_HandlesPathsWithSpaces(t *testing.T) {
	f, err := os.Open("testdata/fake_maps")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	libs, _ := DiscoverLibsFromMaps(f)
	foundSpaced := false
	for _, l := range libs {
		if l.Path == "/opt/my path/libgnutls.so.30" {
			foundSpaced = true
		}
	}
	if !foundSpaced {
		t.Errorf("expected libgnutls at path with spaces; got paths: %v", pathsOf(libs))
	}
}

func TestDiscoverLibs_IgnoresPseudoMappings(t *testing.T) {
	f, err := os.Open("testdata/fake_maps")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	libs, _ := DiscoverLibsFromMaps(f)
	for _, l := range libs {
		if l.Path == "[vdso]" || l.Path == "[heap]" || l.Path == "[stack]" {
			t.Errorf("pseudo mapping should be ignored: %q", l.Path)
		}
	}
}

func pathsOf(libs []DiscoveredLib) []string {
	out := make([]string, len(libs))
	for i, l := range libs {
		out[i] = l.Path
	}
	return out
}
