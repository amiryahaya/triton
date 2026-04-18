package fleet

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

func TestParseUnameArch(t *testing.T) {
	cases := []struct {
		in   string
		goos string
		arch string
	}{
		{"Linux x86_64", "linux", "amd64"},
		{"Linux x86_64\n", "linux", "amd64"},
		{"Linux aarch64", "linux", "arm64"},
		{"Darwin x86_64", "darwin", "amd64"},
		{"Darwin arm64", "darwin", "arm64"},
		{"FreeBSD amd64", "freebsd", "amd64"},
		{"AIX ppc64", "aix", "ppc64"},
		{"SunOS i86pc", "solaris", "amd64"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			goos, arch, err := ParseUnameArch(tc.in)
			if err != nil {
				t.Fatalf("ParseUnameArch(%q): %v", tc.in, err)
			}
			if goos != tc.goos || arch != tc.arch {
				t.Errorf("got %s/%s, want %s/%s", goos, arch, tc.goos, tc.arch)
			}
		})
	}
}

func TestParseUnameArch_Invalid(t *testing.T) {
	cases := []string{"", "Linux", "just one word"}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			if _, _, err := ParseUnameArch(tc); err == nil {
				t.Errorf("ParseUnameArch(%q) should fail", tc)
			}
		})
	}
}

func TestResolveBinary_DeviceOverride(t *testing.T) {
	tmp := t.TempDir()
	devBin := filepath.Join(tmp, "triton-aix")
	os.WriteFile(devBin, []byte("fake binary"), 0o755)

	globalBin := filepath.Join(tmp, "triton-global")
	os.WriteFile(globalBin, []byte("fake binary"), 0o755)

	d := &netscan.Device{Binary: devBin}
	got, err := ResolveBinary(d, globalBin, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got != devBin {
		t.Errorf("ResolveBinary with device override: got %q, want %q", got, devBin)
	}
}

func TestResolveBinary_GlobalFallback(t *testing.T) {
	tmp := t.TempDir()
	globalBin := filepath.Join(tmp, "triton-global")
	os.WriteFile(globalBin, []byte("fake binary"), 0o755)

	d := &netscan.Device{}
	got, err := ResolveBinary(d, globalBin, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got != globalBin {
		t.Errorf("ResolveBinary fallback: got %q, want %q", got, globalBin)
	}
}

func TestResolveBinary_MissingFile(t *testing.T) {
	d := &netscan.Device{}
	_, err := ResolveBinary(d, "/nonexistent/triton", "linux", "amd64")
	if err == nil {
		t.Error("ResolveBinary should fail for nonexistent binary")
	}
}
