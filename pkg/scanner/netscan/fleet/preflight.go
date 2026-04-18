package fleet

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/amiryahaya/triton/pkg/scanner/netscan"
)

// ParseUnameArch converts `uname -s -m` output (e.g. "Linux x86_64") into
// GOOS/GOARCH pair ("linux", "amd64"). Uses the standard mapping that
// matches Go's runtime.GOOS / runtime.GOARCH values.
func ParseUnameArch(out string) (goos, arch string, err error) {
	out = strings.TrimSpace(out)
	parts := strings.Fields(out)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid uname output %q: want 'KERNEL ARCH'", out)
	}

	switch strings.ToLower(parts[0]) {
	case "linux":
		goos = "linux"
	case "darwin":
		goos = "darwin"
	case "freebsd":
		goos = "freebsd"
	case "openbsd":
		goos = "openbsd"
	case "netbsd":
		goos = "netbsd"
	case "aix":
		goos = "aix"
	case "sunos":
		goos = "solaris"
	default:
		return "", "", fmt.Errorf("unsupported OS %q in uname", parts[0])
	}

	switch strings.ToLower(parts[1]) {
	case "x86_64", "amd64":
		arch = "amd64"
	case "aarch64", "arm64":
		arch = "arm64"
	case "armv7l", "armv6l":
		arch = "arm"
	case "i386", "i686", "i86pc":
		if goos == "solaris" {
			arch = "amd64"
		} else {
			arch = "386"
		}
	case "ppc64":
		arch = "ppc64"
	case "ppc64le":
		arch = "ppc64le"
	case "s390x":
		arch = "s390x"
	default:
		return "", "", fmt.Errorf("unsupported arch %q in uname", parts[1])
	}
	return goos, arch, nil
}

// ResolveBinary returns the local file path to push as the triton binary.
// Precedence: device.Binary > globalBinary (from --binary flag or os.Args[0]).
// Verifies the chosen path exists before returning.
//
// goos/arch are accepted for future arch-match validation but are not
// currently used to verify binary compatibility — the operator is
// responsible for choosing a compatible binary.
func ResolveBinary(d *netscan.Device, globalBinary, goos, arch string) (string, error) {
	path := d.Binary
	if path == "" {
		path = globalBinary
	}
	if path == "" {
		return "", fmt.Errorf("no binary specified: set --binary or device.binary")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat binary %s: %w", path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("binary path is a directory: %s", path)
	}
	_ = goos
	_ = arch
	return path, nil
}

// SudoCheck runs `sudo -n true` on the remote to verify NOPASSWD sudo is
// configured. Returns a descriptive error if sudo would prompt.
func SudoCheck(ctx context.Context, r SSHRunner) error {
	out, err := r.Run(ctx, "sudo -n true 2>&1")
	if err != nil {
		return fmt.Errorf("NOPASSWD sudo required: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}
