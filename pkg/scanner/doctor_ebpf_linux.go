//go:build linux

package scanner

import (
	"os"
	"strings"
)

// ebpfDoctorCheck validates the three prereqs for the ebpf_trace module on
// Linux: root (or CAP_BPF — currently only euid==0 is checked), kernel ≥ 5.8
// (ring buffer support), and BTF availability at /sys/kernel/btf/vmlinux.
// Returns (false, reason) on the first miss.
func ebpfDoctorCheck() (ok bool, detail string) {
	if os.Geteuid() != 0 {
		return false, "not root; eBPF requires CAP_BPF or root"
	}
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return false, "cannot read /proc/sys/kernel/osrelease: " + err.Error()
	}
	ver := strings.TrimSpace(string(data))
	if !atLeastKernel58(ver) {
		return false, "kernel " + ver + " < 5.8 (ring buffer unsupported)"
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return false, "/sys/kernel/btf/vmlinux missing (BTF not enabled)"
	}
	return true, "kernel " + ver + ", BTF present, root"
}

// atLeastKernel58 parses the first two dotted numbers of a kernel release
// string (e.g. "5.15.0-91-generic" → major=5, minor=15) and returns true iff
// the version is ≥ 5.8. Tolerant of trailing non-digits after each number.
func atLeastKernel58(release string) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	var major, minor int
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			break
		}
		major = major*10 + int(c-'0')
	}
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			break
		}
		minor = minor*10 + int(c-'0')
	}
	return major > 5 || (major == 5 && minor >= 8)
}
