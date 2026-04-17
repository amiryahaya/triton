//go:build unix

package limits

import "syscall"

// ApplyNice adjusts the current process's scheduling priority.
// On Unix, wraps setpriority(PRIO_PROCESS, 0, nice). Zero is a no-op.
// Failures are silently ignored: CAP_SYS_NICE may be absent and --nice
// should never be the reason a scan refuses to start.
func ApplyNice(n int) {
	if n == 0 {
		return
	}
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, 0, n)
}
