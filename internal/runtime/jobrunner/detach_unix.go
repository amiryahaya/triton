//go:build unix

package jobrunner

import "syscall"

// detachSysProcAttr returns the SysProcAttr that detaches a child from the
// parent's controlling terminal and session. Setsid ensures the child
// becomes its own session leader, so closing the parent's SSH session
// does not deliver SIGHUP to the child.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
