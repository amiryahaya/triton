//go:build windows

package jobrunner

import "syscall"

// Win32 process-creation flags. DETACHED_PROCESS is not in the stdlib's
// syscall package as a named constant, so we define it locally.
const (
	createNewProcessGroup uint32 = 0x00000200 // CREATE_NEW_PROCESS_GROUP
	detachedProcess       uint32 = 0x00000008 // DETACHED_PROCESS
)

// detachSysProcAttr returns the SysProcAttr for a fully detached child on
// windows: no console attached, its own process group, no visible window.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup | detachedProcess,
		HideWindow:    true,
	}
}
