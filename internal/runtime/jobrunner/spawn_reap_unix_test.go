//go:build unix

package jobrunner

import "syscall"

// reapIfZombie calls waitpid(pid, WNOHANG) to reap a zombie child owned
// by the current process. Returns true if the child was reaped (or
// doesn't exist anymore), false if it is still running.
//
// This is test-only scaffolding: in production the parent process exits
// right after Spawn so the daemon is reparented to init (pid 1), which
// handles reaping. Inside the test, the test-process keeps running and
// would leave a zombie behind without an explicit reap — realPIDAlive
// reports zombies as alive because kill(pid, 0) succeeds on them.
func reapIfZombie(pid int) bool {
	var ws syscall.WaitStatus
	wpid, err := syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
	if err != nil {
		// ECHILD: not our child (already reaped or never was).
		return true
	}
	return wpid == pid
}
