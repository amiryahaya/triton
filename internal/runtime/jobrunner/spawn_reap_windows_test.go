//go:build windows

package jobrunner

// reapIfZombie is a no-op on windows: the zombie concept does not exist;
// FindProcess (and hence realPIDAlive) correctly returns false once the
// child exits.
func reapIfZombie(_ int) bool { return true }
