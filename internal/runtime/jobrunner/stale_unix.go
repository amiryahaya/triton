//go:build unix

package jobrunner

import "syscall"

// signalZero is the no-op signal used for liveness probing on unix.
var signalZero = syscall.Signal(0)
