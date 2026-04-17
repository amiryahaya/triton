package jobrunner

import (
	"errors"
	"os"
)

// Reconcile reads status.json from jobDir and, if the state is non-
// terminal and the daemon PID is not alive, rewrites status as failed
// with error "daemon vanished". Returns the (possibly updated) status,
// whether it was changed, and any I/O error.
//
// This is the self-healing path for --status / --list-jobs.
func Reconcile(jobDir string) (*Status, bool, error) {
	return defaultReconciler.Reconcile(jobDir)
}

// reconciler carries the pidAlive injection seam. Production uses
// defaultReconciler; tests construct their own with a fake pidAlive.
type reconciler struct {
	pidAlive func(int) bool
}

var defaultReconciler = &reconciler{pidAlive: realPIDAlive}

// Reconcile is the method form used by tests.
func (r *reconciler) Reconcile(jobDir string) (*Status, bool, error) {
	s, err := ReadStatus(jobDir)
	if err != nil {
		return nil, false, err
	}
	if s.State.IsTerminal() {
		return s, false, nil
	}
	if s.PID > 0 && r.pidAlive(s.PID) {
		return s, false, nil
	}
	// Non-terminal + PID gone → declare failed.
	s.MarkTerminal(StateFailed, errDaemonVanished)
	if err := WriteStatusAtomic(jobDir, s); err != nil {
		return s, false, err
	}
	return s, true, nil
}

// errDaemonVanished is the sentinel error recorded on stale jobs.
var errDaemonVanished = errors.New("daemon vanished (crash or kill)")

// realPIDAlive reports whether a process with the given PID is reachable
// via signal-0. Negative, zero, or absent processes return false.
func realPIDAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// os.FindProcess always succeeds on unix; Signal(0) is the liveness
	// check. On windows, FindProcess fails for dead PIDs.
	if err := p.Signal(signalZero); err != nil {
		return false
	}
	return true
}

// IsProcessAlive is the exported wrapper for realPIDAlive. Returns true
// iff a process with the given PID is reachable via signal-0. Called by
// cmd-layer code that needs the same liveness semantics without the
// reconciler machinery.
func IsProcessAlive(pid int) bool { return realPIDAlive(pid) }
