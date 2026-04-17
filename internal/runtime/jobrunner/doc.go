// Package jobrunner implements the work-dir state machine for detached triton scans.
//
// A detached scan writes lifecycle state to ~/.triton/jobs/<job-id>/ — pid,
// status.json, cancel.flag, scan.log, reports/, result.json. This package owns
// the filesystem contract; consumers read/write status via atomic WriteFile +
// Rename and check daemon liveness via the stale detector.
//
// Platform notes:
//
//   - Detach mechanism is fork-exec with env sentinel (TRITON_DETACHED=1).
//     SysProcAttr differs between unix (Setsid: true) and windows
//     (DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP).
//
//   - Cancellation is cooperative: callers touch cancel.flag; the daemon
//     polls every 2s and cancels its scan context. This avoids platform
//     signal differences (SIGTERM on unix vs GenerateConsoleCtrlEvent on
//     windows).
//
//   - File locks use flock on unix and LockFileEx on windows. The lock is
//     held by the daemon for its lifetime; observing an unheld lock is how
//     stale-job detection works.
package jobrunner
