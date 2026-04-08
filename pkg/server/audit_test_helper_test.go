//go:build integration

package server

import "time"

// waitForAudit yields to let an in-process goroutine that the audit
// writer spawned run its WriteAudit call. The audit path is
// fire-and-forget, so tests that want to assert on the resulting
// row need a short wait between the triggering action and the
// read-back. Kept tiny (5ms) because the goroutine does a single
// DB insert and should complete on the first poll.
//
// Extracted to its own helper file so the primary audit test
// reads linearly without a poll-sleep helper muddling the flow.
func waitForAudit() {
	time.Sleep(5 * time.Millisecond)
}
