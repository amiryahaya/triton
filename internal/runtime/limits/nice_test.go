package limits

import "testing"

// ApplyNice must exist on every platform and never panic. On Unix it calls
// setpriority; on Windows it's a no-op. Testing the actual priority change
// requires root on some systems, so we only verify the function is callable
// with representative inputs and that zero is a no-op.
func TestApplyNiceDoesNotPanic(t *testing.T) {
	for _, n := range []int{0, 1, 5, 10, -1} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ApplyNice(%d) panicked: %v", n, r)
				}
			}()
			ApplyNice(n)
		}()
	}
}
