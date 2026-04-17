//go:build windows

package limits

// ApplyNice is a no-op on Windows. A future task may map this to
// SetPriorityClass via golang.org/x/sys/windows; for now --nice on
// Windows does nothing.
func ApplyNice(n int) {}
