//go:build windows

package jobrunner

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// FileLock holds an exclusive file-level lock using LockFileEx. Zero-value
// is not usable; always use AcquireFileLock.
type FileLock struct {
	f *os.File
}

// AcquireFileLock opens path and tries to acquire an exclusive non-blocking
// LockFileEx lock. Returns an error if the lock is held.
func AcquireFileLock(path string) (*FileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol,
	); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("LockFileEx: %w", err)
	}
	return &FileLock{f: f}, nil
}

// Release unlocks the file and closes it.
func (l *FileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	ol := new(windows.Overlapped)
	_ = windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, ol)
	err := l.f.Close()
	l.f = nil
	return err
}
