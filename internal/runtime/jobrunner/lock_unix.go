//go:build unix

package jobrunner

import (
	"fmt"
	"os"
	"syscall"
)

// FileLock holds an exclusive file-level lock using flock(2). Zero-value is
// not usable; always use AcquireFileLock.
type FileLock struct {
	f *os.File
}

// AcquireFileLock opens path and tries to acquire an exclusive non-blocking
// flock lock. Returns an error if the lock is held by another process.
// The lock is released when Release is called or when the process exits.
func AcquireFileLock(path string) (*FileLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("flock: %w", err)
	}
	return &FileLock{f: f}, nil
}

// Release drops the lock and closes the underlying file. Safe to call more
// than once (subsequent calls are no-ops).
func (l *FileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	err := l.f.Close()
	l.f = nil
	return err
}
