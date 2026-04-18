package jobrunner

import (
	"path/filepath"
	"testing"
)

func TestAcquireFileLock_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	lock, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("AcquireFileLock: %v", err)
	}
	defer lock.Release()

	if lock == nil {
		t.Fatal("lock is nil")
	}
}

func TestAcquireFileLock_SecondAcquireFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	first, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer first.Release()

	// Second acquire on same path must fail.
	second, err := AcquireFileLock(path)
	if err == nil {
		second.Release()
		t.Fatal("second AcquireFileLock should have failed (lock already held)")
	}
}

func TestAcquireFileLock_AcquireAfterRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.lock")

	first, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// After release, a new acquire should succeed.
	second, err := AcquireFileLock(path)
	if err != nil {
		t.Fatalf("second acquire after release: %v", err)
	}
	second.Release()
}
