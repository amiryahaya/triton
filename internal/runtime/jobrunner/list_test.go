package jobrunner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestList_Empty(t *testing.T) {
	tmp := t.TempDir()
	jobs, err := List(tmp)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("List on empty dir: got %d jobs, want 0", len(jobs))
	}
}

func TestList_MultipleJobs(t *testing.T) {
	tmp := t.TempDir()
	for _, id := range []string{"job-a", "job-b", "job-c"} {
		jobDir, err := EnsureJobDir(tmp, id)
		if err != nil {
			t.Fatal(err)
		}
		s := InitialStatus(id, 100, "quick", "v1", "")
		if err := WriteStatusAtomic(jobDir, s); err != nil {
			t.Fatal(err)
		}
	}

	jobs, err := List(tmp)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(jobs) != 3 {
		t.Errorf("got %d jobs, want 3", len(jobs))
	}
	seen := map[string]bool{}
	for _, j := range jobs {
		seen[j.JobID] = true
	}
	for _, want := range []string{"job-a", "job-b", "job-c"} {
		if !seen[want] {
			t.Errorf("missing job %q in list", want)
		}
	}
}

func TestList_SkipsNonJobDirs(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "stray.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "empty-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	jobDir, _ := EnsureJobDir(tmp, "real-job")
	if err := WriteStatusAtomic(jobDir, InitialStatus("real-job", 1, "q", "v", "")); err != nil {
		t.Fatal(err)
	}

	jobs, err := List(tmp)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(jobs) != 1 || jobs[0].JobID != "real-job" {
		t.Errorf("got %+v, want 1 job (real-job)", jobs)
	}
}

func TestRemove_RefusesRunning(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := EnsureJobDir(tmp, "running")
	s := InitialStatus("running", os.Getpid(), "q", "v", "")
	s.State = StateRunning
	if err := WriteStatusAtomic(jobDir, s); err != nil {
		t.Fatal(err)
	}

	err := removeWithLiveness(tmp, "running", func(int) bool { return true })
	if err == nil {
		t.Fatal("Remove on running job should fail")
	}
	if _, e := os.Stat(jobDir); e != nil {
		t.Error("job dir should still exist after refused remove")
	}
}

func TestRemove_FinishedJob(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := EnsureJobDir(tmp, "done")
	s := InitialStatus("done", 1, "q", "v", "")
	s.State = StateDone
	if err := WriteStatusAtomic(jobDir, s); err != nil {
		t.Fatal(err)
	}

	if err := Remove(tmp, "done"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, e := os.Stat(jobDir); !os.IsNotExist(e) {
		t.Error("job dir should be gone after Remove")
	}
}

func TestRemoveAll_OnlyFinished(t *testing.T) {
	tmp := t.TempDir()

	jobA, _ := EnsureJobDir(tmp, "a")
	sA := InitialStatus("a", 1, "q", "v", "")
	sA.State = StateDone
	WriteStatusAtomic(jobA, sA)

	jobB, _ := EnsureJobDir(tmp, "b")
	sB := InitialStatus("b", 1, "q", "v", "")
	sB.State = StateFailed
	WriteStatusAtomic(jobB, sB)

	jobC, _ := EnsureJobDir(tmp, "c")
	sC := InitialStatus("c", os.Getpid(), "q", "v", "")
	sC.State = StateRunning
	WriteStatusAtomic(jobC, sC)

	removed, err := removeAllWithLiveness(tmp, func(int) bool { return true })
	if err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2 (done + failed; running skipped)", removed)
	}

	if _, e := os.Stat(jobC); e != nil {
		t.Error("running job c should not have been removed")
	}
}

func TestRemove_MissingStatusStillRemoves(t *testing.T) {
	// A job-dir without status.json (corrupted or partially-written during
	// spawn failure) should still be removable via --cleanup so operators
	// can reclaim the slot.
	tmp := t.TempDir()
	jobDir := filepath.Join(tmp, "orphan")
	if err := os.MkdirAll(jobDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := removeWithLiveness(tmp, "orphan", func(int) bool { return true }); err != nil {
		t.Fatalf("Remove on dir without status.json should succeed, got: %v", err)
	}
	if _, err := os.Stat(jobDir); !os.IsNotExist(err) {
		t.Error("orphan job-dir should be removed even without status.json")
	}
}

func TestRemoveAll_PublicWrapper(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := EnsureJobDir(tmp, "done")
	s := InitialStatus("done", 1, "q", "v", "")
	s.State = StateDone
	WriteStatusAtomic(jobDir, s)

	n, err := RemoveAll(tmp)
	if err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if n != 1 {
		t.Errorf("removed = %d, want 1", n)
	}
}

func TestRemove_PublicWrapper_Finished(t *testing.T) {
	tmp := t.TempDir()
	jobDir, _ := EnsureJobDir(tmp, "done")
	s := InitialStatus("done", 1, "q", "v", "")
	s.State = StateDone
	WriteStatusAtomic(jobDir, s)

	if err := Remove(tmp, "done"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(jobDir); !os.IsNotExist(err) {
		t.Error("job dir should be removed")
	}
}

func TestIsProcessAlive_Self(t *testing.T) {
	if !IsProcessAlive(os.Getpid()) {
		t.Error("IsProcessAlive on self should return true")
	}
}

func TestIsProcessAlive_InvalidPid(t *testing.T) {
	if IsProcessAlive(0) {
		t.Error("IsProcessAlive(0) should return false")
	}
	if IsProcessAlive(-1) {
		t.Error("IsProcessAlive(-1) should return false")
	}
}
