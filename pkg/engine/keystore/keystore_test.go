package keystore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func newTestKeystore(t *testing.T) *Keystore {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	path := filepath.Join(t.TempDir(), "keystore.db")
	k, err := Open(path, key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = k.Close() })
	return k
}

func TestKeystore_PutGet_RoundTrip(t *testing.T) {
	k := newTestKeystore(t)
	ctx := context.Background()

	plaintext := []byte(`{"username":"root","password":"hunter2"}`)
	if err := k.Put(ctx, "ref1", "prof1", "ssh-password", plaintext); err != nil {
		t.Fatalf("Put: %v", err)
	}
	auth, got, err := k.Get(ctx, "ref1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if auth != "ssh-password" {
		t.Errorf("auth_type = %q, want ssh-password", auth)
	}
	if string(got) != string(plaintext) {
		t.Errorf("plaintext mismatch: got %q", got)
	}
}

func TestKeystore_Put_Overwrite(t *testing.T) {
	k := newTestKeystore(t)
	ctx := context.Background()
	if err := k.Put(ctx, "ref", "p1", "ssh-password", []byte("first")); err != nil {
		t.Fatalf("Put1: %v", err)
	}
	if err := k.Put(ctx, "ref", "p2", "ssh-key", []byte("second")); err != nil {
		t.Fatalf("Put2: %v", err)
	}
	auth, got, err := k.Get(ctx, "ref")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if auth != "ssh-key" || string(got) != "second" {
		t.Errorf("overwrite lost: auth=%q got=%q", auth, got)
	}
}

func TestKeystore_Delete(t *testing.T) {
	k := newTestKeystore(t)
	ctx := context.Background()
	_ = k.Put(ctx, "ref", "p", "ssh-password", []byte("x"))
	if err := k.Delete(ctx, "ref"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := k.Get(ctx, "ref"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Delete: err=%v, want ErrNotFound", err)
	}
	// Deleting missing row is not an error.
	if err := k.Delete(ctx, "missing"); err != nil {
		t.Errorf("Delete missing: %v", err)
	}
}

func TestKeystore_List_EmptyAndNonEmpty(t *testing.T) {
	k := newTestKeystore(t)
	ctx := context.Background()
	got, err := k.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty list: got %d entries", len(got))
	}
	_ = k.Put(ctx, "r1", "p1", "ssh-password", []byte("a"))
	_ = k.Put(ctx, "r2", "p2", "ssh-key", []byte("b"))
	got, err = k.List(ctx)
	if err != nil {
		t.Fatalf("List2: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("list size = %d, want 2", len(got))
	}
	refs := map[string]bool{got[0].SecretRef: true, got[1].SecretRef: true}
	if !refs["r1"] || !refs["r2"] {
		t.Errorf("unexpected refs: %#v", refs)
	}
}

func TestKeystore_Get_NotFound(t *testing.T) {
	k := newTestKeystore(t)
	_, _, err := k.Get(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestKeystore_Get_TamperedPayload_Error(t *testing.T) {
	k := newTestKeystore(t)
	ctx := context.Background()
	if err := k.Put(ctx, "ref", "p", "ssh-password", []byte("secret")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Flip the first byte of the payload column.
	if _, err := k.db.ExecContext(ctx,
		`UPDATE secrets SET payload = ? WHERE secret_ref = 'ref'`,
		[]byte{0xAA, 0xBB, 0xCC, 0xDD}); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, _, err := k.Get(ctx, "ref"); err == nil {
		t.Fatal("Get tampered: want error")
	} else if errors.Is(err, ErrNotFound) {
		t.Fatalf("Get tampered: got ErrNotFound, want decrypt error")
	} else if errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("Get tampered: sql.ErrNoRows, want decrypt error")
	}
}

func TestKeystore_Open_InvalidMasterKey_Error(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ks.db")
	if _, err := Open(path, make([]byte, 31)); err == nil {
		t.Fatal("Open 31-byte key: want error")
	}
	if _, err := Open(path, make([]byte, 33)); err == nil {
		t.Fatal("Open 33-byte key: want error")
	}
}
