package crypto

import (
	"bytes"
	"testing"
)

func TestSealedBox_RoundTrip(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	pt := bytes.Repeat([]byte("a"), 100)
	sealed, err := Seal(pub, pt)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := Open(priv, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(pt, got) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestSealedBox_WrongRecipient_Fails(t *testing.T) {
	_, pubA, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair A: %v", err)
	}
	privB, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair B: %v", err)
	}
	sealed, err := Seal(pubA, []byte("secret"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(privB, sealed); err == nil {
		t.Fatalf("expected Open to fail with wrong recipient")
	}
}

func TestSealedBox_TamperedCiphertext_Fails(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	sealed, err := Seal(pub, []byte("hello world, this is a test payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Flip a byte in the middle of the ciphertext region.
	mid := 44 + (len(sealed)-44)/2
	sealed[mid] ^= 0x01
	if _, err := Open(priv, sealed); err == nil {
		t.Fatalf("expected Open to fail with tampered ciphertext")
	}
}

func TestSealedBox_TamperedNonce_Fails(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	sealed, err := Seal(pub, []byte("payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sealed[32] ^= 0x01 // flip first nonce byte
	if _, err := Open(priv, sealed); err == nil {
		t.Fatalf("expected Open to fail with tampered nonce")
	}
}

func TestSealedBox_EmptyPlaintext_RoundTrips(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	sealed, err := Seal(pub, nil)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := Open(priv, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestSealedBox_Overhead(t *testing.T) {
	_, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	for _, n := range []int{0, 1, 16, 256, 4096} {
		pt := bytes.Repeat([]byte("x"), n)
		sealed, err := Seal(pub, pt)
		if err != nil {
			t.Fatalf("seal(%d): %v", n, err)
		}
		if want := n + SealedBoxOverhead; len(sealed) != want {
			t.Fatalf("n=%d: got len=%d, want %d", n, len(sealed), want)
		}
	}
}
