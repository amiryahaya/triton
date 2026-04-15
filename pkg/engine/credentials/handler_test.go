package credentials

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amiryahaya/triton/pkg/engine/client"
	trcrypto "github.com/amiryahaya/triton/pkg/engine/crypto"
	"github.com/amiryahaya/triton/pkg/engine/keystore"
)

type fakeDeliveryAPI struct {
	mu         sync.Mutex
	deliveries []*client.DeliveryPayload // queued; each Poll dequeues one
	pollErrN   int32                     // first N polls return error
	errToRet   error
	acked      []struct {
		ID  string
		Err string
	}
	doneCh chan struct{} // closed after acks matching len(deliveries)
}

func (f *fakeDeliveryAPI) PollCredentialDelivery(_ context.Context) (*client.DeliveryPayload, error) {
	if atomic.AddInt32(&f.pollErrN, -1) >= 0 {
		return nil, f.errToRet
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.deliveries) == 0 {
		// Block-ish: return 204 (nil, nil). Caller loops.
		time.Sleep(5 * time.Millisecond)
		return nil, nil
	}
	d := f.deliveries[0]
	f.deliveries = f.deliveries[1:]
	return d, nil
}

func (f *fakeDeliveryAPI) AckCredentialDelivery(_ context.Context, id, errMsg string) error {
	f.mu.Lock()
	f.acked = append(f.acked, struct {
		ID  string
		Err string
	}{id, errMsg})
	done := f.doneCh != nil && len(f.acked) == cap(f.acked)
	f.mu.Unlock()
	if done {
		close(f.doneCh)
	}
	return nil
}

func newTestKS(t *testing.T) *keystore.Keystore {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ks, err := keystore.Open(filepath.Join(t.TempDir(), "ks.db"), key)
	if err != nil {
		t.Fatalf("open ks: %v", err)
	}
	t.Cleanup(func() { _ = ks.Close() })
	return ks
}

func newDoneFake(n int, deliveries []*client.DeliveryPayload) *fakeDeliveryAPI {
	ch := make(chan struct{})
	f := &fakeDeliveryAPI{deliveries: deliveries}
	f.acked = make([]struct {
		ID  string
		Err string
	}, 0, n)
	f.doneCh = ch
	return f
}

func runHandlerUntilAcked(t *testing.T, h *Handler, fake *fakeDeliveryAPI, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go h.Run(ctx)
	select {
	case <-fake.doneCh:
	case <-time.After(timeout):
		cancel()
		t.Fatal("timed out waiting for acks")
	}
	cancel()
}

func TestHandler_Push_DecryptsAndStores(t *testing.T) {
	priv, pub, err := trcrypto.GenerateKeypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	plaintext := []byte(`{"username":"u","password":"pw"}`)
	ct, err := trcrypto.Seal(pub, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	d := &client.DeliveryPayload{
		ID:         "d1",
		ProfileID:  "p1",
		SecretRef:  "r1",
		AuthType:   "ssh-password",
		Kind:       "push",
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	fake := newDoneFake(1, []*client.DeliveryPayload{d})
	ks := newTestKS(t)
	h := &Handler{Client: fake, Keystore: ks, PrivateKey: priv, PollBackoff: 10 * time.Millisecond}

	runHandlerUntilAcked(t, h, fake, 2*time.Second)

	if len(fake.acked) != 1 || fake.acked[0].Err != "" {
		t.Fatalf("acked = %+v", fake.acked)
	}
	auth, got, err := ks.Get(context.Background(), "r1")
	if err != nil {
		t.Fatalf("ks.Get: %v", err)
	}
	if auth != "ssh-password" || string(got) != string(plaintext) {
		t.Errorf("stored: auth=%q pt=%q", auth, got)
	}
}

func TestHandler_Delete_PurgesAndAcks(t *testing.T) {
	ks := newTestKS(t)
	ctx := context.Background()
	if err := ks.Put(ctx, "r1", "p1", "ssh-password", []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	fake := newDoneFake(1, []*client.DeliveryPayload{{ID: "d1", SecretRef: "r1", Kind: "delete"}})
	priv, _, _ := trcrypto.GenerateKeypair()
	h := &Handler{Client: fake, Keystore: ks, PrivateKey: priv, PollBackoff: 10 * time.Millisecond}
	runHandlerUntilAcked(t, h, fake, 2*time.Second)

	if fake.acked[0].Err != "" {
		t.Fatalf("ack err = %q", fake.acked[0].Err)
	}
	if _, _, err := ks.Get(ctx, "r1"); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("after delete: err=%v want ErrNotFound", err)
	}
}

func TestHandler_BadCiphertext_AcksWithError(t *testing.T) {
	fake := newDoneFake(1, []*client.DeliveryPayload{{
		ID: "d1", SecretRef: "r1", AuthType: "ssh-password",
		Kind: "push", Ciphertext: "not-base64!@#",
	}})
	priv, _, _ := trcrypto.GenerateKeypair()
	ks := newTestKS(t)
	h := &Handler{Client: fake, Keystore: ks, PrivateKey: priv, PollBackoff: 10 * time.Millisecond}
	runHandlerUntilAcked(t, h, fake, 2*time.Second)
	if fake.acked[0].Err == "" {
		t.Fatal("expected non-empty ack error")
	}
}

func TestHandler_UnknownKind_AcksWithError(t *testing.T) {
	fake := newDoneFake(1, []*client.DeliveryPayload{{
		ID: "d1", SecretRef: "r1", AuthType: "ssh-password", Kind: "bogus",
	}})
	priv, _, _ := trcrypto.GenerateKeypair()
	ks := newTestKS(t)
	h := &Handler{Client: fake, Keystore: ks, PrivateKey: priv, PollBackoff: 10 * time.Millisecond}
	runHandlerUntilAcked(t, h, fake, 2*time.Second)
	if fake.acked[0].Err == "" || fake.acked[0].Err[:7] != "unknown" {
		t.Errorf("ack err = %q, want unknown kind", fake.acked[0].Err)
	}
}

func TestHandler_PollError_BacksOff(t *testing.T) {
	// First 2 polls return errors; then deliver one push; then stop.
	priv, pub, _ := trcrypto.GenerateKeypair()
	ct, _ := trcrypto.Seal(pub, []byte(`{"username":"u"}`))
	d := &client.DeliveryPayload{
		ID: "d1", SecretRef: "r1", AuthType: "ssh-password",
		Kind: "push", Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	fake := newDoneFake(1, []*client.DeliveryPayload{d})
	fake.pollErrN = 2
	fake.errToRet = errors.New("transient")

	ks := newTestKS(t)
	h := &Handler{Client: fake, Keystore: ks, PrivateKey: priv, PollBackoff: 20 * time.Millisecond}
	start := time.Now()
	runHandlerUntilAcked(t, h, fake, 2*time.Second)
	if time.Since(start) < 40*time.Millisecond {
		t.Errorf("backoff not applied: elapsed=%v", time.Since(start))
	}
	if fake.acked[0].Err != "" {
		t.Errorf("ack err = %q", fake.acked[0].Err)
	}
}
