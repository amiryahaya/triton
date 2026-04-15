package credentials

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"log"
	"time"

	"github.com/amiryahaya/triton/pkg/engine/client"
	trcrypto "github.com/amiryahaya/triton/pkg/engine/crypto"
	"github.com/amiryahaya/triton/pkg/engine/keystore"
)

// DeliveryAPI is the slice of the engine HTTP client used by the
// credential delivery handler. Exists for test substitution.
type DeliveryAPI interface {
	PollCredentialDelivery(ctx context.Context) (*client.DeliveryPayload, error)
	AckCredentialDelivery(ctx context.Context, id, errMsg string) error
}

// Handler drains credential deliveries from the portal: decrypts
// sealed-box payloads with the engine's static X25519 private key and
// persists plaintext secrets in the encrypted local keystore.
type Handler struct {
	Client     DeliveryAPI
	Keystore   *keystore.Keystore
	PrivateKey *ecdh.PrivateKey
	// PollBackoff is the wait between retries after a poll error
	// (e.g. transient network failure). Defaults to 5s.
	PollBackoff time.Duration
}

// Run loops until ctx is cancelled. Each iteration long-polls,
// processes one delivery (if any), and acks it.
func (h *Handler) Run(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		d, err := h.Client.PollCredentialDelivery(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("poll credential delivery: %v", err)
			wait := h.PollBackoff
			if wait == 0 {
				wait = 5 * time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			continue
		}
		if d == nil {
			continue
		}
		h.processOne(ctx, d)
	}
}

func (h *Handler) processOne(ctx context.Context, d *client.DeliveryPayload) {
	ackErr := ""
	switch d.Kind {
	case "push":
		ackErr = h.handlePush(ctx, d)
	case "delete":
		if err := h.Keystore.Delete(ctx, d.SecretRef); err != nil {
			ackErr = "keystore delete failed: " + err.Error()
		}
	default:
		ackErr = "unknown kind: " + d.Kind
	}
	if err := h.Client.AckCredentialDelivery(ctx, d.ID, ackErr); err != nil {
		log.Printf("ack delivery %s: %v", d.ID, err)
	}
}

func (h *Handler) handlePush(ctx context.Context, d *client.DeliveryPayload) string {
	if d.Ciphertext == "" {
		return "push delivery missing ciphertext"
	}
	raw, err := base64.StdEncoding.DecodeString(d.Ciphertext)
	if err != nil {
		return "bad ciphertext encoding: " + err.Error()
	}
	plaintext, err := trcrypto.Open(h.PrivateKey, raw)
	if err != nil {
		return "decrypt failed: " + err.Error()
	}
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()
	if err := h.Keystore.Put(ctx, d.SecretRef, d.ProfileID, d.AuthType, plaintext); err != nil {
		return "keystore put failed: " + err.Error()
	}
	return ""
}
