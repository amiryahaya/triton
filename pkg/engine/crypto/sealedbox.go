// Package crypto provides sealed-box style encryption: a sender encrypts
// to a recipient's static X25519 public key without needing a reply
// channel. Used for browser→engine credential delivery.
//
// Scheme: X25519 ECDH between a per-message ephemeral keypair and the
// recipient's static key, HKDF-SHA256 expansion keyed by the raw shared
// secret with salt = ephPub || recipientPub and info = "triton/sealedbox/v1",
// then ChaCha20-Poly1305 AEAD with a fresh 12-byte random nonce.
//
// Wire format: ephemeral_pubkey (32) || nonce (12) || ciphertext_with_tag
// (plaintext_len + 16). No additional authenticated data.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// SealedBoxOverhead = 32 (ephPub) + 12 (nonce) + 16 (Poly1305 tag).
const SealedBoxOverhead = 32 + 12 + 16

const hkdfInfo = "triton/sealedbox/v1"

// GenerateKeypair returns an X25519 private key and its 32-byte public
// key encoding suitable for storing on the engine and publishing to the
// server.
func GenerateKeypair() (*ecdh.PrivateKey, []byte, error) {
	c := ecdh.X25519()
	priv, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// Seal encrypts plaintext to the recipient's 32-byte X25519 public key.
// The returned blob has SealedBoxOverhead bytes of framing prepended.
func Seal(recipientPub []byte, plaintext []byte) ([]byte, error) {
	c := ecdh.X25519()
	recipient, err := c.NewPublicKey(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("parse recipient pubkey: %w", err)
	}
	ephPriv, err := c.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := ephPriv.ECDH(recipient)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(shared, ephPriv.PublicKey().Bytes(), recipientPub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, 32+len(nonce)+len(ct))
	out = append(out, ephPriv.PublicKey().Bytes()...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open decrypts a sealed box with the recipient's private key. Any
// tampering (ciphertext, nonce, or ephemeral pubkey) produces an error.
func Open(recipientPriv *ecdh.PrivateKey, sealed []byte) ([]byte, error) {
	if len(sealed) < SealedBoxOverhead {
		return nil, fmt.Errorf("sealed box too short")
	}
	ephPub := sealed[:32]
	nonce := sealed[32:44]
	ct := sealed[44:]

	c := ecdh.X25519()
	eph, err := c.NewPublicKey(ephPub)
	if err != nil {
		return nil, err
	}
	shared, err := recipientPriv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(shared, ephPub, recipientPriv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ct, nil)
}

func deriveKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephPub)+len(recipientPub))
	salt = append(salt, ephPub...)
	salt = append(salt, recipientPub...)
	r := hkdf.New(newSHA256, shared, salt, []byte(hkdfInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func newSHA256() hash.Hash { return sha256.New() }
