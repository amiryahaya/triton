// crypto.js — browser-side X25519 sealed-box encryption.
//
// Matches pkg/engine/crypto/sealedbox.go byte-for-byte:
//   ephemeral_pubkey (32) || nonce (12) || ciphertext_with_tag
// where key = HKDF-SHA256(shared, salt=ephPub||recipientPub, info="triton/sealedbox/v1", 32)
// and AEAD = ChaCha20-Poly1305 with a fresh 12-byte random nonce.
//
// ESM module — imported dynamically from app.js (classic script) via
// `await import('./crypto.js')`. Dependencies are pulled from esm.sh so
// no build step is required; versions are pinned for reproducibility.

import { x25519 } from 'https://esm.sh/@noble/curves@1.7.0/ed25519';
import { hkdf } from 'https://esm.sh/@noble/hashes@1.7.0/hkdf';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.7.0/sha2';
import { chacha20poly1305 } from 'https://esm.sh/@noble/ciphers@1.0.0/chacha';
import { randomBytes } from 'https://esm.sh/@noble/hashes@1.7.0/utils';

const HKDF_INFO = new TextEncoder().encode('triton/sealedbox/v1');

export async function sealTo(recipientPubB64, plaintextBytes) {
    const recipientPub = base64Decode(recipientPubB64);
    if (recipientPub.length !== 32) throw new Error('recipient pubkey must be 32 bytes');

    const ephPriv = x25519.utils.randomPrivateKey();
    const ephPub = x25519.getPublicKey(ephPriv);
    const shared = x25519.getSharedSecret(ephPriv, recipientPub);

    const salt = new Uint8Array(ephPub.length + recipientPub.length);
    salt.set(ephPub, 0);
    salt.set(recipientPub, ephPub.length);

    const key = hkdf(sha256, shared, salt, HKDF_INFO, 32);
    const nonce = randomBytes(12);
    const aead = chacha20poly1305(key, nonce);
    const ct = aead.encrypt(plaintextBytes);

    const out = new Uint8Array(ephPub.length + nonce.length + ct.length);
    out.set(ephPub, 0);
    out.set(nonce, ephPub.length);
    out.set(ct, ephPub.length + nonce.length);
    return base64Encode(out);
}

export function base64Encode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}

export function base64Decode(str) {
    const bin = atob(str);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}
