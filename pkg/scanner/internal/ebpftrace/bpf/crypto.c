// SPDX-License-Identifier: Apache-2.0
// Triton eBPF crypto tracer: observes OpenSSL/GnuTLS/NSS uprobes and kernel
// crypto API kprobes, emits crypto_event_t records to a ring buffer.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "event.h"

char LICENSE[] SEC("license") = "GPL";

// Ring buffer, 256 KB.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline void emit(
    struct pt_regs *ctx,
    __u8 source, __u8 lib_id, __s32 nid,
    const char *name_src, __u8 name_is_kernel
) {
    struct crypto_event_t *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid = pid_tgid >> 32;
    ev->uid = bpf_get_current_uid_gid();
    ev->ts_ns = bpf_ktime_get_ns();
    ev->source = source;
    ev->lib_id = lib_id;
    ev->_pad0 = 0;
    ev->nid = nid;
    // Zero the name field defensively (Fix B5).
    __builtin_memset(ev->name, 0, NAME_LEN);
    if (name_src) {
        if (name_is_kernel) {
            bpf_probe_read_kernel_str(ev->name, NAME_LEN, name_src);
        } else {
            bpf_probe_read_user_str(ev->name, NAME_LEN, name_src);
        }
    }
    bpf_get_current_comm(&ev->comm, COMM_LEN);
    bpf_ringbuf_submit(ev, 0);
}

// --- Uprobes on libcrypto ---

SEC("uprobe/EVP_CipherInit_ex")
int BPF_KPROBE(uprobe__EVP_CipherInit_ex, void *ctx_arg, int nid) {
    emit(ctx, 1, 1, nid, 0, 0);
    return 0;
}

SEC("uprobe/EVP_EncryptInit_ex")
int BPF_KPROBE(uprobe__EVP_EncryptInit_ex, void *ctx_arg, int nid) {
    emit(ctx, 1, 1, nid, 0, 0);
    return 0;
}

SEC("uprobe/EVP_DigestInit_ex")
int BPF_KPROBE(uprobe__EVP_DigestInit_ex, void *ctx_arg, int md_nid) {
    emit(ctx, 1, 1, md_nid, 0, 0);
    return 0;
}

SEC("uprobe/RSA_generate_key_ex") int BPF_KPROBE(uprobe__RSA_generate_key_ex) { emit(ctx, 1, 1, 6,   0, 0); return 0; }
SEC("uprobe/RSA_sign")            int BPF_KPROBE(uprobe__RSA_sign)            { emit(ctx, 1, 1, 6,   0, 0); return 0; }
SEC("uprobe/RSA_verify")          int BPF_KPROBE(uprobe__RSA_verify)          { emit(ctx, 1, 1, 6,   0, 0); return 0; }
SEC("uprobe/EC_KEY_generate_key") int BPF_KPROBE(uprobe__EC_KEY_generate_key) { emit(ctx, 1, 1, 408, 0, 0); return 0; }
SEC("uprobe/ECDSA_sign")          int BPF_KPROBE(uprobe__ECDSA_sign)          { emit(ctx, 1, 1, 408, 0, 0); return 0; }
SEC("uprobe/EVP_PKEY_derive")     int BPF_KPROBE(uprobe__EVP_PKEY_derive)     { emit(ctx, 1, 1, 1034, 0, 0); return 0; }
SEC("uprobe/SSL_CTX_new")         int BPF_KPROBE(uprobe__SSL_CTX_new)         { emit(ctx, 1, 1, -2, 0, 0); return 0; } // -2 = TLS sentinel

// --- Uprobes on GnuTLS ---

SEC("uprobe/gnutls_cipher_init")
int BPF_KPROBE(uprobe__gnutls_cipher_init, void *h, int algo) {
    emit(ctx, 1, 2, algo, 0, 0);
    return 0;
}

SEC("uprobe/gnutls_hash_init")
int BPF_KPROBE(uprobe__gnutls_hash_init, void *h, int algo) {
    emit(ctx, 1, 2, algo, 0, 0);
    return 0;
}

SEC("uprobe/gnutls_pubkey_verify_data2")
int BPF_KPROBE(uprobe__gnutls_pubkey_verify_data2) { emit(ctx, 1, 2, -3, 0, 0); return 0; } // -3 = Verify sentinel

// --- Uprobes on NSS ---

SEC("uprobe/PK11_CipherOp") int BPF_KPROBE(uprobe__PK11_CipherOp) { emit(ctx, 1, 3, -4, 0, 0); return 0; }
SEC("uprobe/PK11_Digest")   int BPF_KPROBE(uprobe__PK11_Digest)   { emit(ctx, 1, 3, -5, 0, 0); return 0; }

// --- Kprobes on kernel crypto API ---

SEC("kprobe/crypto_alloc_shash")
int BPF_KPROBE(kprobe__crypto_alloc_shash, const char *alg) {
    emit(ctx, 2, 4, -1, alg, 1);
    return 0;
}

SEC("kprobe/crypto_alloc_skcipher")
int BPF_KPROBE(kprobe__crypto_alloc_skcipher, const char *alg) {
    emit(ctx, 2, 4, -1, alg, 1);
    return 0;
}

SEC("kprobe/crypto_alloc_akcipher")
int BPF_KPROBE(kprobe__crypto_alloc_akcipher, const char *alg) {
    emit(ctx, 2, 4, -1, alg, 1);
    return 0;
}

SEC("kprobe/crypto_alloc_aead")
int BPF_KPROBE(kprobe__crypto_alloc_aead, const char *alg) {
    emit(ctx, 2, 4, -1, alg, 1);
    return 0;
}
