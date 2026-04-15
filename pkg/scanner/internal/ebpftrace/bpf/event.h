// SPDX-License-Identifier: Apache-2.0
// Shared uapi between eBPF program and userspace decoder.
#ifndef __TRITON_EBPF_EVENT_H
#define __TRITON_EBPF_EVENT_H

#define NAME_LEN 64
#define COMM_LEN 16

struct crypto_event_t {
    __u32 pid;
    __u32 uid;
    __u64 ts_ns;
    __u8  source;    // 1=uprobe 2=kprobe
    __u8  lib_id;    // 1=libcrypto 2=gnutls 3=nss 4=kernel
    __u16 _pad0;     // alignment to 4 for nid
    __s32 nid;       // -1 for string-based (kernel)
    char  name[NAME_LEN];
    char  comm[COMM_LEN];
};

#endif // __TRITON_EBPF_EVENT_H
