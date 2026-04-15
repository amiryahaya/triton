// SPDX-License-Identifier: Apache-2.0
// Minimal BTF-shim for CO-RE. Full vmlinux.h is 40MB+; we stub only what
// bpf_helpers.h and our probes reference.
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef signed char __s8;
typedef unsigned char __u8;
typedef signed short __s16;
typedef unsigned short __u16;
typedef signed int __s32;
typedef unsigned int __u32;
typedef signed long long __s64;
typedef unsigned long long __u64;

typedef __u32 u32;
typedef __u64 u64;

// struct pt_regs is architecture-dependent. libbpf's bpf_tracing.h provides
// PT_REGS_PARMx macros that expand to the right field. We only need the
// opaque type declaration here.
struct pt_regs;

#endif // __VMLINUX_H__
