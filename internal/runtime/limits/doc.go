// Package limits implements in-process resource limits for triton.
//
// Caveats:
//
//   - MaxMemoryBytes uses runtime/debug.SetMemoryLimit which is a SOFT limit.
//     The GC works harder to stay under it but cannot guarantee. A watchdog
//     goroutine converts catastrophic breaches (>1.5x) into self-SIGKILL so
//     the process exits cleanly rather than being OOM-killed.
//
//   - The watchdog samples runtime.MemStats.Sys, which is the Go runtime's
//     memory footprint, not the kernel's RSS. For CGO_ENABLED=0 builds
//     (triton's default) these are within a few percent. CGO-enabled builds
//     with large C allocations are undercounted.
//
//   - MaxCPUPercent is enforced via GOMAXPROCS. This caps parallelism, not
//     CPU time. A single goroutine in a tight loop can still saturate one
//     core. For hard CPU quotas, use systemd-run or cgroups as a wrapper.
//
//   - Nice is best-effort. On systems with CAP_SYS_NICE restrictions, setting
//     a negative (higher-priority) nice value may silently fail without
//     returning an error on all platforms.
package limits
