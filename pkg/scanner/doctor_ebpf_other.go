//go:build !linux

package scanner

// ebpfDoctorCheck is the non-Linux stub: eBPF is unavailable by platform, so
// this always returns (false, "not Linux") and the doctor reports a WARN.
func ebpfDoctorCheck() (ok bool, detail string) {
	return false, "not Linux"
}
