//go:build linux

package scanner

import "os"

func pcapDoctorCheck() (ok bool, detail string) {
	if os.Geteuid() != 0 {
		return false, "not root; live pcap requires CAP_NET_RAW or root"
	}
	return true, "root access available for AF_PACKET"
}
