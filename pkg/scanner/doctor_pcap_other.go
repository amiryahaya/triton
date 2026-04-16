//go:build !linux

package scanner

func pcapDoctorCheck() (ok bool, detail string) {
	return false, "live pcap capture requires Linux (AF_PACKET); offline .pcap file analysis works on all platforms"
}
