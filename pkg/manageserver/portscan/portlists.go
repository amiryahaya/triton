// Package portscan wraps fingerprintx with profile-derived aggressiveness
// for use in Manage Server port survey jobs.
package portscan

// top100Ports contains TCP ports ordered by scan priority
// (most-commonly-open first). top1000Ports and top10000Ports extend it
// programmatically via buildExtended.
var top100Ports = []uint16{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
	143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
	1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 1027,
	554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1028, 9100,
	1029, 2049, 88, 79, 5004, 5005, 8081, 1030, 9102, 8083,
	5800, 8088, 5555, 3283, 2967, 1031, 9200, 5985, 5986,
	8085, 8086, 8087, 8089, 8090, 9090, 9091, 9300,
	1194, 500, 4500, 1701, 8883, 1883, 1521,
	5432, 27017, 6379, 11211, 2181, 2375, 2376, 4243, 8761, 50000,
}

var top1000Ports []uint16
var top10000Ports []uint16

func init() {
	top1000Ports = buildExtended(top100Ports, 1000)
	top10000Ports = buildExtended(top100Ports, 10000)
}

// buildExtended returns a slice of at most limit ports. It starts with all
// ports from base (preserving priority order) then fills up to limit with
// sequentially numbered ports not already in base.
func buildExtended(base []uint16, limit int) []uint16 {
	seen := make(map[uint16]bool, limit)
	out := make([]uint16, 0, limit)
	for _, p := range base {
		if len(out) >= limit {
			break
		}
		if !seen[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	for p := uint16(1); len(out) < limit; p++ {
		if !seen[p] {
			out = append(out, p)
			seen[p] = true
		}
	}
	return out
}
