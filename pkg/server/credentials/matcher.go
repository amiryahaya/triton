package credentials

import (
	"net"

	"github.com/google/uuid"
)

// ResolveMatcher returns the subset of hosts that satisfy every
// predicate in m. An empty Matcher (no group IDs, no OS, no CIDR,
// no tags) matches every host. All predicates combine with AND.
//
// Tag matching requires every (k, v) pair in m.Tags to appear on the
// host with the exact value. A malformed CIDR yields zero matches
// (not an error) so policy authors get a visibly empty deploy instead
// of a 500 propagating to the operator — validation happens at admit
// time in the handler layer.
func ResolveMatcher(m Matcher, hosts []HostSummary) []uuid.UUID {
	var cidrNet *net.IPNet
	if m.CIDR != "" {
		_, n, err := net.ParseCIDR(m.CIDR)
		if err != nil {
			return nil
		}
		cidrNet = n
	}

	var groupSet map[uuid.UUID]struct{}
	if len(m.GroupIDs) > 0 {
		groupSet = make(map[uuid.UUID]struct{}, len(m.GroupIDs))
		for _, g := range m.GroupIDs {
			groupSet[g] = struct{}{}
		}
	}

	out := make([]uuid.UUID, 0, len(hosts))
	for _, h := range hosts {
		if groupSet != nil {
			if _, ok := groupSet[h.GroupID]; !ok {
				continue
			}
		}
		if m.OS != "" && h.OS != m.OS {
			continue
		}
		if cidrNet != nil {
			if h.Address == nil || !cidrNet.Contains(h.Address) {
				continue
			}
		}
		if len(m.Tags) > 0 {
			if !tagsSubsetEqual(m.Tags, h.Tags) {
				continue
			}
		}
		out = append(out, h.ID)
	}
	return out
}

func tagsSubsetEqual(want, have map[string]string) bool {
	for k, v := range want {
		got, ok := have[k]
		if !ok || got != v {
			return false
		}
	}
	return true
}
