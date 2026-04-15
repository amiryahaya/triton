// Package hostmatch defines the neutral HostSummary projection shared
// between the credentials matcher resolver and the inventory store's
// host-listing query. It lives in its own package to break the
// otherwise-inevitable import cycle:
//
//	credentials (matcher) needs HostSummary
//	credentials (handlers) imports inventory to list hosts
//	inventory (ListHostSummaries) would need to return HostSummary
//
// By parking the type here, both packages import hostmatch and neither
// imports the other for this purpose.
package hostmatch

import (
	"net"

	"github.com/google/uuid"
)

// HostSummary is the projection of inventory_hosts + inventory_tags
// consumed by the matcher resolver. Address is nil for hostname-only
// rows; OS is empty for un-classified hosts; Tags is always non-nil
// (empty map when the host has no tags).
type HostSummary struct {
	ID      uuid.UUID
	GroupID uuid.UUID
	Address net.IP
	OS      string
	Tags    map[string]string
}
