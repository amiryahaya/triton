package juniper

import (
	"context"
	"log"

	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/netadapter/transport"
)

// Adapter scans a Juniper Junos device via NETCONF.
type Adapter struct {
	netconf  *transport.NetconfClient
	hostname string
}

// NewAdapter wires a NetconfClient to a device hostname.
func NewAdapter(netconf *transport.NetconfClient, hostname string) *Adapter {
	return &Adapter{netconf: netconf, hostname: hostname}
}

// Scan runs get-config for each configuration subtree and emits findings.
func (a *Adapter) Scan(ctx context.Context, findings chan<- *model.Finding) error {
	type query struct {
		filter string
		parse  func(hostname string, data []byte) ([]*model.Finding, error)
	}
	queries := []query{
		{`<filter><configuration><system><services><ssh/></services></system></configuration></filter>`, parseSSHConfig},
		{`<filter><configuration><security><ike/></security></configuration></filter>`, parseIKEConfig},
		{`<filter><configuration><security><ipsec/></security></configuration></filter>`, parseIPsecConfig},
		{`<filter><configuration><security><pki/></security></configuration></filter>`, parsePKIConfig},
		{`<filter><configuration><snmp/></configuration></filter>`, parseSNMPConfig},
	}

	for _, q := range queries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		data, err := a.netconf.GetConfig(ctx, q.filter)
		if err != nil {
			log.Printf("juniper: get-config on %s: %v", a.hostname, err)
			continue
		}
		parsed, err := q.parse(a.hostname, data)
		if err != nil {
			log.Printf("juniper: parse on %s: %v", a.hostname, err)
			continue
		}
		for _, f := range parsed {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
