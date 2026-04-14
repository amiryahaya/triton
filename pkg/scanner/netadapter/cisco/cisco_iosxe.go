package cisco

import (
	"context"
	"log"

	"github.com/amiryahaya/triton/pkg/model"
)

// Adapter scans a Cisco IOS-XE device.
type Adapter struct {
	runner   *CiscoRunner
	hostname string
}

// NewAdapter wires a CiscoRunner to a device hostname.
func NewAdapter(runner *CiscoRunner, hostname string) *Adapter {
	return &Adapter{runner: runner, hostname: hostname}
}

// Scan runs all show commands and emits findings via the channel.
// Per-command errors are logged and don't abort the scan.
func (a *Adapter) Scan(ctx context.Context, findings chan<- *model.Finding) error {
	commands := []struct {
		cmd   string
		parse func(hostname, output string) []*model.Finding
	}{
		{"show ip ssh", parseShowIPSSH},
		{"show crypto pki certificates", parseShowCryptoPKI},
		{"show crypto isakmp policy", parseShowIsakmpPolicy},
		{"show crypto ipsec sa", parseShowCryptoIPsec},
		{"show snmp user", parseShowSNMP},
	}

	for _, c := range commands {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		out, err := a.runner.Run(ctx, c.cmd)
		if err != nil {
			log.Printf("cisco: %s on %s: %v", c.cmd, a.hostname, err)
			continue
		}
		for _, f := range c.parse(a.hostname, out) {
			select {
			case findings <- f:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
