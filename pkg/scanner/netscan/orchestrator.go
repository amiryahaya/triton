package netscan

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner/netadapter/cisco"
	"github.com/amiryahaya/triton/pkg/scanner/netadapter/juniper"
	"github.com/amiryahaya/triton/pkg/scanner/netadapter/transport"
)

// Orchestrator runs per-device scans concurrently with bounded parallelism.
type Orchestrator struct {
	Inventory        *Inventory
	Credentials      *CredentialStore
	Concurrency      int
	PerDeviceTimeout time.Duration
	ReportServerURL  string
}

// Scan scans all given devices concurrently. Submits results to the
// report server if ReportServerURL is set.
func (o *Orchestrator) Scan(ctx context.Context, devices []Device) error {
	if o.Concurrency <= 0 {
		o.Concurrency = 20
	}
	if o.PerDeviceTimeout <= 0 {
		o.PerDeviceTimeout = 5 * time.Minute
	}

	var (
		wg        sync.WaitGroup
		sem       = make(chan struct{}, o.Concurrency)
		succeeded int64
		failed    int64
	)

	for i := range devices {
		d := devices[i]
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			devCtx, cancel := context.WithTimeout(ctx, o.PerDeviceTimeout)
			defer cancel()

			result, err := o.scanDevice(devCtx, d)
			if err != nil {
				log.Printf("device %s: %v", d.Name, err)
				result = makeFailureResult(d, err)
				atomic.AddInt64(&failed, 1)
			} else {
				atomic.AddInt64(&succeeded, 1)
			}

			if o.ReportServerURL != "" && result != nil {
				o.submitResult(devCtx, result)
			}
		}()
	}
	wg.Wait()

	fmt.Printf("Scan complete: %d succeeded, %d failed\n",
		atomic.LoadInt64(&succeeded), atomic.LoadInt64(&failed))
	return nil
}

func (o *Orchestrator) scanDevice(ctx context.Context, d Device) (*model.ScanResult, error) {
	cred := o.Credentials.Get(d.Credential)
	if cred == nil {
		return nil, fmt.Errorf("credential %q not found", d.Credential)
	}

	switch d.Type {
	case "unix":
		return o.scanUnix(ctx, d, cred)
	case "cisco-iosxe":
		return o.scanCisco(ctx, d, cred)
	case "juniper-junos":
		return o.scanJuniper(ctx, d, cred)
	default:
		return nil, fmt.Errorf("unknown device type: %s", d.Type)
	}
}

// scanUnix performs a minimal SSH probe for MVP: verifies connectivity
// and returns a result with no findings. Full Tier 1 module execution
// over SSH is a follow-up — it requires plumbing FileReader through
// the scanner engine which is more invasive than this MVP scope.
func (o *Orchestrator) scanUnix(ctx context.Context, d Device, cred *Credential) (*model.ScanResult, error) {
	sshCfg, err := credToSSHConfig(d, cred)
	if err != nil {
		return nil, err
	}
	client, err := transport.NewSSHClient(ctx, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Probe: run `uname -a` to verify SSH works.
	if _, err := client.Run(ctx, "uname -a"); err != nil {
		return nil, fmt.Errorf("ssh probe: %w", err)
	}

	return &model.ScanResult{
		Metadata: model.ScanMetadata{
			Hostname:  d.Name,
			AgentID:   "triton-netscan",
			ScanProfile: "agentless-unix",
			Timestamp: time.Now().UTC(),
		},
		// Findings empty for MVP. Follow-up wires Tier 1 scanner engine
		// against an SshReader.
	}, nil
}

func (o *Orchestrator) scanCisco(ctx context.Context, d Device, cred *Credential) (*model.ScanResult, error) {
	sshCfg, err := credToSSHConfig(d, cred)
	if err != nil {
		return nil, err
	}
	client, err := transport.NewSSHClient(ctx, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	enablePass := ""
	if d.EnableCredential != "" {
		if ec := o.Credentials.Get(d.EnableCredential); ec != nil {
			enablePass = ec.Password
		}
	}

	runner := cisco.NewCiscoRunner(client, enablePass)
	adapter := cisco.NewAdapter(runner, d.Name)

	return runAdapter(ctx, d, "agentless-cisco", adapter.Scan)
}

func (o *Orchestrator) scanJuniper(ctx context.Context, d Device, cred *Credential) (*model.ScanResult, error) {
	sshCfg, err := credToSSHConfig(d, cred)
	if err != nil {
		return nil, err
	}
	client, err := transport.NewSSHClient(ctx, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	nc, err := transport.NewNetconfClient(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("netconf: %w", err)
	}
	defer func() { _ = nc.Close() }()

	adapter := juniper.NewAdapter(nc, d.Name)
	return runAdapter(ctx, d, "agentless-juniper", adapter.Scan)
}

// runAdapter drains the findings channel from a vendor adapter and
// packages them into a ScanResult.
func runAdapter(
	ctx context.Context,
	d Device,
	profile string,
	scanFn func(context.Context, chan<- *model.Finding) error,
) (*model.ScanResult, error) {
	findings := make(chan *model.Finding, 100)
	result := &model.ScanResult{
		Metadata: model.ScanMetadata{
			Hostname:    d.Name,
			AgentID:     "triton-netscan",
			ScanProfile: profile,
			Timestamp:   time.Now().UTC(),
		},
	}

	errCh := make(chan error, 1)
	go func() {
		err := scanFn(ctx, findings)
		close(findings)
		errCh <- err
	}()

	for f := range findings {
		result.Findings = append(result.Findings, *f)
	}
	if err := <-errCh; err != nil {
		return result, err
	}
	return result, nil
}

func (o *Orchestrator) submitResult(ctx context.Context, result *model.ScanResult) {
	client := agent.New(o.ReportServerURL)
	if _, err := client.Submit(ctx, result); err != nil {
		log.Printf("submit %s: %v", result.Metadata.Hostname, err)
	}
}

func credToSSHConfig(d Device, cred *Credential) (transport.SSHConfig, error) {
	cfg := transport.SSHConfig{
		Address:  fmt.Sprintf("%s:%d", d.Address, d.Port),
		Username: cred.Username,
		Password: cred.Password,
	}
	if cred.PrivateKeyPath != "" {
		data, err := os.ReadFile(cred.PrivateKeyPath)
		if err != nil {
			return cfg, fmt.Errorf("read private key %s: %w", cred.PrivateKeyPath, err)
		}
		cfg.PrivateKey = data
	}
	cfg.Passphrase = cred.Passphrase
	return cfg, nil
}

func makeFailureResult(d Device, err error) *model.ScanResult {
	return &model.ScanResult{
		Metadata: model.ScanMetadata{
			Hostname:     d.Name,
			AgentID:      "triton-netscan",
			ScanProfile:  "agentless-failed",
			Timestamp:    time.Now().UTC(),
			PolicyResult: err.Error(),
		},
	}
}
