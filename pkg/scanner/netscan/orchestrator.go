package netscan

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/agent"
	"github.com/amiryahaya/triton/pkg/model"
	"github.com/amiryahaya/triton/pkg/scanner"
	"github.com/amiryahaya/triton/pkg/scanner/fsadapter"
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
	KnownHostsFile   string // path to SSH known_hosts (required unless InsecureHostKey=true)
	InsecureHostKey  bool   // explicit opt-in for lab use; skips host key verification
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
		// Acquire semaphore with context awareness so Ctrl-C during
		// a long scan unblocks the dispatcher instead of waiting for
		// all in-flight workers to drain.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			// Report parent cancellation after wg drains in-flight work.
			goto done
		}
		wg.Add(1)
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
				// Submit with the parent ctx (not devCtx) so that a
				// device that consumed its full PerDeviceTimeout can
				// still submit its result — submission latency should
				// not be tied to scan duration.
				submitCtx, cancelSubmit := context.WithTimeout(ctx, 30*time.Second)
				o.submitResult(submitCtx, result)
				cancelSubmit()
			}
		}()
	}
done:
	wg.Wait()

	totalFailed := atomic.LoadInt64(&failed)
	totalSucceeded := atomic.LoadInt64(&succeeded)
	fmt.Printf("Scan complete: %d succeeded, %d failed\n", totalSucceeded, totalFailed)

	// Surface fleet-wide failure so continuous mode (--interval) can
	// distinguish "all devices broken" (e.g., bad credentials file)
	// from "normal scan with a few flaky hosts".
	if totalSucceeded == 0 && totalFailed > 0 {
		return fmt.Errorf("all %d devices failed — check credentials and network connectivity", totalFailed)
	}
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

// scanUnix runs the standard Tier 1 scanner pipeline against a remote
// Unix host via SSH. Constructs an SshReader, registers default modules,
// injects reader + hostname override, and drains the progress channel.
func (o *Orchestrator) scanUnix(ctx context.Context, d Device, cred *Credential) (*model.ScanResult, error) {
	sshCfg, err := o.credToSSHConfig(d, cred)
	if err != nil {
		return nil, err
	}
	client, err := transport.NewSSHClient(ctx, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	reader := fsadapter.NewSshReader(client)

	paths := d.ScanPaths
	if len(paths) == 0 {
		paths = []string{"/etc", "/usr/local/etc", "/opt"}
	}

	cfg := scannerconfig.Load("standard")
	cfg.DBUrl = ""
	cfg.Workers = 4
	cfg.ScanTargets = make([]model.ScanTarget, 0, len(paths))
	for _, p := range paths {
		cfg.ScanTargets = append(cfg.ScanTargets, model.ScanTarget{
			Type:  model.TargetFilesystem,
			Value: p,
			Depth: 10,
		})
	}

	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()
	eng.SetFileReader(reader)
	eng.SetHostnameOverride(d.Name)

	progressCh := make(chan scanner.Progress, 32)
	go func() {
		for range progressCh {
		}
	}()

	result := eng.Scan(ctx, progressCh)
	if result == nil {
		return nil, fmt.Errorf("engine returned nil result")
	}
	result.Metadata.AgentID = "triton-netscan"
	result.Metadata.ScanProfile = "agentless-unix"
	return result, nil
}

func (o *Orchestrator) scanCisco(ctx context.Context, d Device, cred *Credential) (*model.ScanResult, error) {
	sshCfg, err := o.credToSSHConfig(d, cred)
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
	sshCfg, err := o.credToSSHConfig(d, cred)
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

func (o *Orchestrator) credToSSHConfig(d Device, cred *Credential) (transport.SSHConfig, error) {
	cfg := transport.SSHConfig{
		Address:         fmt.Sprintf("%s:%d", d.Address, d.Port),
		Username:        cred.Username,
		Password:        cred.Password,
		KnownHostsFile:  o.KnownHostsFile,
		InsecureHostKey: o.InsecureHostKey,
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
