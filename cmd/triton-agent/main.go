// Command triton-agent is a lightweight daemon that connects to the Triton
// Manage Server's mTLS gateway, heartbeats periodically, and executes
// scans on demand.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/amiryahaya/triton/internal/version"
	"github.com/amiryahaya/triton/pkg/tritonagent"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfgPath := os.Getenv("TRITON_AGENT_CONFIG")
	if cfgPath == "" {
		cfgPath = "/opt/triton/agent.yaml"
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	c, err := tritonagent.NewClient(cfg.ManageURL, cfg.CertPath, cfg.KeyPath, cfg.CAPath, cfg.HostID)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Printf("triton-agent starting: host_id=%s manage=%s", cfg.HostID, cfg.ManageURL)

	loopErr := tritonagent.Run(ctx, c, tritonagent.Config{
		DefaultProfile: cfg.ScanProfile,
		Version:        version.Version,
		Scanner:        &localScanner{},
	})
	if loopErr != nil && loopErr != context.Canceled {
		return loopErr
	}

	log.Println("triton-agent stopped")
	return nil
}
