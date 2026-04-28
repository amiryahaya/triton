// Command triton-sshagent is a dispatched worker binary. It claims one
// SSH agentless scan job from the Manage Server, SSHes into the target
// host, runs the full Triton scanner via fsadapter.SshReader, and
// submits the result back to the Manage Server. Exits 0 on success.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/sshagent"
)

func main() {
	if err := run(); err != nil {
		log.Printf("triton-sshagent: %v", err)
		os.Exit(1)
	}
}

func run() error {
	manageURL := flag.String("manage-url", "", "Manage Server base URL (required)")
	jobIDStr := flag.String("job-id", "", "Job UUID to execute (required)")
	flag.Parse()

	workerKey := os.Getenv("TRITON_WORKER_KEY")

	if *manageURL == "" {
		return fmt.Errorf("--manage-url is required")
	}
	if workerKey == "" {
		return fmt.Errorf("TRITON_WORKER_KEY env var is required")
	}
	jobID, err := uuid.Parse(*jobIDStr)
	if err != nil {
		return fmt.Errorf("invalid --job-id: %w", err)
	}

	mc := sshagent.NewClient(*manageURL, workerKey)
	sc := &sshagent.SSHScanner{}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	return sshagent.RunOne(ctx, jobID, mc, sc)
}
