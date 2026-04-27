package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/portscan"
	"github.com/amiryahaya/triton/pkg/scanrunner"
)

func main() {
	if err := run(); err != nil {
		log.Printf("triton-portscan: %v", err)
		os.Exit(1)
	}
}

func run() error {
	// CLI flags
	manageURL := flag.String("manage-url", "", "Manage server base URL (required)")
	jobIDStr := flag.String("job-id", "", "Job UUID to claim and run (required)")
	reportURL := flag.String("report-url", "", "Report server base URL (optional; skip submission if empty)")
	licenseToken := flag.String("license-token", "", "License token for the report server (env: TRITON_LICENSE_TOKEN)")
	flag.Parse()

	// Worker key from env (not flag — avoids ps exposure).
	workerKey := os.Getenv("TRITON_WORKER_KEY")

	// License token: flag wins over env var.
	if *licenseToken == "" {
		*licenseToken = os.Getenv("TRITON_LICENSE_TOKEN")
	}

	// Validate required inputs.
	if *manageURL == "" {
		log.Fatal("--manage-url is required")
	}
	if workerKey == "" {
		log.Fatal("TRITON_WORKER_KEY env var is required")
	}
	jobID, err := uuid.Parse(*jobIDStr)
	if err != nil {
		log.Fatalf("invalid --job-id: %v", err)
	}

	// Build clients.
	mc := scanrunner.NewManageClient(*manageURL, workerKey)
	var rc *scanrunner.ReportClient
	if *reportURL != "" {
		rc = scanrunner.NewReportClient(*reportURL, *licenseToken)
	}

	// Build scanner.
	scanner := portscan.NewFingerprintxScanner()

	// Context: cancel on SIGTERM/SIGINT.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	return scanrunner.RunOne(ctx, jobID, mc, rc, scanner)
}
