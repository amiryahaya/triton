// Command triton-engine is the long-running agent binary that phones
// home to the Triton portal. It loads an onboarding bundle (cert/key/
// manifest) from disk, enrolls, then heartbeats every 30s until the
// process receives SIGINT or SIGTERM.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/amiryahaya/triton/pkg/engine/client"
	"github.com/amiryahaya/triton/pkg/engine/loop"
)

// run is the real entry point — factored out so that main() stays
// free of `defer + log.Fatalf` hazards flagged by gocritic. main()
// simply calls run() and propagates the exit code.
func run() int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutdown signal received")
		cancel()
	}()

	bundlePath := os.Getenv("TRITON_BUNDLE_PATH")
	if bundlePath == "" {
		bundlePath = "/etc/triton/bundle.tar.gz"
	}

	c, err := client.New(bundlePath)
	if err != nil {
		log.Printf("bundle load: %v", err)
		return 1
	}

	log.Printf("triton-engine starting: engine_id=%s portal=%s", c.EngineID, c.PortalURL)

	if err := loop.Run(ctx, c, loop.Config{}); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("loop: %v", err)
		return 1
	}
	log.Println("triton-engine stopped")
	return 0
}

func main() { os.Exit(run()) }
