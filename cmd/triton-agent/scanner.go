package main

import (
	"context"

	"github.com/amiryahaya/triton/internal/scannerconfig"
	"github.com/amiryahaya/triton/pkg/scanner"
)

// localScanner implements tritonagent.Scanner by delegating to the real
// scanner engine. It scans the local filesystem — no remote adapters.
type localScanner struct{}

func (s *localScanner) RunScan(ctx context.Context, profile string) (any, error) {
	cfg := scannerconfig.Load(profile)
	eng := scanner.New(cfg)
	eng.RegisterDefaultModules()

	progressCh := make(chan scanner.Progress, 32)
	go func() {
		for range progressCh {
		}
	}()

	result := eng.Scan(ctx, progressCh)
	return result, nil
}
