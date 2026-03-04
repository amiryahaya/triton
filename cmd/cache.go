package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/store"
)

func openStore() (store.Store, error) {
	url := dbPath
	if url == "" {
		url = config.DefaultDBUrl()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return store.NewPostgresStore(ctx, url)
}

var cacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage the file hash cache used for incremental scanning",
}

var cacheStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show cache statistics",
	RunE:  runCacheStats,
}

var cacheClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear the file hash cache",
	RunE:  runCacheClear,
}

func init() {
	rootCmd.AddCommand(cacheCmd)
	cacheCmd.AddCommand(cacheStatsCmd)
	cacheCmd.AddCommand(cacheClearCmd)
}

func runCacheStats(_ *cobra.Command, _ []string) error {
	db, err := openStore()
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	count, oldest, newest, err := db.FileHashStats(context.Background())
	if err != nil {
		return fmt.Errorf("querying stats: %w", err)
	}

	fmt.Printf("File hash cache statistics:\n")
	fmt.Printf("  Cached entries: %d\n", count)
	if count > 0 {
		fmt.Printf("  Oldest entry:   %s\n", oldest.Format(time.RFC3339))
		fmt.Printf("  Newest entry:   %s\n", newest.Format(time.RFC3339))
	}
	return nil
}

func runCacheClear(_ *cobra.Command, _ []string) error {
	db, err := openStore()
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Prune everything by using a far-future cutoff.
	err = db.PruneStaleHashes(context.Background(), time.Now().Add(24*time.Hour))
	if err != nil {
		return fmt.Errorf("clearing cache: %w", err)
	}

	fmt.Println("File hash cache cleared.")
	return nil
}
