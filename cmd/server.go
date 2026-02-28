package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/amiryahaya/triton/internal/config"
	"github.com/amiryahaya/triton/pkg/server"
	"github.com/amiryahaya/triton/pkg/store"
)

var (
	serverListen  string
	serverDB      string
	serverAPIKeys []string
	serverTLSCert string
	serverTLSKey  string
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the Triton REST API server",
	RunE:  runServer,
}

func init() {
	serverCmd.Flags().StringVar(&serverListen, "listen", ":8080", "Listen address")
	serverCmd.Flags().StringVar(&serverDB, "db", "", "PostgreSQL connection URL (default: postgres://triton:triton@localhost:5434/triton?sslmode=disable)")
	serverCmd.Flags().StringSliceVar(&serverAPIKeys, "api-key", nil, "Allowed API keys (can be specified multiple times)")
	serverCmd.Flags().StringVar(&serverTLSCert, "tls-cert", "", "TLS certificate file")
	serverCmd.Flags().StringVar(&serverTLSKey, "tls-key", "", "TLS key file")
	rootCmd.AddCommand(serverCmd)
}

func runServer(_ *cobra.Command, _ []string) error {
	dbUrlVal := serverDB
	if dbUrlVal == "" {
		dbUrlVal = config.DefaultDBUrl()
	}

	ctx := context.Background()
	db, err := store.NewPostgresStore(ctx, dbUrlVal)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = db.Close() }()

	cfg := &server.Config{
		ListenAddr: serverListen,
		DBUrl:      dbUrlVal,
		APIKeys:    serverAPIKeys,
		TLSCert:    serverTLSCert,
		TLSKey:     serverTLSKey,
	}

	srv := server.New(cfg, db)

	// Graceful shutdown.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case sig := <-sigCh:
		fmt.Printf("\nReceived %v, shutting down...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
