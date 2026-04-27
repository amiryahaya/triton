package sshagent

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/model"
)

// ManageClient is the interface RunOne needs from *Client.
type ManageClient interface {
	GetJob(ctx context.Context, jobID uuid.UUID) (*JobPayload, error)
	SubmitResult(ctx context.Context, jobID uuid.UUID, result *model.ScanResult) error
}

// RunOne fetches job jobID from the Manage Server, runs the SSH scan,
// and submits the result. Entry point for the triton-sshagent binary.
func RunOne(ctx context.Context, jobID uuid.UUID, mc ManageClient, sc Scanner) error {
	job, err := mc.GetJob(ctx, jobID)
	if err != nil {
		return fmt.Errorf("sshagent: get job: %w", err)
	}

	creds := Credentials{
		Username:   job.Credentials.Username,
		Password:   job.Credentials.Password,
		PrivateKey: job.Credentials.PrivateKey,
		Passphrase: job.Credentials.Passphrase,
		Port:       job.Credentials.Port,
	}

	result, err := sc.Scan(ctx, job.Hostname, job.TargetHost, creds, job.ScanProfile)
	if err != nil {
		return fmt.Errorf("sshagent: scan: %w", err)
	}

	if err := mc.SubmitResult(ctx, jobID, result); err != nil {
		return fmt.Errorf("sshagent: submit: %w", err)
	}
	return nil
}
