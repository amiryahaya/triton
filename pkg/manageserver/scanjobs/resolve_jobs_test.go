package scanjobs_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/scanjobs"
)

func TestResolveJobs_PortSurveyAlwaysCreated(t *testing.T) {
	host := scanjobs.ResolveHostInfo{ID: uuid.New(), ConnectionType: "ssh"}
	created, skipped := scanjobs.ResolveJobs(
		[]scanjobs.ResolveHostInfo{host},
		[]scanjobs.JobType{scanjobs.JobTypePortSurvey},
	)
	require.Len(t, created, 1)
	assert.Len(t, skipped, 0)
	assert.Equal(t, scanjobs.JobTypePortSurvey, created[0].JobType)
	assert.Nil(t, created[0].CredentialsRef, "port survey must not carry a credential ref")
}

func TestResolveJobs_FilesystemEnrolledAgent_NoCredNeeded(t *testing.T) {
	host := scanjobs.ResolveHostInfo{ID: uuid.New(), ConnectionType: "agent"}
	created, skipped := scanjobs.ResolveJobs(
		[]scanjobs.ResolveHostInfo{host},
		[]scanjobs.JobType{scanjobs.JobTypeFilesystem},
	)
	require.Len(t, created, 1)
	assert.Len(t, skipped, 0)
	assert.Nil(t, created[0].CredentialsRef, "agent job must not carry SSH cred")
}

func TestResolveJobs_FilesystemSSH_CredAndPortSet(t *testing.T) {
	credID := uuid.New()
	host := scanjobs.ResolveHostInfo{
		ID:             uuid.New(),
		ConnectionType: "ssh",
		CredentialsRef: &credID,
		SSHPort:        22,
	}
	created, skipped := scanjobs.ResolveJobs(
		[]scanjobs.ResolveHostInfo{host},
		[]scanjobs.JobType{scanjobs.JobTypeFilesystem},
	)
	require.Len(t, created, 1)
	assert.Len(t, skipped, 0)
	assert.Equal(t, &credID, created[0].CredentialsRef)
}

func TestResolveJobs_FilesystemSSH_NoCred_Skipped(t *testing.T) {
	host := scanjobs.ResolveHostInfo{ID: uuid.New(), ConnectionType: "ssh"}
	created, skipped := scanjobs.ResolveJobs(
		[]scanjobs.ResolveHostInfo{host},
		[]scanjobs.JobType{scanjobs.JobTypeFilesystem},
	)
	assert.Len(t, created, 0)
	require.Len(t, skipped, 1)
	assert.Equal(t, "no_credential", skipped[0].Reason)
}

func TestResolveJobs_AgentSupersedesSSHCred(t *testing.T) {
	credID := uuid.New()
	host := scanjobs.ResolveHostInfo{
		ID:             uuid.New(),
		ConnectionType: "agent",
		CredentialsRef: &credID,
		SSHPort:        22,
	}
	created, skipped := scanjobs.ResolveJobs(
		[]scanjobs.ResolveHostInfo{host},
		[]scanjobs.JobType{scanjobs.JobTypeFilesystem},
	)
	require.Len(t, created, 1)
	assert.Len(t, skipped, 0)
	assert.Nil(t, created[0].CredentialsRef, "enrolled agent supersedes SSH cred — cred must be nil")
}
