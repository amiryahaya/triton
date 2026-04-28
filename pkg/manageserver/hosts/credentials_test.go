package hosts_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/manageserver/hosts"
)

func TestHost_CredentialsRefAndAccessPortFields(t *testing.T) {
	var h hosts.Host
	credID := uuid.New()
	h.CredentialsRef = &credID
	h.SSHPort = 2222
	if h.SSHPort != 2222 {
		t.Error("AccessPort not settable")
	}
	if h.CredentialsRef == nil || *h.CredentialsRef != credID {
		t.Error("CredentialsRef not settable")
	}
}
