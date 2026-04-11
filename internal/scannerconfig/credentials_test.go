package scannerconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanCredentials_StringRedacts(t *testing.T) {
	c := ScanCredentials{
		RegistryAuthFile: "/etc/docker/config.json",
		RegistryUsername: "alice",
		RegistryPassword: "super-secret",
		Kubeconfig:       "/home/alice/.kube/config",
		K8sContext:       "prod",
	}
	s := c.String()
	assert.Contains(t, s, "/etc/docker/config.json")
	assert.Contains(t, s, "alice")
	assert.Contains(t, s, "REDACTED")
	assert.NotContains(t, s, "super-secret")
}

func TestScanCredentials_EmptyPasswordNotRedacted(t *testing.T) {
	c := ScanCredentials{RegistryUsername: "alice"}
	s := c.String()
	assert.NotContains(t, s, "REDACTED")
}

func TestScanCredentials_JSONMarshalDropsSecrets(t *testing.T) {
	c := ScanCredentials{
		RegistryAuthFile: "/etc/docker/config.json",
		RegistryUsername: "alice",
		RegistryPassword: "super-secret",
		Kubeconfig:       "/home/alice/.kube/config",
		K8sContext:       "prod",
	}
	b, err := json.Marshal(c)
	require.NoError(t, err)
	body := string(b)
	assert.False(t, strings.Contains(body, "super-secret"), "password must not appear")
	assert.False(t, strings.Contains(body, "alice"), "username tagged json:- must not appear")
	assert.False(t, strings.Contains(body, "prod"), "context tagged json:- must not appear")
	assert.Equal(t, "{}", body, "all fields tagged json:- so marshal is empty object")
}
