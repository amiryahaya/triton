//go:build integration

package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/pkg/scanner/internal/cli"
)

// BuildDotNetTestAssembly returns bytes for a synthetic .NET assembly used by
// integration tests in test/integration/. Exported through this build-tagged
// shim so the cli package's fixture builder isn't reachable from production
// code paths.
func BuildDotNetTestAssembly(t *testing.T) []byte {
	return cli.BuildAssembly(t, cli.FixtureAssembly{
		TypeRefs: []cli.TypeRef{
			{Namespace: "System.Security.Cryptography", Name: "AesManaged"},
			{Namespace: "System.Security.Cryptography", Name: "MD5CryptoServiceProvider"},
		},
		UserStrings: []string{"BCRYPT_RSA_ALGORITHM"},
	})
}
