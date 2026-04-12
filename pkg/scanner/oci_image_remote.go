package scanner

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	dockerconfig "github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	dockertypes "github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

type remoteFetcher struct{}

func newRemoteFetcher() imageFetcher {
	return &remoteFetcher{}
}

func (r *remoteFetcher) Fetch(ctx context.Context, ref string, creds ScanCredentials) (*fetchedImage, error) {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse ref: %w", err)
	}

	keychain := resolveKeychain(creds)
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(keychain),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}),
	}

	img, err := remote.Image(parsedRef, opts...)
	if err != nil {
		return nil, fmt.Errorf("remote.Image: %w", err)
	}

	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("img.Digest: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("img.Layers: %w", err)
	}
	// Guard before extraction: reject oversized images early to avoid
	// materialising hundreds of layers to disk only to discard them.
	if len(layers) > ociMaxLayers {
		return nil, fmt.Errorf("oci_image: image exceeds layer cap (%d > %d)", len(layers), ociMaxLayers)
	}

	sandboxRoot, err := newSandboxRoot(digest.String())
	if err != nil {
		return nil, err
	}

	flattened := mutate.Extract(img)
	defer func() { _ = flattened.Close() }()

	sizeBytes, err := extractTarToSandbox(flattened, sandboxRoot)
	if err != nil {
		_ = os.RemoveAll(sandboxRoot)
		return nil, fmt.Errorf("extract: %w", err)
	}

	return &fetchedImage{
		RootFS:    sandboxRoot,
		Ref:       parsedRef.String(),
		Digest:    digest.String(),
		LayerN:    len(layers),
		SizeBytes: sizeBytes,
		Cleanup: func() error {
			return os.RemoveAll(sandboxRoot)
		},
	}, nil
}

func resolveKeychain(creds ScanCredentials) authn.Keychain {
	if creds.RegistryUsername != "" && creds.RegistryPassword != "" {
		return &staticKeychain{
			username: creds.RegistryUsername,
			password: creds.RegistryPassword,
		}
	}
	if creds.RegistryAuthFile != "" {
		if kc, err := newKeychainFromFile(creds.RegistryAuthFile); err == nil {
			return kc
		}
		// Fall through to default keychain if the file is unreadable.
	}
	return authn.DefaultKeychain
}

// newKeychainFromFile reads a Docker-format auth config file at path and
// returns a Keychain backed by it. This avoids mutating os.Setenv("DOCKER_CONFIG"),
// which is a process-global variable and would race under concurrent image scans
// with different auth files.
func newKeychainFromFile(path string) (authn.Keychain, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	cf, err := dockerconfig.LoadFromReader(f)
	if err != nil {
		return nil, err
	}

	return &fileKeychain{cf: cf}, nil
}

// fileKeychain is an authn.Keychain backed by a pre-loaded Docker config file.
// It mirrors the registry-lookup logic of authn.defaultKeychain without
// touching any process-global environment variables.
type fileKeychain struct {
	cf *configfile.ConfigFile
}

// Resolve implements authn.Keychain.
func (k *fileKeychain) Resolve(target authn.Resource) (authn.Authenticator, error) {
	var (
		empty dockertypes.AuthConfig
		cfg   dockertypes.AuthConfig
		err   error
	)
	for _, key := range []string{target.String(), target.RegistryStr()} {
		cfg, err = k.cf.GetAuthConfig(key)
		if err != nil {
			return nil, err
		}
		// GetAuthConfig always sets ServerAddress; clear it so the
		// empty-config check below works correctly.
		cfg.ServerAddress = ""
		if cfg != empty {
			break
		}
	}
	if cfg == empty {
		return authn.Anonymous, nil
	}
	return authn.FromConfig(authn.AuthConfig{
		Username:      cfg.Username,
		Password:      cfg.Password,
		Auth:          cfg.Auth,
		IdentityToken: cfg.IdentityToken,
		RegistryToken: cfg.RegistryToken,
	}), nil
}

type staticKeychain struct {
	username string
	password string
}

func (k *staticKeychain) Resolve(authn.Resource) (authn.Authenticator, error) {
	return &authn.Basic{Username: k.username, Password: k.password}, nil
}

func newSandboxRoot(digest string) (string, error) {
	short := strings.TrimPrefix(digest, "sha256:")
	if len(short) > 12 {
		short = short[:12]
	}
	salt := make([]byte, 4)
	_, _ = rand.Read(salt)
	dir := filepath.Join(os.TempDir(),
		fmt.Sprintf("triton-oci-%s-%s", short, hex.EncodeToString(salt)))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create sandbox: %w", err)
	}
	return dir, nil
}

// extractTarToSandbox reads a tar stream from r and writes entries under
// sandboxRoot, rejecting any path that escapes the sandbox via .. or
// absolute paths. Symlinks and hard links are skipped to prevent escape.
// Returns total extracted bytes.
func extractTarToSandbox(r io.Reader, sandboxRoot string) (int64, error) {
	tr := tar.NewReader(r)
	var total int64

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return total, err
		}

		cleaned := filepath.Clean(hdr.Name)
		if strings.HasPrefix(cleaned, "..") || filepath.IsAbs(cleaned) {
			continue
		}
		target := filepath.Join(sandboxRoot, cleaned)
		if !strings.HasPrefix(target, sandboxRoot+string(os.PathSeparator)) && target != sandboxRoot {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return total, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return total, err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return total, err
			}
			n, err := io.Copy(f, tr)
			_ = f.Close()
			if err != nil {
				return total, err
			}
			total += n
			if total > ociMaxUncompressedBytes {
				return total, fmt.Errorf("extraction exceeded size cap")
			}
		case tar.TypeSymlink, tar.TypeLink:
			continue
		default:
			continue
		}
	}
	return total, nil
}
