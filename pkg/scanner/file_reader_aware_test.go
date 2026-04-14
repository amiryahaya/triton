package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
)

// TestFileReaderAware_OnlyAgentlessCompatibleModules asserts that only
// modules which actually honor the injected FileReader implement
// FileReaderAware. Prevents the "dead adapter" pattern from returning —
// i.e. modules that store the reader but call os.Open / zip.OpenReader
// directly, which would silently miss remote files in agentless scans.
//
// The modules named in deadAdapterModules below read the local filesystem
// via stdlib (os.Open, archive/zip.OpenReader) and cannot service a
// non-local FileReader today. If one of them re-adds SetFileReader
// without also plumbing the reader into section extraction / ZIP
// decoding, this test will fail with a clear explanation of why.
func TestFileReaderAware_OnlyAgentlessCompatibleModules(t *testing.T) {
	cfg := &scannerconfig.Config{}
	e := New(cfg)
	e.RegisterDefaultModules()

	deadAdapterModules := map[string]bool{
		"asn1_oid":      true,
		"java_bytecode": true,
		// config: parseSSHConfig and parseJavaSecurity call os.Open
		// directly despite the walker being wired to the reader.
		// SetFileReader has been removed for now; if re-added before
		// the parsers are plumbed, this guard catches it.
		"config": true,
	}

	for _, m := range e.modules {
		name := m.Name()
		if _, implements := m.(FileReaderAware); implements && deadAdapterModules[name] {
			t.Errorf(
				"%s implements FileReaderAware but does not honor the reader "+
					"(it reads via os.Open / zip.OpenReader). Remove SetFileReader "+
					"until agentless section/ZIP reading is genuinely wired through.",
				name,
			)
		}
	}
}
