package scanner

import (
	"testing"

	"github.com/amiryahaya/triton/internal/scannerconfig"
)

// TestFileReaderAware_OnlyAgentlessCompatibleModules asserts that the
// modules known to read the local filesystem directly (os.Open,
// archive/zip.OpenReader, os.Readlink) do NOT implement FileReaderAware
// — implementing the interface without honoring the reader produces a
// "dead adapter" that silently misses remote files in agentless scans.
//
// This test guards against two regression cases:
//  1. A dead-listed module re-adds SetFileReader without plumbing the
//     reader into its file-I/O helpers (e.g. section extraction, ZIP
//     decoding, config parsing).
//  2. A new scanner is added to the dead-adapter set (listed here) but
//     forgets to drop SetFileReader.
//
// Ideal future state: invert to a fullyWiredModules allowlist so every
// FileReaderAware implementer must explicitly justify itself via the
// audited list. Deferred pending a full audit of the ~25 existing
// FileReaderAware implementers.
func TestFileReaderAware_OnlyAgentlessCompatibleModules(t *testing.T) {
	cfg := &scannerconfig.Config{}
	e := New(cfg)
	e.RegisterDefaultModules()

	knownDeadAdapterModules := map[string]bool{
		// asn1_oid, java_bytecode: read ELF/Mach-O/PE sections and ZIP
		// entries through stdlib directly; the injected reader would
		// never be consulted. See engine.go's FileReaderAware contract.
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
		if _, implements := m.(FileReaderAware); implements && knownDeadAdapterModules[name] {
			t.Errorf(
				"%s implements FileReaderAware but does not honor the reader "+
					"(it reads via os.Open / zip.OpenReader). Remove SetFileReader "+
					"until agentless section/ZIP reading is genuinely wired through.",
				name,
			)
		}
	}
}
