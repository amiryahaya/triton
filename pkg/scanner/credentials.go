package scanner

import "github.com/amiryahaya/triton/internal/scannerconfig"

// ScanCredentials is re-exported from scannerconfig to avoid an import
// cycle between pkg/scanner and internal/scannerconfig while keeping
// the pkg/scanner.ScanCredentials symbol available to scanner-package
// consumers (e.g., the imageFetcher interface).
type ScanCredentials = scannerconfig.ScanCredentials
