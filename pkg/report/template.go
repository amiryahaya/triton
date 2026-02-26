package report

import (
	_ "embed"
	"os"
)

//go:embed template/pqc_report_template.xlsx
var templateXLSX []byte

// copyTemplate writes the embedded Excel template to the destination path.
func copyTemplate(destPath string) error {
	return os.WriteFile(destPath, templateXLSX, 0o644)
}
