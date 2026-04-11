package scanner

import "fmt"

// ScanCredentials holds optional auth for target types that need it.
// Every secret-bearing field is tagged json:"-" and redacted by String()
// so credentials never leak into scan results, logs, reports, or API
// payloads. Matches the vpn_config.go "REDACTED" precedent.
type ScanCredentials struct {
	RegistryAuthFile string `json:"-"` // path to docker config.json override
	RegistryUsername string `json:"-"` // explicit registry username override
	RegistryPassword string `json:"-"` // explicit registry password override
	Kubeconfig       string `json:"-"` // kubeconfig path override (Sprint 1b)
	K8sContext       string `json:"-"` // kubeconfig context name override
}

// String returns a representation safe to log. Secret fields are replaced
// with "REDACTED" when non-empty; empty fields render as empty strings.
func (c ScanCredentials) String() string {
	return fmt.Sprintf(
		"ScanCredentials{RegistryAuthFile=%q, RegistryUsername=%q, "+
			"RegistryPassword=%s, Kubeconfig=%q, K8sContext=%q}",
		c.RegistryAuthFile,
		c.RegistryUsername,
		redact(c.RegistryPassword),
		c.Kubeconfig,
		c.K8sContext,
	)
}

func redact(s string) string {
	if s == "" {
		return ""
	}
	return "REDACTED"
}
