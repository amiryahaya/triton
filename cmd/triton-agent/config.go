package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

// agentConfig holds the triton-agent configuration loaded from YAML.
type agentConfig struct {
	EngineURL   string `yaml:"engine_url"`
	CertPath    string `yaml:"cert_path"`
	KeyPath     string `yaml:"key_path"`
	CAPath      string `yaml:"ca_path"`
	ScanProfile string `yaml:"scan_profile"`
	HostID      string `yaml:"host_id"`
}

func loadConfig(path string) (agentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return agentConfig{}, err
	}
	var cfg agentConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return agentConfig{}, err
	}
	if cfg.ScanProfile == "" {
		cfg.ScanProfile = "standard"
	}
	return cfg, nil
}
