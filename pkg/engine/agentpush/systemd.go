package agentpush

import (
	"bytes"
	"text/template"
)

// systemdUnit is the systemd service unit installed on target hosts by
// the push executor. The agent binary reads its config from the path
// set in TRITON_AGENT_CONFIG.
const systemdUnit = `[Unit]
Description=Triton Agent — PQC crypto scanner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/triton/triton-agent
Restart=always
RestartSec=10
WorkingDirectory=/opt/triton
Environment=TRITON_AGENT_CONFIG=/opt/triton/agent.yaml

[Install]
WantedBy=multi-user.target
`

// agentConfigTmpl renders the agent's YAML configuration file.
var agentConfigTmpl = template.Must(template.New("agent.yaml").Parse(`engine_url: {{.EngineURL}}
cert_path: /opt/triton/agent.crt
key_path: /opt/triton/agent.key
ca_path: /opt/triton/engine-ca.crt
scan_profile: {{.ScanProfile}}
host_id: {{.HostID}}
`))

// AgentConfigData holds the template values for the agent config file.
type AgentConfigData struct {
	EngineURL   string
	ScanProfile string
	HostID      string
}

// RenderAgentConfig executes the agent config template and returns the
// rendered YAML bytes.
func RenderAgentConfig(data AgentConfigData) ([]byte, error) {
	var buf bytes.Buffer
	if err := agentConfigTmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
