package transport

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"
)

// NETCONF end-of-message framing (RFC 6242 NETCONF 1.0).
const netconfEOM = "]]>]]>"

// NetconfClient is a minimal NETCONF client over the SSH 'netconf' subsystem.
// Supports <get-config> only — no edit-config, no notifications.
type NetconfClient struct {
	sess   *ssh.Session
	stdin  io.WriteCloser
	stdout io.Reader
}

// NewNetconfClient opens the 'netconf' SSH subsystem and exchanges hello messages.
func NewNetconfClient(ctx context.Context, sshClient *SSHClient) (*NetconfClient, error) {
	_ = ctx
	sess, err := sshClient.Client().NewSession()
	if err != nil {
		return nil, fmt.Errorf("netconf session: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("netconf stdin: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("netconf stdout: %w", err)
	}
	if err := sess.RequestSubsystem("netconf"); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("netconf subsystem: %w", err)
	}

	nc := &NetconfClient{sess: sess, stdin: stdin, stdout: stdout}

	// Send client hello
	hello := `<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
  </capabilities>
</hello>
` + netconfEOM
	if _, err := stdin.Write([]byte(hello)); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("netconf hello: %w", err)
	}
	// Read and discard server hello
	if _, err := nc.readMessage(); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("netconf server hello: %w", err)
	}
	return nc, nil
}

// GetConfig issues <get-config source=running> with an optional XML filter.
// Returns the <data> payload bytes.
func (n *NetconfClient) GetConfig(ctx context.Context, filter string) ([]byte, error) {
	_ = ctx
	rpc := fmt.Sprintf(`<?xml version="1.0"?>
<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
  <get-config>
    <source><running/></source>
    %s
  </get-config>
</rpc>`+netconfEOM, filter)
	if _, err := n.stdin.Write([]byte(rpc)); err != nil {
		return nil, err
	}
	return n.readMessage()
}

// Close terminates the session.
func (n *NetconfClient) Close() error {
	_, _ = n.stdin.Write([]byte(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="close"><close-session/></rpc>` + netconfEOM))
	return n.sess.Close()
}

// readMessage reads bytes up to the NETCONF end-of-message marker.
func (n *NetconfClient) readMessage() ([]byte, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		nb, err := n.stdout.Read(tmp)
		if nb > 0 {
			buf.Write(tmp[:nb])
			if idx := bytes.Index(buf.Bytes(), []byte(netconfEOM)); idx >= 0 {
				return buf.Bytes()[:idx], nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
}

// ValidateXML confirms the response parses as XML (best-effort sanity check).
func ValidateXML(data []byte) error {
	var v struct{ XMLName xml.Name }
	return xml.Unmarshal(data, &v)
}
