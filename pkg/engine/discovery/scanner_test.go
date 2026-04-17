package discovery

import (
	"context"
	"encoding/xml"
	"testing"
)

func TestParseNmapXML_BasicHosts(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="router.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.0.166" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.0.2" addrtype="ipv4"/>
  </host>
</nmaprun>`)

	candidates, err := parseNmapXML(data)
	if err != nil {
		t.Fatalf("parseNmapXML: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
	if candidates[0].Address != "192.168.0.1" {
		t.Errorf("host 0 address: %s", candidates[0].Address)
	}
	if candidates[0].Hostname != "router.local" {
		t.Errorf("host 0 hostname: %s", candidates[0].Hostname)
	}
	if len(candidates[0].OpenPorts) != 3 {
		t.Errorf("host 0 ports: %v", candidates[0].OpenPorts)
	}
	if candidates[1].Address != "192.168.0.166" {
		t.Errorf("host 1 address: %s", candidates[1].Address)
	}
}

func TestParseNmapXML_PingSweep_NoPorts(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/></host>
  <host><status state="down"/><address addr="10.0.0.2" addrtype="ipv4"/></host>
</nmaprun>`)

	candidates, err := parseNmapXML(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2, got %d", len(candidates))
	}
	if len(candidates[0].OpenPorts) != 0 {
		t.Errorf("expected no ports for ping sweep, got %v", candidates[0].OpenPorts)
	}
}

func TestParseNmapXML_Empty(t *testing.T) {
	data := []byte(`<?xml version="1.0"?><nmaprun></nmaprun>`)
	candidates, err := parseNmapXML(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("expected 0, got %d", len(candidates))
	}
}

func TestParseNmapXML_IPv6(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="fe80::1" addrtype="ipv6"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
  </host>
</nmaprun>`)
	candidates, err := parseNmapXML(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Address != "fe80::1" {
		t.Errorf("IPv6: %+v", candidates)
	}
}

func TestNmapXML_StructTags(t *testing.T) {
	var run nmapRun
	data := []byte(`<nmaprun><host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/></host></nmaprun>`)
	if err := xml.Unmarshal(data, &run); err != nil {
		t.Fatal(err)
	}
	if len(run.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(run.Hosts))
	}
}

func TestScan_NmapNotFound_Error(t *testing.T) {
	s := Scanner{NmapPath: "/nonexistent/nmap"}
	_, err := s.Scan(context.Background(), []string{"127.0.0.1/32"}, []int{80})
	if err == nil {
		t.Fatal("expected error when nmap not found")
	}
}
