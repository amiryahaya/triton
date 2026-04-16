//go:build integration

// Package integration contains cross-package tests.
//
// Wire-format contract tests ensure portal response JSON round-trips
// correctly into engine-client types. Catches drift between portal
// types (with json tags) and engine/client types (independently defined
// wire structs). Phase 4 C1 and Phase 5 I1 both found such drift only
// via code review — these tests prevent regression.
package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	// Portal types
	"github.com/amiryahaya/triton/pkg/server/agentpush"
	creds "github.com/amiryahaya/triton/pkg/server/credentials"
	disc "github.com/amiryahaya/triton/pkg/server/discovery"
	scanjobs "github.com/amiryahaya/triton/pkg/server/scanjobs"

	// Engine client types
	"github.com/amiryahaya/triton/pkg/engine/client"
)

// TestWireFormat_CredentialDelivery verifies portal Delivery JSON
// round-trips into engine client.DeliveryPayload without field loss.
func TestWireFormat_CredentialDelivery(t *testing.T) {
	profID := uuid.Must(uuid.NewV7())
	portal := creds.Delivery{
		ID:          uuid.Must(uuid.NewV7()),
		OrgID:       uuid.Must(uuid.NewV7()),
		EngineID:    uuid.Must(uuid.NewV7()),
		ProfileID:   &profID,
		SecretRef:   uuid.Must(uuid.NewV7()),
		AuthType:    creds.AuthSSHPassword,
		Kind:        creds.DeliveryPush,
		Ciphertext:  []byte("test-ciphertext"),
		Status:      "queued",
		RequestedAt: time.Now().UTC(),
	}

	b, err := json.Marshal(portal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var engine client.DeliveryPayload
	if err := json.Unmarshal(b, &engine); err != nil {
		t.Fatalf("unmarshal into engine type: %v", err)
	}

	// Assert key fields survived the round-trip.
	if engine.ID != portal.ID.String() {
		t.Errorf("ID mismatch: portal=%s engine=%s", portal.ID, engine.ID)
	}
	if engine.SecretRef != portal.SecretRef.String() {
		t.Errorf("SecretRef mismatch: portal=%s engine=%s", portal.SecretRef, engine.SecretRef)
	}
	if engine.AuthType != string(portal.AuthType) {
		t.Errorf("AuthType mismatch: portal=%s engine=%s", portal.AuthType, engine.AuthType)
	}
	if engine.Kind != string(portal.Kind) {
		t.Errorf("Kind mismatch: portal=%s engine=%s", portal.Kind, engine.Kind)
	}
	// Ciphertext: portal []byte → Go JSON marshals as base64.
	// engine.Ciphertext is string → should be the base64 representation.
	if engine.Ciphertext == "" {
		t.Error("Ciphertext empty after roundtrip")
	}
	if engine.ProfileID != profID.String() {
		t.Errorf("ProfileID mismatch: portal=%s engine=%s", profID, engine.ProfileID)
	}
}

// TestWireFormat_CredentialTestJob verifies portal TestJobPayload JSON
// round-trips into engine client.TestJobPayload without field loss.
func TestWireFormat_CredentialTestJob(t *testing.T) {
	portalHostID := uuid.Must(uuid.NewV7())
	portal := creds.TestJobPayload{
		ID:        uuid.Must(uuid.NewV7()),
		ProfileID: uuid.Must(uuid.NewV7()),
		SecretRef: uuid.Must(uuid.NewV7()),
		AuthType:  creds.AuthSSHKey,
		Hosts: []creds.HostTarget{
			{ID: portalHostID, Address: "10.0.0.1", Port: 22},
		},
	}

	b, err := json.Marshal(portal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var engine client.TestJobPayload
	if err := json.Unmarshal(b, &engine); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if engine.ID != portal.ID.String() {
		t.Errorf("ID: portal=%s engine=%s", portal.ID, engine.ID)
	}
	if engine.ProfileID != portal.ProfileID.String() {
		t.Errorf("ProfileID: portal=%s engine=%s", portal.ProfileID, engine.ProfileID)
	}
	if engine.SecretRef != portal.SecretRef.String() {
		t.Errorf("SecretRef: portal=%s engine=%s", portal.SecretRef, engine.SecretRef)
	}
	if engine.AuthType != string(portal.AuthType) {
		t.Errorf("AuthType: portal=%s engine=%s", portal.AuthType, engine.AuthType)
	}
	if len(engine.Hosts) != 1 {
		t.Fatalf("Hosts: want 1, got %d", len(engine.Hosts))
	}
	if engine.Hosts[0].ID != portalHostID.String() {
		t.Errorf("Host ID: portal=%s engine=%s", portalHostID, engine.Hosts[0].ID)
	}
	if engine.Hosts[0].Address != "10.0.0.1" {
		t.Errorf("Host address: want 10.0.0.1, got %s", engine.Hosts[0].Address)
	}
	if engine.Hosts[0].Port != 22 {
		t.Errorf("Host port: want 22, got %d", engine.Hosts[0].Port)
	}
}

// TestWireFormat_ScanJobPayload verifies portal JobPayload JSON
// round-trips into engine client.ScanJobPayload. Specifically tests
// CredentialSecretRef (uuid.UUID vs *string) which was the Phase 5 I1
// drift.
func TestWireFormat_ScanJobPayload(t *testing.T) {
	secretRef := uuid.Must(uuid.NewV7())
	hostID := uuid.Must(uuid.NewV7())
	portal := scanjobs.JobPayload{
		ID:                  uuid.Must(uuid.NewV7()),
		ScanProfile:         scanjobs.ProfileStandard,
		CredentialSecretRef: &secretRef,
		CredentialAuthType:  "ssh-password",
		Hosts: []scanjobs.HostTarget{
			{ID: hostID, Address: "10.0.0.1", Port: 22, Hostname: "app-01", OS: "linux"},
		},
	}

	b, err := json.Marshal(portal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var engine client.ScanJobPayload
	if err := json.Unmarshal(b, &engine); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if engine.ID != portal.ID.String() {
		t.Errorf("ID: portal=%s engine=%s", portal.ID, engine.ID)
	}
	if engine.ScanProfile != string(portal.ScanProfile) {
		t.Errorf("ScanProfile: portal=%s engine=%s", portal.ScanProfile, engine.ScanProfile)
	}
	// CredentialSecretRef: portal = *uuid.UUID, engine = *string
	if engine.CredentialSecretRef == nil || *engine.CredentialSecretRef != secretRef.String() {
		t.Errorf("CredentialSecretRef: portal=%s engine=%v", secretRef, engine.CredentialSecretRef)
	}
	if engine.CredentialAuthType != "ssh-password" {
		t.Errorf("CredentialAuthType: want ssh-password, got %s", engine.CredentialAuthType)
	}
	if len(engine.Hosts) != 1 {
		t.Fatalf("Hosts: want 1, got %d", len(engine.Hosts))
	}
	h := engine.Hosts[0]
	if h.ID != hostID.String() {
		t.Errorf("Host ID: portal=%s engine=%s", hostID, h.ID)
	}
	if h.Address != "10.0.0.1" {
		t.Errorf("Host address: want 10.0.0.1, got %s", h.Address)
	}
	if h.Hostname != "app-01" {
		t.Errorf("Hostname: want app-01, got %s", h.Hostname)
	}
	if h.OS != "linux" {
		t.Errorf("OS: want linux, got %s", h.OS)
	}
}

// TestWireFormat_ScanJobPayload_NilCredential verifies that a job
// without a credential profile serializes correctly (omitted field).
func TestWireFormat_ScanJobPayload_NilCredential(t *testing.T) {
	portal := scanjobs.JobPayload{
		ID:          uuid.Must(uuid.NewV7()),
		ScanProfile: scanjobs.ProfileQuick,
		Hosts: []scanjobs.HostTarget{
			{ID: uuid.Must(uuid.NewV7()), Address: "10.0.0.2", Port: 22},
		},
	}

	b, err := json.Marshal(portal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var engine client.ScanJobPayload
	if err := json.Unmarshal(b, &engine); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if engine.CredentialSecretRef != nil {
		t.Errorf("CredentialSecretRef should be nil, got %v", engine.CredentialSecretRef)
	}
}

// TestWireFormat_DiscoveryJob verifies the discovery Job JSON shape.
// Discovery jobs do NOT have an engine client type (the engine uses a
// different poll response shape), so we verify the JSON has the
// expected keys and values.
func TestWireFormat_DiscoveryJob(t *testing.T) {
	requestedBy := uuid.Must(uuid.NewV7())
	portal := disc.Job{
		ID:          uuid.Must(uuid.NewV7()),
		OrgID:       uuid.Must(uuid.NewV7()),
		EngineID:    uuid.Must(uuid.NewV7()),
		RequestedBy: &requestedBy,
		CIDRs:       []string{"10.0.0.0/24"},
		Ports:       []int{22, 80, 443},
		Status:      disc.StatusQueued,
		RequestedAt: time.Now().UTC(),
	}

	b, err := json.Marshal(portal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}

	// Discovery Job struct has no json tags — fields marshal with their
	// Go field names (PascalCase). Verify the JSON contains expected
	// keys matching Go struct field names.
	if raw["ID"] == nil && raw["id"] == nil {
		t.Error("ID/id missing from JSON")
	}
	if raw["CIDRs"] == nil && raw["cidrs"] == nil {
		t.Error("CIDRs/cidrs missing from JSON")
	}
	if raw["Ports"] == nil && raw["ports"] == nil {
		t.Error("Ports/ports missing from JSON")
	}

	// Verify CIDR and port values
	var cidrs []any
	if c, ok := raw["CIDRs"].([]any); ok {
		cidrs = c
	} else if c, ok := raw["cidrs"].([]any); ok {
		cidrs = c
	}
	if len(cidrs) != 1 || cidrs[0] != "10.0.0.0/24" {
		t.Errorf("cidrs = %v, want [10.0.0.0/24]", cidrs)
	}

	var ports []any
	if p, ok := raw["Ports"].([]any); ok {
		ports = p
	} else if p, ok := raw["ports"].([]any); ok {
		ports = p
	}
	if len(ports) != 3 {
		t.Errorf("ports = %v, want 3 elements", ports)
	}
}

// TestWireFormat_PushJobPayload_RoundTrips verifies portal PushJobPayload
// JSON round-trips into engine client.PushJobPayload without field loss.
// Portal types use uuid.UUID; engine client types use string — Go's
// uuid.UUID marshals as a plain JSON string so the engine side can
// unmarshal it without special handling.
func TestWireFormat_PushJobPayload_RoundTrips(t *testing.T) {
	portal := agentpush.PushJobPayload{
		ID:                  uuid.Must(uuid.NewV7()),
		CredentialSecretRef: uuid.Must(uuid.NewV7()),
		CredentialAuthType:  "bootstrap-admin",
		Hosts: []agentpush.HostTarget{
			{ID: uuid.Must(uuid.NewV7()), Address: "10.0.0.5", Port: 22, Hostname: "app-01", OS: "linux"},
		},
	}

	b, err := json.Marshal(portal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var engine client.PushJobPayload
	if err := json.Unmarshal(b, &engine); err != nil {
		t.Fatalf("unmarshal into engine type: %v", err)
	}

	if engine.ID != portal.ID.String() {
		t.Errorf("ID mismatch: portal=%s engine=%s", portal.ID, engine.ID)
	}
	if engine.CredentialSecretRef != portal.CredentialSecretRef.String() {
		t.Errorf("CredentialSecretRef mismatch: portal=%s engine=%s", portal.CredentialSecretRef, engine.CredentialSecretRef)
	}
	if engine.CredentialAuthType != portal.CredentialAuthType {
		t.Errorf("CredentialAuthType mismatch: portal=%s engine=%s", portal.CredentialAuthType, engine.CredentialAuthType)
	}
	if len(engine.Hosts) != 1 {
		t.Fatalf("Hosts: want 1, got %d", len(engine.Hosts))
	}
	h := engine.Hosts[0]
	if h.ID != portal.Hosts[0].ID.String() {
		t.Errorf("Host ID mismatch: portal=%s engine=%s", portal.Hosts[0].ID, h.ID)
	}
	if h.Address != "10.0.0.5" {
		t.Errorf("Host Address: want 10.0.0.5, got %s", h.Address)
	}
	if h.Port != 22 {
		t.Errorf("Host Port: want 22, got %d", h.Port)
	}
	if h.Hostname != "app-01" {
		t.Errorf("Host Hostname: want app-01, got %s", h.Hostname)
	}
	if h.OS != "linux" {
		t.Errorf("Host OS: want linux, got %s", h.OS)
	}
}

// TestWireFormat_RegisterAgentRequest_AcceptsStringUUID verifies that the
// portal's registerAgentRequest (which uses uuid.UUID for HostID) can
// decode a plain string UUID as sent by the engine client.
func TestWireFormat_RegisterAgentRequest_AcceptsStringUUID(t *testing.T) {
	hostID := uuid.Must(uuid.NewV7())
	// Simulate what the engine sends (plain string UUID):
	engineJSON := `{"host_id":"` + hostID.String() + `","cert_fingerprint":"abc123","version":"1.0"}`

	// Simulate what the portal decodes into:
	type portalReq struct {
		HostID          uuid.UUID `json:"host_id"`
		CertFingerprint string    `json:"cert_fingerprint"`
		Version         string    `json:"version"`
	}
	var req portalReq
	if err := json.Unmarshal([]byte(engineJSON), &req); err != nil {
		t.Fatalf("portal decode failed: %v — wire-format mismatch between engine string and portal uuid.UUID", err)
	}
	if req.HostID == uuid.Nil {
		t.Error("HostID decoded as nil")
	}
	if req.HostID != hostID {
		t.Errorf("HostID mismatch: want %s, got %s", hostID, req.HostID)
	}
	if req.CertFingerprint != "abc123" {
		t.Errorf("CertFingerprint: want abc123, got %s", req.CertFingerprint)
	}
}
