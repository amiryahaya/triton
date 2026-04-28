package agents

// Unit tests for GatewayHandlers.SetInstanceInfo + IngestScan stamping.
// Uses in-package fakes (no build tag required) so the test runs under
// `go test ./pkg/manageserver/agents/...` without a database.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/model"
)

// --- fakes ---

// fakeAgentStoreUnit satisfies agents.Store for unit tests.
type fakeAgentStoreUnit struct {
	markActiveOK bool
}

func (f *fakeAgentStoreUnit) Create(_ context.Context, a Agent) (Agent, error) { return a, nil }
func (f *fakeAgentStoreUnit) Get(_ context.Context, _ uuid.UUID) (Agent, error) {
	return Agent{}, ErrNotFound
}
func (f *fakeAgentStoreUnit) GetByCertSerial(_ context.Context, _ string) (Agent, error) {
	return Agent{}, ErrNotFound
}
func (f *fakeAgentStoreUnit) List(_ context.Context) ([]Agent, error) { return nil, nil }
func (f *fakeAgentStoreUnit) MarkActive(_ context.Context, _ uuid.UUID) error {
	if !f.markActiveOK {
		return ErrNotFound
	}
	return nil
}
func (f *fakeAgentStoreUnit) UpdateCert(_ context.Context, _ uuid.UUID, _ string, _ time.Time) error {
	return nil
}
func (f *fakeAgentStoreUnit) Revoke(_ context.Context, _ uuid.UUID) error { return nil }
func (f *fakeAgentStoreUnit) Count(_ context.Context) (int64, error)      { return 0, nil }
func (f *fakeAgentStoreUnit) SetCommand(_ context.Context, _ uuid.UUID, _ *AgentCommand) error {
	return nil
}
func (f *fakeAgentStoreUnit) PopCommand(_ context.Context, _ uuid.UUID) (*AgentCommand, error) {
	return nil, nil
}

// fakeEnqueuerUnit records the last enqueued scan for assertions.
type fakeEnqueuerUnit struct {
	lastScan *model.ScanResult
}

func (f *fakeEnqueuerUnit) Enqueue(_ context.Context, _ uuid.UUID, _ string, _ uuid.UUID, scan *model.ScanResult) error {
	f.lastScan = scan
	return nil
}

// withCNUnit injects a CN string into a context, simulating what
// MTLSCNAuth does in production. Declared here so unit tests don't
// need to construct a real TLS connection.
func withCNUnit(ctx context.Context, cn string) context.Context {
	return context.WithValue(ctx, cnCtxKey{}, cn)
}

// --- tests ---

func TestIngestScan_StampsInstanceInfo(t *testing.T) {
	enq := &fakeEnqueuerUnit{}
	gw := &GatewayHandlers{
		AgentStore:   &fakeAgentStoreUnit{markActiveOK: true},
		ResultsStore: enq,
	}
	gw.SetInstanceInfo("test-uuid-123", "test-manage")

	scan := model.ScanResult{
		ID:       uuid.NewString(),
		Metadata: model.ScanMetadata{Hostname: "host1"},
	}
	body, _ := json.Marshal(scan)
	req := httptest.NewRequest(http.MethodPost, "/agents/scans", bytes.NewReader(body))
	req = req.WithContext(withCNUnit(req.Context(), "agent:"+uuid.NewString()))
	rec := httptest.NewRecorder()
	gw.IngestScan(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)
	require.NotNil(t, enq.lastScan)
	assert.Equal(t, "test-uuid-123", enq.lastScan.Metadata.ManageServerID)
	assert.Equal(t, "test-manage", enq.lastScan.Metadata.ManageServerName)
}

func TestIngestScan_NoStampWhenInstanceInfoEmpty(t *testing.T) {
	enq := &fakeEnqueuerUnit{}
	gw := &GatewayHandlers{
		AgentStore:   &fakeAgentStoreUnit{markActiveOK: true},
		ResultsStore: enq,
	}
	// SetInstanceInfo not called — instanceID stays ""

	scan := model.ScanResult{
		ID:       uuid.NewString(),
		Metadata: model.ScanMetadata{Hostname: "host1"},
	}
	body, _ := json.Marshal(scan)
	req := httptest.NewRequest(http.MethodPost, "/agents/scans", bytes.NewReader(body))
	req = req.WithContext(withCNUnit(req.Context(), "agent:"+uuid.NewString()))
	rec := httptest.NewRecorder()
	gw.IngestScan(rec, req)

	require.Equal(t, http.StatusAccepted, rec.Code)
	require.NotNil(t, enq.lastScan)
	assert.Empty(t, enq.lastScan.Metadata.ManageServerID)
	assert.Empty(t, enq.lastScan.Metadata.ManageServerName)
}
