package inventory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/server"
)

// seedGroupInOrg adds a group to fs so GetGroup passes for (orgID, gid).
func seedGroupInOrg(fs *fakeStore, orgID, gid uuid.UUID) {
	fs.groups[gid] = Group{ID: gid, OrgID: orgID, Name: "g"}
}

func TestImportHosts_DryRun_ReturnsPreviewWithoutInserting(t *testing.T) {
	fs := newFakeStore()
	fs.importResult = ImportResult{Accepted: 5, Rejected: 0, Duplicates: 2}
	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	gid := uuid.Must(uuid.NewV7())
	body := map[string]any{
		"group_id": gid.String(),
		"dry_run":  true,
		"rows": []map[string]string{
			{"hostname": "a", "address": "10.0.0.1"},
		},
	}
	req, orgID, _ := makeReqWithClaims(t, "POST", "/hosts/import", body, server.RoleEngineer)
	seedGroupInOrg(fs, orgID, gid)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code, "body=%s", rr.Body.String())
	var got ImportResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.True(t, got.DryRun)
	assert.Equal(t, 5, got.Accepted)
	assert.Equal(t, 2, got.Duplicates)

	require.Len(t, fs.importCalls, 1)
	assert.True(t, fs.importCalls[0].DryRun)
}

func TestImportHosts_Commit_InsertsAllRows(t *testing.T) {
	fs := newFakeStore()
	fs.importResult = ImportResult{Accepted: 3}
	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	gid := uuid.Must(uuid.NewV7())
	body := map[string]any{
		"group_id": gid.String(),
		"dry_run":  false,
		"rows": []map[string]string{
			{"hostname": "a"}, {"hostname": "b"}, {"hostname": "c"},
		},
	}
	req, orgID, _ := makeReqWithClaims(t, "POST", "/hosts/import", body, server.RoleEngineer)
	seedGroupInOrg(fs, orgID, gid)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var got ImportResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &got))
	assert.False(t, got.DryRun)
	assert.Equal(t, 3, got.Accepted)

	require.Len(t, fs.importCalls, 1)
	assert.False(t, fs.importCalls[0].DryRun)
	assert.Len(t, fs.importCalls[0].Rows, 3)
}

func TestImportHosts_InvalidGroup_404(t *testing.T) {
	fs := newFakeStore()
	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	body := map[string]any{
		"group_id": uuid.Must(uuid.NewV7()).String(),
		"rows":     []map[string]string{{"hostname": "a"}},
	}
	req, _, _ := makeReqWithClaims(t, "POST", "/hosts/import", body, server.RoleEngineer)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusNotFound, rr.Code)
	assert.Empty(t, fs.importCalls, "ImportHosts must not run if group check fails")
}

func TestImportHosts_Officer_403(t *testing.T) {
	fs := newFakeStore()
	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	body := map[string]any{
		"group_id": uuid.Must(uuid.NewV7()).String(),
		"rows":     []map[string]string{{"hostname": "a"}},
	}
	req, _, _ := makeReqWithClaims(t, "POST", "/hosts/import", body, server.RoleOfficer)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusForbidden, rr.Code)
	assert.Empty(t, fs.importCalls)
}

func TestImportHosts_OverLimit_400(t *testing.T) {
	fs := newFakeStore()
	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	rows := make([]map[string]string, 10001)
	for i := range rows {
		rows[i] = map[string]string{"hostname": "h"}
	}
	body := map[string]any{
		"group_id": uuid.Must(uuid.NewV7()).String(),
		"rows":     rows,
	}
	req, _, _ := makeReqWithClaims(t, "POST", "/hosts/import", body, server.RoleEngineer)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Empty(t, fs.importCalls)
}

func TestImportHosts_EmptyRows_400(t *testing.T) {
	fs := newFakeStore()
	h := NewHandlers(fs, nil)
	r := newMountedRouter(h)

	body := map[string]any{
		"group_id": uuid.Must(uuid.NewV7()).String(),
		"rows":     []map[string]string{},
	}
	req, _, _ := makeReqWithClaims(t, "POST", "/hosts/import", body, server.RoleEngineer)

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
}
